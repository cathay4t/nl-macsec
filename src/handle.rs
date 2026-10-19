// SPDX-License-Identifier: MIT

use std::{io, sync::Arc};

use futures_util::{Stream, StreamExt, future::ready};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{
    DecodeError, ErrorMessage, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_macsec::{MacsecCmd, MacsecMessage};

use crate::{ErrorKind, MacsecConfig, MacsecError};

#[derive(Clone, Debug)]
pub struct MacsecHandle {
    handle: GenetlinkHandle,
}

impl MacsecHandle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        Self { handle }
    }

    /// Dump all MACsec SecYs of the current network namespace.
    ///
    /// The list fields of each returned [MacsecConfig] are `Some`, including
    /// empty lists when the SecY has no TX SAs or RX SCs.
    pub async fn get_all(&mut self) -> Result<Vec<MacsecConfig>, MacsecError> {
        let message = MacsecMessage::new(MacsecCmd::GetTxsc);
        let mut stream =
            self.request(NLM_F_REQUEST | NLM_F_DUMP, message).await?;

        let mut secys = Vec::new();
        while let Some(reply) = stream.next().await {
            secys.push(MacsecConfig::try_from(reply?)?);
        }
        Ok(secys)
    }

    /// Apply a desired MACsec configuration.
    ///
    /// The current SecY state is read first and the minimum set of add,
    /// update and delete requests is sent to make it match `config`.
    ///
    /// MACsec netdevice properties except the offload mode (`sci`, cipher
    /// suite, ICV length, encryption, ...) are configured through rtnetlink
    /// when the netdevice is created and are read-only here.
    ///
    /// List fields ([MacsecConfig::tx_sa], [MacsecConfig::rx_sc] and
    /// [crate::MacsecRxScConfig::sa_list]) are complete desired sets when
    /// they are `Some`: entries present in the kernel but missing from the
    /// list are deleted, and `Some(Vec::new())` deletes all entries. `None`
    /// leaves the current entries untouched.
    ///
    /// Creating a new SA requires its key; the kernel never reports keys,
    /// so a configuration returned by [MacsecHandle::get_all] can only
    /// update existing SAs.
    ///
    /// Applying a configuration for an ifindex which does not exist, or
    /// which is not a MACsec SecY, does nothing and succeeds.
    pub async fn apply(
        &mut self,
        config: &MacsecConfig,
    ) -> Result<(), MacsecError> {
        let Some(current) = self
            .get_all()
            .await?
            .into_iter()
            .find(|current| current.ifindex == config.ifindex)
        else {
            return Ok(());
        };

        let messages = config.to_messages(&current)?;
        for message in messages {
            self.do_request(message).await?;
        }

        Ok(())
    }

    async fn request(
        &mut self,
        nl_header_flags: u16,
        message: MacsecMessage,
    ) -> Result<
        impl Stream<Item = Result<MacsecMessage, MacsecError>>,
        MacsecError,
    > {
        let mut nl_msg =
            NetlinkMessage::from(GenlMessage::from_payload(message));
        nl_msg.header.flags = nl_header_flags;

        match self.handle.request(nl_msg.clone()).await {
            Ok(stream) => Ok(parse_nl_msg_stream(nl_msg, stream)),
            Err(e) => Err(MacsecError::new(
                ErrorKind::NetlinkError,
                format!("Netlink request failed: {e}"),
                Some(nl_msg),
            )),
        }
    }

    async fn do_request(
        &mut self,
        message: MacsecMessage,
    ) -> Result<(), MacsecError> {
        // A successful request is acknowledged with an `NLMSG_ERROR`
        // message without an error code, which ends the reply stream
        // without yielding an item, therefore an error is the only way a
        // request fails.
        let mut stream =
            self.request(NLM_F_REQUEST | NLM_F_ACK, message).await?;
        while let Some(reply) = stream.next().await {
            reply?;
        }
        Ok(())
    }
}

fn parse_nl_msg_stream(
    nl_msg: NetlinkMessage<GenlMessage<MacsecMessage>>,
    stream: impl Stream<
        Item = Result<NetlinkMessage<GenlMessage<MacsecMessage>>, DecodeError>,
    >,
) -> impl Stream<Item = Result<MacsecMessage, MacsecError>> {
    let nl_msg = Arc::new(nl_msg);

    stream.filter_map(move |reply| {
        let nl_msg = Arc::clone(&nl_msg);
        ready(match reply {
            Ok(reply_msg) => {
                let (header, payload) = reply_msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(genl_msg) => {
                        let (_genl_hdr, macsec_msg) = genl_msg.into_parts();
                        Some(Ok(macsec_msg))
                    }
                    // An acknowledgement holds no error code and completes
                    // the request.
                    NetlinkPayload::Error(err) if err.code.is_none() => None,
                    NetlinkPayload::Error(err) => Some(Err(MacsecError::new(
                        ErrorKind::KernelError,
                        netlink_error_message(&err),
                        Some((*nl_msg).clone()),
                    ))),
                    // A dump reports its error code in the message which
                    // ends the dump.
                    NetlinkPayload::Done(done) => {
                        if done.code == 0 {
                            None
                        } else {
                            Some(Err(MacsecError::new(
                                ErrorKind::KernelError,
                                format!(
                                    "Netlink dump failed: {}",
                                    io::Error::from_raw_os_error(-done.code)
                                ),
                                Some((*nl_msg).clone()),
                            )))
                        }
                    }
                    NetlinkPayload::Noop => None,
                    // An overrun message holds raw bytes of a message which
                    // could not be read, attach the request instead.
                    NetlinkPayload::Overrun(_) => Some(Err(MacsecError::new(
                        ErrorKind::Bug,
                        "Netlink message overrun, messages were lost"
                            .to_string(),
                        Some((*nl_msg).clone()),
                    ))),
                    payload => Some(Err(MacsecError::new(
                        ErrorKind::Bug,
                        format!(
                            "Unexpected NetlinkPayload type: {}",
                            payload_type(&payload)
                        ),
                        Some(NetlinkMessage::new(header, payload)),
                    ))),
                }
            }
            Err(e) => Some(Err(MacsecError::new(
                ErrorKind::DecodeError,
                format!("netlink decode error: {e}"),
                Some((*nl_msg).clone()),
            ))),
        })
    })
}

/// Describe a netlink error by its errno.
fn netlink_error_message(err: &ErrorMessage) -> String {
    match err.code {
        Some(code) => format!(
            "Netlink error: {}",
            io::Error::from_raw_os_error(-code.get())
        ),
        None => "Netlink error: no error code".to_string(),
    }
}

/// Name the type of `payload` without rendering its content.
fn payload_type<I>(payload: &NetlinkPayload<I>) -> &'static str {
    match payload {
        NetlinkPayload::Done(_) => "Done",
        NetlinkPayload::Error(_) => "Error",
        NetlinkPayload::Noop => "Noop",
        NetlinkPayload::Overrun(_) => "Overrun",
        NetlinkPayload::InnerMessage(_) => "InnerMessage",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use futures_util::stream;
    use netlink_packet_core::{DoneMessage, ErrorMessage, NetlinkHeader};
    use netlink_packet_macsec::MacsecAttribute;

    use super::*;

    type NetlinkMsg = NetlinkMessage<GenlMessage<MacsecMessage>>;

    fn inner_message() -> NetlinkMsg {
        NetlinkMessage::from(GenlMessage::from_payload(MacsecMessage {
            cmd: MacsecCmd::GetTxsc,
            attributes: vec![MacsecAttribute::Ifindex(3)],
        }))
    }

    fn acknowledgement() -> NetlinkMsg {
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(ErrorMessage::default()),
        )
    }

    fn error(code: i32) -> NetlinkMsg {
        let mut error_message = ErrorMessage::default();
        error_message.code = NonZeroI32::new(code);
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(error_message),
        )
    }

    fn done(code: i32) -> NetlinkMsg {
        let mut done_message = DoneMessage::default();
        done_message.code = code;
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Done(done_message),
        )
    }

    async fn parse_replies(
        replies: Vec<NetlinkMsg>,
    ) -> Vec<Result<MacsecMessage, MacsecError>> {
        let replies: Vec<Result<NetlinkMsg, DecodeError>> =
            replies.into_iter().map(Ok).collect();
        parse_nl_msg_stream(inner_message(), stream::iter(replies))
            .collect()
            .await
    }

    #[tokio::test]
    async fn acknowledgement_and_done_are_not_errors() {
        let replies =
            parse_replies(vec![inner_message(), done(0), acknowledgement()])
                .await;

        assert_eq!(replies.len(), 1);
        assert!(replies[0].is_ok());
    }

    #[tokio::test]
    async fn kernel_error_is_reported() {
        let replies = parse_replies(vec![error(-22)]).await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::KernelError);
        assert!(
            err.msg.contains("Invalid argument"),
            "unexpected error message: {}",
            err.msg
        );
    }

    #[tokio::test]
    async fn dump_error_is_reported() {
        let replies = parse_replies(vec![done(-19)]).await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::KernelError);
        assert!(
            err.msg.contains("No such device"),
            "unexpected error message: {}",
            err.msg
        );
    }

    #[tokio::test]
    async fn overrun_is_reported() {
        let replies = parse_replies(vec![NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Overrun(Vec::new()),
        )])
        .await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::Bug);
    }
}
