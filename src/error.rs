// SPDX-License-Identifier: MIT

use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::GenlMessage;
use netlink_packet_macsec::MacsecMessage;

/// Kind of a [MacsecError].
///
/// This enum is `#[non_exhaustive]`, a `match` on it needs a wildcard arm.
/// Otherwise every new error kind would break the code of every user.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    Bug,
    NetlinkError,
    DecodeError,
    /// Invalid input from the caller, e.g. missing required property.
    InvalidInput,
    /// The kernel denied the request, e.g. a duplicate SA.
    KernelError,
    /// The requested object does not exist.
    NotFound,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bug => "bug",
                Self::NetlinkError => "netlink_error",
                Self::DecodeError => "decode_error",
                Self::InvalidInput => "invalid_input",
                Self::KernelError => "kernel_error",
                Self::NotFound => "not_found",
            }
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MacsecError {
    pub kind: ErrorKind,
    pub msg: String,
    pub netlink_msg: Option<NetlinkMessage<GenlMessage<MacsecMessage>>>,
}

impl std::fmt::Display for MacsecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(nl_msg) = self.netlink_msg.as_ref() {
            write!(
                f,
                "{}: {}, netlink message: {:?}",
                self.kind, self.msg, nl_msg
            )
        } else {
            write!(f, "{}: {}", self.kind, self.msg)
        }
    }
}

impl std::error::Error for MacsecError {}

impl MacsecError {
    /// Create a new [MacsecError].
    pub fn new(
        kind: ErrorKind,
        msg: String,
        netlink_msg: Option<NetlinkMessage<GenlMessage<MacsecMessage>>>,
    ) -> Self {
        Self {
            kind,
            msg,
            netlink_msg,
        }
    }
}
