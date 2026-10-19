// SPDX-License-Identifier: MIT

use netlink_packet_macsec::{
    MacSecCipherId, MacSecOffload, MacSecValidate, MacsecAttribute, MacsecCmd,
    MacsecMessage, MacsecOffloadAttribute, MacsecRxscAttribute, MacsecRxscList,
    MacsecRxscStatsAttribute, MacsecSaAttribute, MacsecSaList,
    MacsecSaStatsAttribute, MacsecSecyAttribute, MacsecSecyStatsAttribute,
    MacsecTxscStatsAttribute,
};

use crate::{ErrorKind, MacsecError};

const MACSEC_NUM_AN: u8 = 4;
const MACSEC_KEYID_LEN: usize = 16;
pub const MACSEC_SALT_LEN: usize = 12;
const MACSEC_MAX_KEY_LEN: usize = 128;

/// The configuration of a transmit secure association (TX SA), as accepted
/// by `ip macsec add|set|del DEV tx sa AN`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) struct MacsecTxSa {
    /// The ifindex of the MACsec netdevice.
    pub ifindex: u32,
    /// The association number, 0..3.
    pub an: u8,
    /// The initial or next packet number.
    pub pn: Option<u64>,
    /// Use the 64-bit extended packet number (XPN) format.
    pub xpn: bool,
    /// The secure association key.
    pub key: Option<Vec<u8>>,
    /// The key identifier, up to 16 bytes. The kernel stores exactly 16
    /// bytes, so the value is zero padded.
    pub key_id: Option<Vec<u8>>,
    /// The XPN salt, required for XPN cipher suites.
    pub salt: Option<[u8; MACSEC_SALT_LEN]>,
    /// The XPN short secure channel identifier, required for XPN cipher
    /// suites.
    pub ssci: Option<u32>,
    /// Whether the association is active.
    pub active: Option<bool>,
}

impl MacsecTxSa {
    /// Create a TX SA configuration for `ifindex` and `an`.
    pub(crate) fn new(ifindex: u32, an: u8) -> Self {
        Self {
            ifindex,
            an,
            ..Default::default()
        }
    }

    /// Build the [MacsecMessage] of the `cmd` request for this TX SA.
    ///
    /// [MacsecCmd::AddTxsa] requires a key, a key ID and a non-zero PN.
    /// [MacsecCmd::UpdTxsa] accepts only PN and active state; changing the
    /// key requires adding a new SA. [MacsecCmd::DelTxsa] sends only the AN.
    pub(crate) fn build(
        &self,
        cmd: MacsecCmd,
    ) -> Result<MacsecMessage, MacsecError> {
        match cmd {
            MacsecCmd::AddTxsa => {
                if self.pn.is_none() {
                    return Err(invalid_input(
                        "a non-zero packet number is required to add a TX SA",
                    ));
                }
            }
            MacsecCmd::UpdTxsa | MacsecCmd::DelTxsa => (),
            _ => {
                return Err(invalid_input(
                    "the TX SA configuration only supports add, update and \
                     delete commands",
                ));
            }
        }

        let sa_config = build_sa_config(
            cmd,
            SaFields {
                an: self.an,
                pn: self.pn,
                xpn: self.xpn,
                key: self.key.as_deref(),
                key_id: self.key_id.as_deref(),
                salt: self.salt.as_ref(),
                ssci: self.ssci,
                active: self.active,
            },
        )?;

        Ok(MacsecMessage {
            cmd,
            attributes: vec![
                MacsecAttribute::Ifindex(self.ifindex),
                MacsecAttribute::SaConfig(sa_config),
            ],
        })
    }
}

/// The configuration of a receive secure channel (RX SC), as accepted by
/// `ip macsec add|set|del DEV rx SCI`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) struct MacsecRxSc {
    /// The ifindex of the MACsec netdevice.
    pub ifindex: u32,
    /// The secure channel identifier of the peer.
    pub sci: u64,
    /// Whether the secure channel is active. The kernel defaults to active
    /// when the attribute is omitted on add.
    pub active: Option<bool>,
}

impl MacsecRxSc {
    /// Create an RX SC configuration for `ifindex` and `sci`.
    pub(crate) fn new(ifindex: u32, sci: u64) -> Self {
        Self {
            ifindex,
            sci,
            ..Default::default()
        }
    }

    /// Build the [MacsecMessage] of the `cmd` request for this RX SC.
    pub(crate) fn build(
        &self,
        cmd: MacsecCmd,
    ) -> Result<MacsecMessage, MacsecError> {
        match cmd {
            MacsecCmd::AddRxsc | MacsecCmd::UpdRxsc | MacsecCmd::DelRxsc => (),
            _ => {
                return Err(invalid_input(
                    "the RX SC configuration only supports add, update and \
                     delete commands",
                ));
            }
        }

        let mut rxsc_attrs = vec![MacsecRxscAttribute::Sci(self.sci)];
        if cmd != MacsecCmd::DelRxsc
            && let Some(active) = self.active
        {
            rxsc_attrs.push(MacsecRxscAttribute::Active(u8::from(active)));
        }

        Ok(MacsecMessage {
            cmd,
            attributes: vec![
                MacsecAttribute::Ifindex(self.ifindex),
                MacsecAttribute::RxscConfig(rxsc_attrs),
            ],
        })
    }
}

/// The configuration of a receive secure association (RX SA), as accepted
/// by `ip macsec add|set|del DEV rx SCI sa AN`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) struct MacsecRxSa {
    /// The ifindex of the MACsec netdevice.
    pub ifindex: u32,
    /// The secure channel identifier of the peer.
    pub sci: u64,
    /// The association number, 0..3.
    pub an: u8,
    /// The initial or next packet number.
    pub pn: Option<u64>,
    /// Use the 64-bit extended packet number (XPN) format.
    pub xpn: bool,
    /// The secure association key.
    pub key: Option<Vec<u8>>,
    /// The key identifier, up to 16 bytes. The kernel stores exactly 16
    /// bytes, so the value is zero padded.
    pub key_id: Option<Vec<u8>>,
    /// The XPN salt, required for XPN cipher suites.
    pub salt: Option<[u8; MACSEC_SALT_LEN]>,
    /// The XPN short secure channel identifier, required for XPN cipher
    /// suites.
    pub ssci: Option<u32>,
    /// Whether the association is active.
    pub active: Option<bool>,
}

impl MacsecRxSa {
    /// Create an RX SA configuration for `ifindex`, `sci` and `an`.
    pub(crate) fn new(ifindex: u32, sci: u64, an: u8) -> Self {
        Self {
            ifindex,
            sci,
            an,
            ..Default::default()
        }
    }

    /// Build the [MacsecMessage] of the `cmd` request for this RX SA.
    ///
    /// [MacsecCmd::AddRxsa] requires a key and a key ID. The PN and active
    /// state are optional. [MacsecCmd::UpdRxsa] accepts only PN and active
    /// state; changing the key requires adding a new SA.
    pub(crate) fn build(
        &self,
        cmd: MacsecCmd,
    ) -> Result<MacsecMessage, MacsecError> {
        match cmd {
            MacsecCmd::AddRxsa | MacsecCmd::UpdRxsa | MacsecCmd::DelRxsa => (),
            _ => {
                return Err(invalid_input(
                    "the RX SA configuration only supports add, update and \
                     delete commands",
                ));
            }
        }

        let sa_config = build_sa_config(
            cmd,
            SaFields {
                an: self.an,
                pn: self.pn,
                xpn: self.xpn,
                key: self.key.as_deref(),
                key_id: self.key_id.as_deref(),
                salt: self.salt.as_ref(),
                ssci: self.ssci,
                active: self.active,
            },
        )?;

        Ok(MacsecMessage {
            cmd,
            attributes: vec![
                MacsecAttribute::Ifindex(self.ifindex),
                MacsecAttribute::RxscConfig(vec![MacsecRxscAttribute::Sci(
                    self.sci,
                )]),
                MacsecAttribute::SaConfig(sa_config),
            ],
        })
    }
}

/// The configuration of the MACsec offload mode, as accepted by
/// `ip macsec offload DEV off|phy|mac`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct MacsecOffload {
    /// The ifindex of the MACsec netdevice.
    pub ifindex: u32,
    /// The offload mode.
    pub offload: MacSecOffload,
}

impl MacsecOffload {
    /// Create an offload configuration for `ifindex`.
    pub(crate) fn new(ifindex: u32, offload: MacSecOffload) -> Self {
        Self { ifindex, offload }
    }

    /// Build the [MacsecMessage] of the offload update request.
    pub(crate) fn build(&self) -> MacsecMessage {
        MacsecMessage {
            cmd: MacsecCmd::UpdOffload,
            attributes: vec![
                MacsecAttribute::Ifindex(self.ifindex),
                MacsecAttribute::Offload(vec![MacsecOffloadAttribute::Type(
                    self.offload,
                )]),
            ],
        }
    }
}

struct SaFields<'a> {
    an: u8,
    pn: Option<u64>,
    xpn: bool,
    key: Option<&'a [u8]>,
    key_id: Option<&'a [u8]>,
    salt: Option<&'a [u8; MACSEC_SALT_LEN]>,
    ssci: Option<u32>,
    active: Option<bool>,
}

fn build_sa_config(
    cmd: MacsecCmd,
    fields: SaFields<'_>,
) -> Result<Vec<MacsecSaAttribute>, MacsecError> {
    if fields.an >= MACSEC_NUM_AN {
        return Err(invalid_input("the association number must be 0..3"));
    }

    let mut attrs = vec![MacsecSaAttribute::An(fields.an)];

    if cmd == MacsecCmd::DelTxsa || cmd == MacsecCmd::DelRxsa {
        return Ok(attrs);
    }

    let update = cmd == MacsecCmd::UpdTxsa || cmd == MacsecCmd::UpdRxsa;
    if update
        && (fields.key.is_some()
            || fields.key_id.is_some()
            || fields.salt.is_some()
            || fields.ssci.is_some())
    {
        return Err(invalid_input(
            "a key, key ID, SSCI and salt can not be changed on an existing \
             SA, add a new SA instead",
        ));
    }

    if let Some(pn) = fields.pn {
        if pn == 0 {
            return Err(invalid_input("the packet number must not be zero"));
        }
        if fields.xpn {
            attrs.push(MacsecSaAttribute::Pn64(pn));
        } else if let Ok(pn) = u32::try_from(pn) {
            attrs.push(MacsecSaAttribute::Pn32(pn));
        } else {
            return Err(invalid_input(
                "the packet number does not fit into 32 bits, use XPN",
            ));
        }
    } else if cmd == MacsecCmd::AddTxsa {
        return Err(invalid_input(
            "a non-zero packet number is required to add a TX SA",
        ));
    }

    if !update {
        let key =
            fields.key.filter(|key| !key.is_empty()).ok_or_else(|| {
                invalid_input("the secure association key is required")
            })?;
        if key.len() > MACSEC_MAX_KEY_LEN {
            return Err(invalid_input(
                "the secure association key is too long",
            ));
        }

        let key_id = fields.key_id.ok_or_else(|| {
            invalid_input("the secure association key ID is required")
        })?;
        if key_id.len() > MACSEC_KEYID_LEN {
            return Err(invalid_input(
                "the secure association key ID is too long",
            ));
        }

        if fields.xpn {
            let salt = fields.salt.ok_or_else(|| {
                invalid_input("the XPN salt is required for an XPN SA")
            })?;
            let ssci = fields.ssci.ok_or_else(|| {
                invalid_input("the SSCI is required for an XPN SA")
            })?;
            attrs.push(MacsecSaAttribute::Salt(salt.to_vec()));
            attrs.push(MacsecSaAttribute::Ssci(ssci));
        } else if fields.salt.is_some() || fields.ssci.is_some() {
            return Err(invalid_input(
                "the salt and SSCI are only valid for an XPN SA",
            ));
        }

        attrs.push(MacsecSaAttribute::KeyId(pad_key_id(key_id)));
        attrs.push(MacsecSaAttribute::Key(key.to_vec()));
    }

    if let Some(active) = fields.active {
        attrs.push(MacsecSaAttribute::Active(u8::from(active)));
    }

    Ok(attrs)
}

fn pad_key_id(key_id: &[u8]) -> Vec<u8> {
    let mut padded = key_id.to_vec();
    padded.resize(MACSEC_KEYID_LEN, 0);
    padded
}

fn invalid_input(msg: &str) -> MacsecError {
    MacsecError::new(ErrorKind::InvalidInput, msg.to_string(), None)
}

/// A complete MACsec SecY configuration, as returned by
/// [crate::MacsecHandle::get_all].
///
/// The SecY fields except [MacsecSecyConfig::offload] are configured through
/// rtnetlink when the MACsec netdevice is created and cannot be changed by
/// the `macsec` generic netlink family. [crate::MacsecHandle::apply] manages
/// the secure associations, receive secure channels and offload mode.
///
/// For [crate::MacsecHandle::apply], the list fields [MacsecConfig::tx_sa],
/// [MacsecConfig::rx_sc] and [MacsecRxScConfig::sa_list] are complete desired
/// sets when they are `Some`, and are left untouched when they are `None`.
/// `Some(Vec::new())` therefore removes all entries of that list.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecConfig {
    /// The ifindex of the MACsec netdevice.
    pub ifindex: u32,
    /// The SecY properties.
    pub secy: MacsecSecyConfig,
    /// The TX SAs of the transmit secure channel.
    ///
    /// `None` leaves the current TX SAs untouched. `Some(list)` describes
    /// the complete desired set: TX SAs missing from `list` are deleted,
    /// listed SAs are added or updated, and `Some(Vec::new())` deletes all
    /// TX SAs.
    pub tx_sa: Option<Vec<MacsecSaConfig>>,
    /// The receive secure channels and their associations.
    ///
    /// `None` leaves the current RX SCs untouched. `Some(list)` describes
    /// the complete desired set: RX SCs missing from `list` are deleted,
    /// listed SCs are added or updated, and `Some(Vec::new())` deletes all
    /// RX SCs.
    pub rx_sc: Option<Vec<MacsecRxScConfig>>,
    /// SecY statistics.
    pub secy_stats: MacsecSecyStats,
    /// Transmit secure channel statistics.
    pub tx_sc_stats: MacsecTxScStats,
}

impl MacsecConfig {
    /// Create a configuration for the MACsec netdevice with `ifindex`.
    ///
    /// List fields and other optional properties are `None`, so applying this
    /// configuration leaves the current state unchanged.
    pub fn new(ifindex: u32) -> Self {
        Self {
            ifindex,
            ..Default::default()
        }
    }

    /// Whether the SecY uses an XPN cipher suite.
    pub fn is_xpn(&self) -> bool {
        matches!(
            self.secy.cipher_suite,
            MacSecCipherId::GcmAesXpn128 | MacSecCipherId::GcmAesXpn256
        )
    }
}

/// The SecY level properties reported by the `macsec` generic netlink
/// family.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MacsecSecyConfig {
    /// The transmit secure channel identifier.
    pub sci: u64,
    /// The transmit association currently selected for encoding.
    pub encoding_sa: u8,
    /// The replay window, when replay protection is enabled.
    pub window: Option<u32>,
    /// The cipher suite.
    pub cipher_suite: MacSecCipherId,
    /// The ICV length.
    pub icv_len: u8,
    /// Whether frames are protected.
    pub protect: bool,
    /// Whether replay protection is enabled.
    pub replay: bool,
    /// The validation mode.
    pub validate: MacSecValidate,
    /// Whether transmitted frames are encrypted.
    pub encrypt: bool,
    /// Whether the SCI is included in the SecTAG.
    pub send_sci: bool,
    /// Whether the end-station bit is set.
    pub end_station: bool,
    /// Whether the single-copy-broadcast bit is set.
    pub scb: bool,
    /// Whether the SecY is operational.
    pub operational: bool,
    /// The offload mode. `None` leaves the current mode unchanged when
    /// applying a configuration.
    pub offload: Option<MacSecOffload>,
}

impl Default for MacsecSecyConfig {
    fn default() -> Self {
        Self {
            sci: 0,
            encoding_sa: 0,
            window: None,
            cipher_suite: MacSecCipherId::GcmAes128,
            icv_len: 0,
            protect: false,
            replay: false,
            validate: MacSecValidate::Disabled,
            encrypt: false,
            send_sci: false,
            end_station: false,
            scb: false,
            operational: false,
            offload: None,
        }
    }
}

/// A transmit or receive secure association.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecSaConfig {
    /// The association number, 0..3.
    pub an: u8,
    /// The packet number. The kernel reports the next PN of the SA.
    pub pn: Option<u64>,
    /// The XPN short secure channel identifier.
    pub ssci: Option<u32>,
    /// Whether the association is active.
    pub active: Option<bool>,
    /// The key identifier.
    pub key_id: Vec<u8>,
    /// The secure association key. The kernel never reports keys, this is
    /// only used when applying a configuration which creates a new SA.
    pub key: Option<Vec<u8>>,
    /// The XPN salt. The kernel never reports the salt, this is only used
    /// when applying a configuration which creates a new XPN SA.
    pub salt: Option<[u8; MACSEC_SALT_LEN]>,
    /// Per-SA statistics.
    pub stats: MacsecSaStats,
}

impl MacsecSaConfig {
    /// Create an empty SA configuration for `an`.
    pub fn new(an: u8) -> Self {
        Self {
            an,
            ..Default::default()
        }
    }
}

/// A receive secure channel.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecRxScConfig {
    /// The secure channel identifier of the peer.
    pub sci: u64,
    /// Whether the secure channel is active.
    pub active: Option<bool>,
    /// The receive secure associations.
    ///
    /// `None` leaves the current SAs untouched. `Some(list)` describes the
    /// complete desired set: SAs missing from `list` are deleted, listed
    /// SAs are added or updated, and `Some(Vec::new())` deletes all SAs
    /// while keeping the secure channel.
    pub sa_list: Option<Vec<MacsecSaConfig>>,
    /// Per-RX-SC statistics.
    pub stats: MacsecRxScStats,
}

impl MacsecRxScConfig {
    /// Create an empty RX SC configuration for `sci`.
    pub fn new(sci: u64) -> Self {
        Self {
            sci,
            ..Default::default()
        }
    }
}

/// Per-SecY statistics.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecSecyStats {
    pub out_pkts_untagged: u64,
    pub in_pkts_untagged: u64,
    pub out_pkts_too_long: u64,
    pub in_pkts_no_tag: u64,
    pub in_pkts_bad_tag: u64,
    pub in_pkts_unknown_sci: u64,
    pub in_pkts_no_sci: u64,
    pub in_pkts_overrun: u64,
}

/// Per-TX-SC statistics.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecTxScStats {
    pub out_pkts_protected: u64,
    pub out_pkts_encrypted: u64,
    pub out_octets_protected: u64,
    pub out_octets_encrypted: u64,
}

/// Per-RX-SC statistics.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecRxScStats {
    pub in_octets_validated: u64,
    pub in_octets_decrypted: u64,
    pub in_pkts_unchecked: u64,
    pub in_pkts_delayed: u64,
    pub in_pkts_ok: u64,
    pub in_pkts_invalid: u64,
    pub in_pkts_late: u64,
    pub in_pkts_not_valid: u64,
    pub in_pkts_not_using_sa: u64,
    pub in_pkts_unused_sa: u64,
}

/// Per-SA statistics.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MacsecSaStats {
    pub in_pkts_ok: u64,
    pub in_pkts_invalid: u64,
    pub in_pkts_not_valid: u64,
    pub in_pkts_not_using_sa: u64,
    pub in_pkts_unused_sa: u64,
    pub out_pkts_protected: u64,
    pub out_pkts_encrypted: u64,
}

impl MacsecConfig {
    /// Convert the difference between `self` and `current` into the MACsec
    /// generic-netlink messages which make the kernel state match `self`.
    ///
    /// A complete SecY configuration requires multiple messages: the kernel
    /// has no bulk-replace command.
    ///
    /// TX SAs, RX SCs and RX SAs are only touched when their `Option` is
    /// `Some`: `None` leaves the current state untouched, while a `Some`
    /// list is the complete desired set and therefore deletes entries which
    /// are not listed. `Some(Vec::new())` deletes all entries of that list.
    ///
    /// Existing SAs are matched by AN (within the SC for RX SAs). Since the
    /// kernel never reports SA keys or salts, a key or salt in a listed SA
    /// is only used when the SA has to be created. Changing the key of an
    /// existing SA requires deleting and re-adding the SA.
    pub fn to_messages(
        &self,
        current: &Self,
    ) -> Result<Vec<MacsecMessage>, MacsecError> {
        let desired = self;
        if desired.ifindex != current.ifindex {
            return Err(invalid_input(
                "the desired and current configurations have different \
                 ifindex values",
            ));
        }

        let mut messages = Vec::new();

        if let Some(offload) = desired.secy.offload
            && current.secy.offload != Some(offload)
        {
            messages.push(MacsecOffload::new(desired.ifindex, offload).build());
        }

        let xpn = desired.is_xpn();
        let current_tx_sa = current.tx_sa.as_deref().unwrap_or(&[]);
        let current_rx_sc = current.rx_sc.as_deref().unwrap_or(&[]);

        if let Some(tx_sa) = &desired.tx_sa {
            messages.extend(tx_sa_messages(
                desired.ifindex,
                tx_sa,
                current_tx_sa,
                xpn,
            )?);
        }

        if let Some(rx_sc) = &desired.rx_sc {
            messages.extend(rx_sc_messages(
                desired.ifindex,
                rx_sc,
                current_rx_sc,
                xpn,
            )?);
        }

        Ok(messages)
    }
}

fn tx_sa_messages(
    ifindex: u32,
    desired: &[MacsecSaConfig],
    current: &[MacsecSaConfig],
    xpn: bool,
) -> Result<Vec<MacsecMessage>, MacsecError> {
    let mut messages = Vec::new();

    for current_sa in current {
        if desired.iter().any(|sa| sa.an == current_sa.an) {
            continue;
        }
        if current_sa.active == Some(true) {
            let mut deactivate = MacsecTxSa::new(ifindex, current_sa.an);
            deactivate.active = Some(false);
            messages.push(deactivate.build(MacsecCmd::UpdTxsa)?);
        }
        messages.push(
            MacsecTxSa::new(ifindex, current_sa.an)
                .build(MacsecCmd::DelTxsa)?,
        );
    }

    for wanted in desired {
        match current.iter().find(|sa| sa.an == wanted.an) {
            None => messages.push(
                tx_sa_from_config(ifindex, wanted, xpn)
                    .build(MacsecCmd::AddTxsa)?,
            ),
            Some(current_sa) => {
                let mut update = MacsecTxSa::new(ifindex, wanted.an);
                update.xpn = xpn;
                let mut changed = false;
                if wanted.pn.is_some() && wanted.pn != current_sa.pn {
                    update.pn = wanted.pn;
                    changed = true;
                }
                if wanted.active.is_some() && wanted.active != current_sa.active
                {
                    update.active = wanted.active;
                    changed = true;
                }
                if changed {
                    messages.push(update.build(MacsecCmd::UpdTxsa)?);
                }
            }
        }
    }

    Ok(messages)
}

fn rx_sc_messages(
    ifindex: u32,
    desired: &[MacsecRxScConfig],
    current: &[MacsecRxScConfig],
    xpn: bool,
) -> Result<Vec<MacsecMessage>, MacsecError> {
    let mut messages = Vec::new();

    for current_sc in current {
        if desired.iter().any(|sc| sc.sci == current_sc.sci) {
            continue;
        }
        messages.push(
            MacsecRxSc::new(ifindex, current_sc.sci)
                .build(MacsecCmd::DelRxsc)?,
        );
    }

    for wanted_sc in desired {
        let current_sc = current.iter().find(|sc| sc.sci == wanted_sc.sci);

        match current_sc {
            None => {
                let mut new_sc = MacsecRxSc::new(ifindex, wanted_sc.sci);
                new_sc.active = wanted_sc.active;
                messages.push(new_sc.build(MacsecCmd::AddRxsc)?);
            }
            Some(current_sc) => {
                if wanted_sc.active.is_some()
                    && wanted_sc.active != current_sc.active
                {
                    let mut update = MacsecRxSc::new(ifindex, wanted_sc.sci);
                    update.active = wanted_sc.active;
                    messages.push(update.build(MacsecCmd::UpdRxsc)?);
                }
            }
        }

        if let Some(wanted_sas) = &wanted_sc.sa_list {
            let current_sas = current_sc
                .and_then(|sc| sc.sa_list.as_deref())
                .unwrap_or(&[]);
            messages.extend(rx_sa_messages(
                ifindex,
                wanted_sc.sci,
                wanted_sas,
                current_sas,
                xpn,
            )?);
        }
    }

    Ok(messages)
}

fn rx_sa_messages(
    ifindex: u32,
    sci: u64,
    desired: &[MacsecSaConfig],
    current: &[MacsecSaConfig],
    xpn: bool,
) -> Result<Vec<MacsecMessage>, MacsecError> {
    let mut messages = Vec::new();

    for current_sa in current {
        if desired.iter().any(|sa| sa.an == current_sa.an) {
            continue;
        }
        if current_sa.active == Some(true) {
            let mut deactivate = MacsecRxSa::new(ifindex, sci, current_sa.an);
            deactivate.active = Some(false);
            messages.push(deactivate.build(MacsecCmd::UpdRxsa)?);
        }
        messages.push(
            MacsecRxSa::new(ifindex, sci, current_sa.an)
                .build(MacsecCmd::DelRxsa)?,
        );
    }

    for wanted in desired {
        match current.iter().find(|sa| sa.an == wanted.an) {
            None => messages.push(
                rx_sa_from_config(ifindex, sci, wanted, xpn)
                    .build(MacsecCmd::AddRxsa)?,
            ),
            Some(current_sa) => {
                let mut update = MacsecRxSa::new(ifindex, sci, wanted.an);
                update.xpn = xpn;
                let mut changed = false;
                if wanted.pn.is_some() && wanted.pn != current_sa.pn {
                    update.pn = wanted.pn;
                    changed = true;
                }
                if wanted.active.is_some() && wanted.active != current_sa.active
                {
                    update.active = wanted.active;
                    changed = true;
                }
                if changed {
                    messages.push(update.build(MacsecCmd::UpdRxsa)?);
                }
            }
        }
    }

    Ok(messages)
}

fn tx_sa_from_config(
    ifindex: u32,
    config: &MacsecSaConfig,
    xpn: bool,
) -> MacsecTxSa {
    MacsecTxSa {
        ifindex,
        an: config.an,
        pn: config.pn,
        xpn,
        key: config.key.clone(),
        key_id: Some(config.key_id.clone()),
        salt: config.salt,
        ssci: config.ssci,
        active: config.active,
    }
}

fn rx_sa_from_config(
    ifindex: u32,
    sci: u64,
    config: &MacsecSaConfig,
    xpn: bool,
) -> MacsecRxSa {
    MacsecRxSa {
        ifindex,
        sci,
        an: config.an,
        pn: config.pn,
        xpn,
        key: config.key.clone(),
        key_id: Some(config.key_id.clone()),
        salt: config.salt,
        ssci: config.ssci,
        active: config.active,
    }
}

impl TryFrom<MacsecMessage> for MacsecConfig {
    type Error = MacsecError;

    fn try_from(message: MacsecMessage) -> Result<Self, Self::Error> {
        let mut ifindex = None;
        let mut secy = MacsecSecyConfig::default();
        let mut secy_seen = false;
        let mut tx_sa = None;
        let mut rx_sc = None;
        let mut secy_stats = MacsecSecyStats::default();
        let mut tx_sc_stats = MacsecTxScStats::default();

        for attr in message.attributes {
            match attr {
                MacsecAttribute::Ifindex(value) => ifindex = Some(value),
                MacsecAttribute::Secy(attrs) => {
                    secy_seen = true;
                    for attr in attrs {
                        match attr {
                            MacsecSecyAttribute::Sci(value) => secy.sci = value,
                            MacsecSecyAttribute::EncodingSa(value) => {
                                secy.encoding_sa = value
                            }
                            MacsecSecyAttribute::Window(value) => {
                                secy.window = Some(value)
                            }
                            MacsecSecyAttribute::CipherSuite(value) => {
                                secy.cipher_suite = value
                            }
                            MacsecSecyAttribute::IcvLen(value) => {
                                secy.icv_len = value
                            }
                            MacsecSecyAttribute::Protect(value) => {
                                secy.protect = value != 0
                            }
                            MacsecSecyAttribute::Replay(value) => {
                                secy.replay = value != 0
                            }
                            MacsecSecyAttribute::Oper(value) => {
                                secy.operational = value != 0
                            }
                            MacsecSecyAttribute::Validate(value) => {
                                secy.validate = value
                            }
                            MacsecSecyAttribute::Encrypt(value) => {
                                secy.encrypt = value != 0
                            }
                            MacsecSecyAttribute::IncSci(value) => {
                                secy.send_sci = value != 0
                            }
                            MacsecSecyAttribute::Es(value) => {
                                secy.end_station = value != 0
                            }
                            MacsecSecyAttribute::Scb(value) => {
                                secy.scb = value != 0
                            }
                            MacsecSecyAttribute::Pad
                            | MacsecSecyAttribute::Other(_) => (),
                            _ => (),
                        }
                    }
                }
                MacsecAttribute::TxsaList(list) => {
                    tx_sa = Some(list.iter().map(parse_sa).collect());
                }
                MacsecAttribute::RxscList(list) => {
                    rx_sc = Some(list.iter().map(parse_rx_sc).collect());
                }
                MacsecAttribute::TxscStats(attrs) => {
                    tx_sc_stats = parse_tx_sc_stats(&attrs);
                }
                MacsecAttribute::SecyStats(attrs) => {
                    secy_stats = parse_secy_stats(&attrs);
                }
                MacsecAttribute::Offload(attrs) => {
                    for attr in attrs {
                        if let MacsecOffloadAttribute::Type(value) = attr {
                            secy.offload = Some(value);
                        }
                    }
                }
                MacsecAttribute::RxscConfig(_)
                | MacsecAttribute::SaConfig(_) => {}
                MacsecAttribute::Other(_) => (),
                _ => (),
            }
        }

        let ifindex = ifindex.ok_or_else(|| {
            MacsecError::new(
                ErrorKind::DecodeError,
                "the MACsec dump message has no ifindex".to_string(),
                None,
            )
        })?;
        if !secy_seen {
            return Err(MacsecError::new(
                ErrorKind::DecodeError,
                "the MACsec dump message has no SecY attributes".to_string(),
                None,
            ));
        }

        Ok(Self {
            ifindex,
            secy,
            tx_sa,
            rx_sc,
            secy_stats,
            tx_sc_stats,
        })
    }
}

fn parse_sa(list: &MacsecSaList) -> MacsecSaConfig {
    let mut sa = MacsecSaConfig::default();
    for attr in &list.attributes {
        match attr {
            MacsecSaAttribute::An(value) => sa.an = *value,
            MacsecSaAttribute::Active(value) => sa.active = Some(*value != 0),
            MacsecSaAttribute::Pn32(value) => sa.pn = Some(u64::from(*value)),
            MacsecSaAttribute::Pn64(value) => sa.pn = Some(*value),
            MacsecSaAttribute::KeyId(value) => sa.key_id = value.clone(),
            MacsecSaAttribute::Ssci(value) => sa.ssci = Some(*value),
            MacsecSaAttribute::Stats(attrs) => sa.stats = parse_sa_stats(attrs),
            MacsecSaAttribute::Key(_)
            | MacsecSaAttribute::Salt(_)
            | MacsecSaAttribute::Pad
            | MacsecSaAttribute::Other(_) => (),
            _ => (),
        }
    }
    sa
}

fn parse_rx_sc(list: &MacsecRxscList) -> MacsecRxScConfig {
    let mut rx_sc = MacsecRxScConfig::default();
    for attr in &list.attributes {
        match attr {
            MacsecRxscAttribute::Sci(value) => rx_sc.sci = *value,
            MacsecRxscAttribute::Active(value) => {
                rx_sc.active = Some(*value != 0)
            }
            MacsecRxscAttribute::SaList(list) => {
                rx_sc.sa_list = Some(list.iter().map(parse_sa).collect());
            }
            MacsecRxscAttribute::Stats(attrs) => {
                rx_sc.stats = parse_rx_sc_stats(attrs)
            }
            MacsecRxscAttribute::Pad | MacsecRxscAttribute::Other(_) => (),
            _ => (),
        }
    }
    rx_sc
}

fn parse_secy_stats(attrs: &[MacsecSecyStatsAttribute]) -> MacsecSecyStats {
    let mut stats = MacsecSecyStats::default();
    for attr in attrs {
        match attr {
            MacsecSecyStatsAttribute::OutPktsUntagged(v) => {
                stats.out_pkts_untagged = *v
            }
            MacsecSecyStatsAttribute::InPktsUntagged(v) => {
                stats.in_pkts_untagged = *v
            }
            MacsecSecyStatsAttribute::OutPktsTooLong(v) => {
                stats.out_pkts_too_long = *v
            }
            MacsecSecyStatsAttribute::InPktsNoTag(v) => {
                stats.in_pkts_no_tag = *v
            }
            MacsecSecyStatsAttribute::InPktsBadTag(v) => {
                stats.in_pkts_bad_tag = *v
            }
            MacsecSecyStatsAttribute::InPktsUnknownSci(v) => {
                stats.in_pkts_unknown_sci = *v
            }
            MacsecSecyStatsAttribute::InPktsNoSci(v) => {
                stats.in_pkts_no_sci = *v
            }
            MacsecSecyStatsAttribute::InPktsOverrun(v) => {
                stats.in_pkts_overrun = *v
            }
            MacsecSecyStatsAttribute::Other(_) => (),
            _ => (),
        }
    }
    stats
}

fn parse_tx_sc_stats(attrs: &[MacsecTxscStatsAttribute]) -> MacsecTxScStats {
    let mut stats = MacsecTxScStats::default();
    for attr in attrs {
        match attr {
            MacsecTxscStatsAttribute::OutPktsProtected(v) => {
                stats.out_pkts_protected = *v
            }
            MacsecTxscStatsAttribute::OutPktsEncrypted(v) => {
                stats.out_pkts_encrypted = *v
            }
            MacsecTxscStatsAttribute::OutOctetsProtected(v) => {
                stats.out_octets_protected = *v
            }
            MacsecTxscStatsAttribute::OutOctetsEncrypted(v) => {
                stats.out_octets_encrypted = *v
            }
            MacsecTxscStatsAttribute::Other(_) => (),
            _ => (),
        }
    }
    stats
}

fn parse_rx_sc_stats(attrs: &[MacsecRxscStatsAttribute]) -> MacsecRxScStats {
    let mut stats = MacsecRxScStats::default();
    for attr in attrs {
        match attr {
            MacsecRxscStatsAttribute::InOctetsValidated(v) => {
                stats.in_octets_validated = *v
            }
            MacsecRxscStatsAttribute::InOctetsDecrypted(v) => {
                stats.in_octets_decrypted = *v
            }
            MacsecRxscStatsAttribute::InPktsUnchecked(v) => {
                stats.in_pkts_unchecked = *v
            }
            MacsecRxscStatsAttribute::InPktsDelayed(v) => {
                stats.in_pkts_delayed = *v
            }
            MacsecRxscStatsAttribute::InPktsOk(v) => stats.in_pkts_ok = *v,
            MacsecRxscStatsAttribute::InPktsInvalid(v) => {
                stats.in_pkts_invalid = *v
            }
            MacsecRxscStatsAttribute::InPktsLate(v) => stats.in_pkts_late = *v,
            MacsecRxscStatsAttribute::InPktsNotValid(v) => {
                stats.in_pkts_not_valid = *v
            }
            MacsecRxscStatsAttribute::InPktsNotUsingSa(v) => {
                stats.in_pkts_not_using_sa = *v
            }
            MacsecRxscStatsAttribute::InPktsUnusedSa(v) => {
                stats.in_pkts_unused_sa = *v
            }
            MacsecRxscStatsAttribute::Other(_) => (),
            _ => (),
        }
    }
    stats
}

fn parse_sa_stats(attrs: &[MacsecSaStatsAttribute]) -> MacsecSaStats {
    let mut stats = MacsecSaStats::default();
    for attr in attrs {
        match attr {
            MacsecSaStatsAttribute::InPktsOk(v) => stats.in_pkts_ok = *v,
            MacsecSaStatsAttribute::InPktsInvalid(v) => {
                stats.in_pkts_invalid = *v
            }
            MacsecSaStatsAttribute::InPktsNotValid(v) => {
                stats.in_pkts_not_valid = *v
            }
            MacsecSaStatsAttribute::InPktsNotUsingSa(v) => {
                stats.in_pkts_not_using_sa = *v
            }
            MacsecSaStatsAttribute::InPktsUnusedSa(v) => {
                stats.in_pkts_unused_sa = *v
            }
            MacsecSaStatsAttribute::OutPktsProtected(v) => {
                stats.out_pkts_protected = *v
            }
            MacsecSaStatsAttribute::OutPktsEncrypted(v) => {
                stats.out_pkts_encrypted = *v
            }
            MacsecSaStatsAttribute::Other(_) => (),
            _ => (),
        }
    }
    stats
}
#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn build_add_tx_sa() {
        let config = MacsecTxSa {
            pn: Some(1),
            key: Some(vec![0x81; 16]),
            key_id: Some(vec![0x01]),
            active: Some(true),
            ..MacsecTxSa::new(3, 0)
        };

        assert_eq!(
            config.build(MacsecCmd::AddTxsa).unwrap(),
            MacsecMessage {
                cmd: MacsecCmd::AddTxsa,
                attributes: vec![
                    MacsecAttribute::Ifindex(3),
                    MacsecAttribute::SaConfig(vec![
                        MacsecSaAttribute::An(0),
                        MacsecSaAttribute::Pn32(1),
                        MacsecSaAttribute::KeyId(vec![
                            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]),
                        MacsecSaAttribute::Key(vec![0x81; 16]),
                        MacsecSaAttribute::Active(1),
                    ]),
                ],
            }
        );
    }

    #[test]
    fn build_add_xpn_tx_sa() {
        let config = MacsecTxSa {
            pn: Some(0x1_0000_0001),
            xpn: true,
            key: Some(vec![0x81; 16]),
            key_id: Some(vec![0x01]),
            salt: Some([0x83; MACSEC_SALT_LEN]),
            ssci: Some(123),
            active: Some(true),
            ..MacsecTxSa::new(3, 0)
        };

        assert_eq!(
            config.build(MacsecCmd::AddTxsa).unwrap(),
            MacsecMessage {
                cmd: MacsecCmd::AddTxsa,
                attributes: vec![
                    MacsecAttribute::Ifindex(3),
                    MacsecAttribute::SaConfig(vec![
                        MacsecSaAttribute::An(0),
                        MacsecSaAttribute::Pn64(0x1_0000_0001),
                        MacsecSaAttribute::Salt(vec![0x83; MACSEC_SALT_LEN]),
                        MacsecSaAttribute::Ssci(123),
                        MacsecSaAttribute::KeyId(vec![
                            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]),
                        MacsecSaAttribute::Key(vec![0x81; 16]),
                        MacsecSaAttribute::Active(1),
                    ]),
                ],
            }
        );
    }

    #[test]
    fn build_delete_tx_sa_sends_only_an() {
        let config = MacsecTxSa {
            key: Some(vec![0x81; 16]),
            key_id: Some(vec![0x01]),
            ..MacsecTxSa::new(3, 2)
        };

        assert_eq!(
            config.build(MacsecCmd::DelTxsa).unwrap(),
            MacsecMessage {
                cmd: MacsecCmd::DelTxsa,
                attributes: vec![
                    MacsecAttribute::Ifindex(3),
                    MacsecAttribute::SaConfig(vec![MacsecSaAttribute::An(2)]),
                ],
            }
        );
    }

    #[test]
    fn build_update_tx_sa_rejects_key() {
        let config = MacsecTxSa {
            key: Some(vec![0x81; 16]),
            ..MacsecTxSa::new(3, 0)
        };
        assert!(config.build(MacsecCmd::UpdTxsa).is_err());
    }

    #[test]
    fn build_rx_sc() {
        let config = MacsecRxSc {
            active: Some(false),
            ..MacsecRxSc::new(3, 0x0ed1490827840009)
        };

        assert_eq!(
            config.build(MacsecCmd::AddRxsc).unwrap(),
            MacsecMessage {
                cmd: MacsecCmd::AddRxsc,
                attributes: vec![
                    MacsecAttribute::Ifindex(3),
                    MacsecAttribute::RxscConfig(vec![
                        MacsecRxscAttribute::Sci(0x0ed1490827840009),
                        MacsecRxscAttribute::Active(0),
                    ]),
                ],
            }
        );
    }

    #[test]
    fn build_add_rx_sa() {
        let config = MacsecRxSa {
            pn: Some(2),
            key: Some(vec![0x82; 16]),
            key_id: Some(vec![0x00]),
            active: Some(true),
            ..MacsecRxSa::new(3, 0x0ed1490827840009, 0)
        };

        assert_eq!(
            config.build(MacsecCmd::AddRxsa).unwrap(),
            MacsecMessage {
                cmd: MacsecCmd::AddRxsa,
                attributes: vec![
                    MacsecAttribute::Ifindex(3),
                    MacsecAttribute::RxscConfig(vec![
                        MacsecRxscAttribute::Sci(0x0ed1490827840009)
                    ]),
                    MacsecAttribute::SaConfig(vec![
                        MacsecSaAttribute::An(0),
                        MacsecSaAttribute::Pn32(2),
                        MacsecSaAttribute::KeyId(vec![0; 16]),
                        MacsecSaAttribute::Key(vec![0x82; 16]),
                        MacsecSaAttribute::Active(1),
                    ]),
                ],
            }
        );
    }

    #[test]
    fn build_offload() {
        let config = MacsecOffload::new(3, MacSecOffload::Phy);
        assert_eq!(
            config.build(),
            MacsecMessage {
                cmd: MacsecCmd::UpdOffload,
                attributes: vec![
                    MacsecAttribute::Ifindex(3),
                    MacsecAttribute::Offload(vec![
                        MacsecOffloadAttribute::Type(MacSecOffload::Phy)
                    ]),
                ],
            }
        );
    }

    #[test]
    fn to_messages_adds_tx_sa() {
        let current = MacsecConfig::new(3);
        let mut desired = MacsecConfig::new(3);
        let mut sa = MacsecSaConfig::new(0);
        sa.pn = Some(1);
        sa.key = Some(vec![0x81; 16]);
        sa.key_id = vec![0x01];
        sa.active = Some(true);
        desired.tx_sa = Some(vec![sa]);

        let messages = desired.to_messages(&current).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].cmd, MacsecCmd::AddTxsa);
        assert_eq!(
            messages[0].attributes,
            vec![
                MacsecAttribute::Ifindex(3),
                MacsecAttribute::SaConfig(vec![
                    MacsecSaAttribute::An(0),
                    MacsecSaAttribute::Pn32(1),
                    MacsecSaAttribute::KeyId(vec![
                        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                    MacsecSaAttribute::Key(vec![0x81; 16]),
                    MacsecSaAttribute::Active(1),
                ]),
            ]
        );
    }

    #[test]
    fn to_messages_purges_lists() {
        let mut current = MacsecConfig::new(3);
        let mut sa = MacsecSaConfig::new(0);
        sa.active = Some(true);
        current.tx_sa = Some(vec![sa]);
        current.rx_sc = Some(vec![MacsecRxScConfig::new(9)]);

        let mut desired = MacsecConfig::new(3);
        desired.tx_sa = Some(Vec::new());
        desired.rx_sc = Some(Vec::new());

        let messages = desired.to_messages(&current).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].cmd, MacsecCmd::UpdTxsa);
        assert_eq!(messages[1].cmd, MacsecCmd::DelTxsa);
        assert_eq!(messages[2].cmd, MacsecCmd::DelRxsc);
    }

    #[test]
    fn to_messages_none_leaves_state_untouched() {
        let mut current = MacsecConfig::new(3);
        current.tx_sa = Some(vec![MacsecSaConfig::new(0)]);
        current.rx_sc = Some(vec![MacsecRxScConfig::new(9)]);

        let desired = MacsecConfig::new(3);
        assert!(desired.to_messages(&current).unwrap().is_empty());
    }

    #[test]
    fn to_messages_overrides_tx_sa_list() {
        let mut current = MacsecConfig::new(3);
        let mut active = MacsecSaConfig::new(0);
        active.active = Some(true);
        current.tx_sa = Some(vec![active, MacsecSaConfig::new(1)]);

        let mut desired = MacsecConfig::new(3);
        desired.tx_sa = Some(vec![MacsecSaConfig::new(1)]);

        let messages = desired.to_messages(&current).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].cmd, MacsecCmd::UpdTxsa);
        assert_eq!(messages[1].cmd, MacsecCmd::DelTxsa);
    }

    #[test]
    fn to_messages_rx_sa_list_none_keeps_sas() {
        let mut current = MacsecConfig::new(3);
        let mut sc = MacsecRxScConfig::new(9);
        sc.sa_list = Some(vec![MacsecSaConfig::new(0)]);
        current.rx_sc = Some(vec![sc]);

        let mut desired = MacsecConfig::new(3);
        desired.rx_sc = Some(vec![MacsecRxScConfig::new(9)]);

        assert!(desired.to_messages(&current).unwrap().is_empty());
    }

    #[test]
    fn to_messages_purges_rx_sa_list() {
        let mut current = MacsecConfig::new(3);
        let mut sc = MacsecRxScConfig::new(9);
        let mut sa = MacsecSaConfig::new(0);
        sa.active = Some(true);
        sc.sa_list = Some(vec![sa]);
        current.rx_sc = Some(vec![sc]);

        let mut desired = MacsecConfig::new(3);
        let mut sc = MacsecRxScConfig::new(9);
        sc.sa_list = Some(Vec::new());
        desired.rx_sc = Some(vec![sc]);

        let messages = desired.to_messages(&current).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].cmd, MacsecCmd::UpdRxsa);
        assert_eq!(messages[1].cmd, MacsecCmd::DelRxsa);
    }

    #[test]
    fn to_messages_adds_rx_sa() {
        let mut current = MacsecConfig::new(3);
        let mut sc = MacsecRxScConfig::new(9);
        sc.sa_list = Some(Vec::new());
        current.rx_sc = Some(vec![sc]);

        let mut desired = MacsecConfig::new(3);
        let mut sc = MacsecRxScConfig::new(9);
        let mut sa = MacsecSaConfig::new(0);
        sa.pn = Some(1);
        sa.key = Some(vec![0x82; 16]);
        sa.key_id = vec![0x02];
        sa.active = Some(true);
        sc.sa_list = Some(vec![sa]);
        desired.rx_sc = Some(vec![sc]);

        let messages = desired.to_messages(&current).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].cmd, MacsecCmd::AddRxsa);
    }

    #[test]
    fn parse_macsec_config() {
        let message = MacsecMessage {
            cmd: MacsecCmd::GetTxsc,
            attributes: vec![
                MacsecAttribute::Ifindex(3),
                MacsecAttribute::Secy(vec![
                    MacsecSecyAttribute::Sci(0x0ed1490827840001),
                    MacsecSecyAttribute::EncodingSa(0),
                    MacsecSecyAttribute::CipherSuite(
                        MacSecCipherId::GcmAesXpn128,
                    ),
                    MacsecSecyAttribute::IcvLen(16),
                    MacsecSecyAttribute::Protect(1),
                    MacsecSecyAttribute::Replay(1),
                    MacsecSecyAttribute::Oper(1),
                    MacsecSecyAttribute::Validate(MacSecValidate::Strict),
                    MacsecSecyAttribute::Encrypt(1),
                    MacsecSecyAttribute::IncSci(1),
                    MacsecSecyAttribute::Es(0),
                    MacsecSecyAttribute::Scb(0),
                    MacsecSecyAttribute::Window(100),
                ]),
                MacsecAttribute::Offload(vec![MacsecOffloadAttribute::Type(
                    MacSecOffload::Off,
                )]),
                MacsecAttribute::TxsaList(vec![MacsecSaList {
                    kind: 1,
                    attributes: vec![
                        MacsecSaAttribute::An(0),
                        MacsecSaAttribute::Pn64(5),
                        MacsecSaAttribute::Ssci(7),
                        MacsecSaAttribute::KeyId(vec![1; 16]),
                        MacsecSaAttribute::Active(1),
                    ],
                }]),
                MacsecAttribute::RxscList(vec![MacsecRxscList {
                    kind: 1,
                    attributes: vec![
                        MacsecRxscAttribute::Active(1),
                        MacsecRxscAttribute::Sci(0x0ed1490827840009),
                        MacsecRxscAttribute::SaList(vec![MacsecSaList {
                            kind: 1,
                            attributes: vec![
                                MacsecSaAttribute::An(0),
                                MacsecSaAttribute::Pn64(8),
                                MacsecSaAttribute::Ssci(9),
                                MacsecSaAttribute::KeyId(vec![2; 16]),
                                MacsecSaAttribute::Active(1),
                            ],
                        }]),
                    ],
                }]),
            ],
        };

        let config = MacsecConfig::try_from(message).unwrap();
        assert_eq!(config.ifindex, 3);
        assert_eq!(config.secy.sci, 0x0ed1490827840001);
        assert_eq!(config.secy.cipher_suite, MacSecCipherId::GcmAesXpn128);
        assert_eq!(config.secy.window, Some(100));
        assert_eq!(config.secy.offload, Some(MacSecOffload::Off));
        assert!(config.is_xpn());
        let tx_sa = config.tx_sa.as_ref().unwrap();
        assert_eq!(tx_sa.len(), 1);
        assert_eq!(tx_sa[0].an, 0);
        assert_eq!(tx_sa[0].pn, Some(5));
        assert_eq!(tx_sa[0].ssci, Some(7));
        let rx_sc = config.rx_sc.as_ref().unwrap();
        assert_eq!(rx_sc.len(), 1);
        assert_eq!(rx_sc[0].sci, 0x0ed1490827840009);
        let sa_list = rx_sc[0].sa_list.as_ref().unwrap();
        assert_eq!(sa_list.len(), 1);
        assert_eq!(sa_list[0].pn, Some(8));
    }

    #[test]
    fn reject_invalid_input() {
        assert!(MacsecTxSa::new(3, 4).build(MacsecCmd::AddTxsa).is_err());
        assert!(
            MacsecTxSa {
                pn: Some(0),
                key: Some(vec![0x81; 16]),
                key_id: Some(vec![1]),
                ..MacsecTxSa::new(3, 0)
            }
            .build(MacsecCmd::AddTxsa)
            .is_err()
        );
        assert!(
            MacsecTxSa {
                pn: Some(1),
                key: Some(vec![0x81; 16]),
                key_id: Some(vec![1]),
                salt: Some([0; 12]),
                ..MacsecTxSa::new(3, 0)
            }
            .build(MacsecCmd::AddTxsa)
            .is_err()
        );
    }
}
