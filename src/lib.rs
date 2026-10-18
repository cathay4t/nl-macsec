// SPDX-License-Identifier: MIT

//! This crate provides methods to manage MACsec secure channels and secure
//! associations via the generic netlink protocol, as the `ip macsec`
//! command of [iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git)
//! does.
//!
//! The MACsec netdevice itself is created through rtnetlink, for example
//! with the `rtnetlink` crate. This crate only manages the SecY state
//! exposed by the `macsec` generic netlink family.
//!
//! [MacsecHandle::get_all] returns the parsed [MacsecConfig] of every SecY.
//! Filter the returned vector by [MacsecConfig::ifindex] when needed.
//!
//! A complete desired state is applied with a single [MacsecHandle::apply]
//! call:
//!
//! ```no_run
//! use nl_macsec::{MacsecConfig, MacsecSaConfig};
//!
//! async fn apply_config() -> Result<(), Box<dyn std::error::Error>> {
//!     let (conn, mut handle, _) = nl_macsec::new_connection()?;
//!     tokio::spawn(conn);
//!
//!     let current = handle.get_all().await?;
//!     println!("{current:?}");
//!
//!     let mut config = MacsecConfig::new(3);
//!     let mut sa = MacsecSaConfig::new(0);
//!     sa.pn = Some(1);
//!     sa.key = Some(vec![0x81; 16]);
//!     sa.key_id = vec![0x01];
//!     sa.active = Some(true);
//!     config.tx_sa.push(sa);
//!     handle.apply(&config).await?;
//!     Ok(())
//! }
//! ```
//!
//! Set [MacsecConfig::delete] to `true` before calling [MacsecHandle::apply]
//! to delete all TX SAs and RX SCs of the SecY.

mod config;
mod connection;
mod error;
mod handle;

#[doc(no_inline)]
pub use netlink_packet_macsec::{
    MacSecCipherId, MacSecOffload, MacSecValidate, MacsecAttribute, MacsecCmd,
    MacsecMessage, MacsecOffloadAttribute, MacsecRxscAttribute, MacsecRxscList,
    MacsecRxscStatsAttribute, MacsecSaAttribute, MacsecSaList,
    MacsecSaStatsAttribute, MacsecSecyAttribute, MacsecSecyStatsAttribute,
    MacsecTxscStatsAttribute,
};

#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::{
    config::{
        MACSEC_SALT_LEN, MacsecConfig, MacsecRxScConfig, MacsecRxScStats,
        MacsecSaConfig, MacsecSaStats, MacsecSecyConfig, MacsecSecyStats,
        MacsecTxScStats,
    },
    connection::new_connection_with_socket,
    error::{ErrorKind, MacsecError},
    handle::MacsecHandle,
};

// Compile the examples of the README as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
