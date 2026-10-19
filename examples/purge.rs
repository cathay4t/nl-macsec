// SPDX-License-Identifier: MIT

use std::error::Error;

use nl_macsec::{MacsecConfig, new_connection};

async fn run() -> Result<(), Box<dyn Error>> {
    let ifindex: u32 = std::env::args()
        .nth(1)
        .expect("usage: purge <ifindex>")
        .parse()?;

    let (conn, mut handle, _) = new_connection()?;
    tokio::spawn(conn);

    let mut config = MacsecConfig::new(ifindex);
    config.tx_sa = Some(Vec::new());
    config.rx_sc = Some(Vec::new());

    handle.apply(&config).await?;
    println!("removed all TX SAs and RX SCs from ifindex {ifindex}");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
