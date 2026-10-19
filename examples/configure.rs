use std::error::Error;

use nl_macsec::{
    MacsecConfig, MacsecRxScConfig, MacsecSaConfig, new_connection,
};

fn sa(an: u8, key: u8) -> MacsecSaConfig {
    let mut sa = MacsecSaConfig::new(an);
    sa.pn = Some(1);
    sa.key = Some(vec![key; 16]);
    sa.key_id = vec![key];
    sa.active = Some(true);
    sa
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let ifindex: u32 = args
        .next()
        .expect("usage: configure <ifindex> <rx-sci-hex>")
        .parse()?;
    let sci = u64::from_str_radix(
        args.next()
            .expect("usage: configure <ifindex> <rx-sci-hex>")
            .trim_start_matches("0x"),
        16,
    )?;

    let (conn, mut handle, _) = new_connection()?;
    tokio::spawn(conn);

    let mut config = MacsecConfig::new(ifindex);
    config.tx_sa = Some(vec![sa(0, 0x81)]);

    let mut rx_sc = MacsecRxScConfig::new(sci);
    rx_sc.active = Some(true);
    rx_sc.sa_list = Some(vec![sa(0, 0x82)]);
    config.rx_sc = Some(vec![rx_sc]);

    handle.apply(&config).await?;
    println!(
        "applied TX SA 0 and RX SC {sci:016x} with RX SA 0 on ifindex \
         {ifindex}"
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
