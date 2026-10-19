use std::error::Error;

use nl_macsec::{
    MacSecOffload, MacsecConfig, MacsecRxScConfig, MacsecSaConfig,
    new_connection,
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
        .expect("usage: multi_sa <ifindex> <rx-sci-hex> [off|phy|mac]")
        .parse()?;
    let sci = u64::from_str_radix(
        args.next()
            .expect("usage: multi_sa <ifindex> <rx-sci-hex> [off|phy|mac]")
            .trim_start_matches("0x"),
        16,
    )?;
    let offload = match args.next().as_deref() {
        None => None,
        Some("off") => Some(MacSecOffload::Off),
        Some("phy") => Some(MacSecOffload::Phy),
        Some("mac") => Some(MacSecOffload::Mac),
        Some(mode) => {
            return Err(format!("invalid offload mode: {mode}").into());
        }
    };

    let (conn, mut handle, _) = new_connection()?;
    tokio::spawn(conn);

    let mut config = MacsecConfig::new(ifindex);
    config.tx_sa =
        Some(vec![sa(0, 0x81), sa(1, 0x82), sa(2, 0x83), sa(3, 0x84)]);

    let mut rx_sc = MacsecRxScConfig::new(sci);
    rx_sc.active = Some(true);
    rx_sc.sa_list =
        Some(vec![sa(0, 0x91), sa(1, 0x92), sa(2, 0x93), sa(3, 0x94)]);
    config.rx_sc = Some(vec![rx_sc]);

    handle.apply(&config).await?;
    println!(
        "applied 4 TX SAs and 4 RX SAs for SCI {sci:016x} on ifindex {ifindex}"
    );

    if let Some(offload) = offload {
        let mut config = MacsecConfig::new(ifindex);
        config.secy.offload = Some(offload);
        handle.apply(&config).await?;
        println!("set offload mode to {offload:?}");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
