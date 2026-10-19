# nl-macsec

Linux netlink library for MACsec management for the
[rust-netlink](https://github.com/rust-netlink) project.

This crate manages MACsec secure channels and secure associations through
the `macsec` generic netlink family, as the `ip macsec` command of
[iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git)
does. The MACsec netdevice itself is created through rtnetlink, for example
with the `rtnetlink` crate.

`MacsecHandle::get_all` returns a parsed `MacsecConfig` for each MACsec
SecY. Filter the vector by `MacsecConfig::ifindex` when needed.

A complete desired state is applied with a single `MacsecHandle::apply`
call:

```rust,no_run
use nl_macsec::{MacsecConfig, MacsecSaConfig};

async fn configure() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_macsec::new_connection()?;
    tokio::spawn(conn);

    let current = handle.get_all().await?;
    println!("{current:?}");

    let mut config = MacsecConfig::new(3);
    let mut sa = MacsecSaConfig::new(0);
    sa.pn = Some(1);
    sa.key = Some(vec![0x81; 16]);
    sa.key_id = vec![0x01];
    sa.active = Some(true);
    config.tx_sa = Some(vec![sa]);
    handle.apply(&config).await?;
    Ok(())
}
```

List fields are left untouched when they are `None` and are complete
desired sets when they are `Some`. Set `tx_sa` or `rx_sc` to
`Some(Vec::new())` to remove all of them:

```rust,no_run
use nl_macsec::MacsecConfig;

async fn delete() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_macsec::new_connection()?;
    tokio::spawn(conn);

    let mut config = MacsecConfig::new(3);
    config.tx_sa = Some(Vec::new());
    config.rx_sc = Some(Vec::new());
    handle.apply(&config).await?;
    Ok(())
}
```

An RX SC is kept when it is still listed; set its `sa_list` to
`Some(Vec::new())` to delete all its SAs without deleting the SC.

## Examples

Runnable examples are in the `examples` directory (default `tokio_socket`
feature, run as root):

```console
cargo run --example show
cargo run --example configure -- <ifindex> <rx-sci-hex>
cargo run --example multi_sa -- <ifindex> <rx-sci-hex> [off|phy|mac]
cargo run --example purge -- <ifindex>
```

License: MIT
