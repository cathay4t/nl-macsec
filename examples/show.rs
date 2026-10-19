// SPDX-License-Identifier: MIT

use std::error::Error;

use nl_macsec::new_connection;

async fn run() -> Result<(), Box<dyn Error>> {
    let (conn, mut handle, _) = new_connection()?;
    tokio::spawn(conn);

    for config in handle.get_all().await? {
        println!("{config:#?}");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
