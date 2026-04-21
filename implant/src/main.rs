mod beacon;
mod config;
mod modules;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::load()?;
    beacon::run(cfg).await
}
