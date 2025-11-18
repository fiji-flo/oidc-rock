use oidc_rock::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}
