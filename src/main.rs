#[tokio::main]
async fn main() {}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_reqwest() {
        let response = reqwest::get("http://example.org").await.unwrap();
        println!(
            "Got HTTP {}, with headers: {:#?}",
            response.status(),
            response.headers()
        );

        let body = response.text().await.unwrap();

        let num_lines = 10;
        println!("First {num_lines} lines of body:");
        for line in body.lines().take(num_lines) {
            println!("{line}");
        }
    }
    #[tokio::test]
    async fn test_hyper() {
        let response = hyper::Client::new()
            .get("http://example.org".parse().unwrap())
            .await
            .unwrap();
        println!(
            "Got HTTP {}, with headers: {:#?}",
            response.status(),
            response.headers()
        );

        let body = response.body();
        println!("Body: {:?}", body);
    }
    #[tokio::test]
    async fn test_hyper_stream_body() {
        use futures::TryStreamExt;
        let response = hyper::Client::new()
            .get("https://example.org".parse().unwrap())
            .await
            .unwrap();

        let mut body = response.into_body();

        while let Some(buffer) = body.try_next().await.unwrap() {
            println!("Read {} bytes", buffer.len());
        }
    }
    #[tokio::test]
    async fn test_rustls() {
        use std::sync::Arc;

        use hyper_rustls::ConfigBuilderExt;
        use rustls::{ClientConfig, KeyLogFile};
        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_native_roots()
            .with_no_client_auth();
        // this is the fun option
        client_config.key_log = Arc::new(KeyLogFile::new());

        let conn = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_or_http()
            .enable_http1()
            .build();

        let client = hyper::Client::builder().build::<_, hyper::Body>(conn);

        let response = client
            .get("https://example.org".parse().unwrap())
            .await
            .unwrap();

        let body = String::from_utf8(
            hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        println!("response body: {body}");
    }
}
