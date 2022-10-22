#[tokio::main]
async fn main() {}
mod http11;
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
    async fn test_hyper_stream_body_http() {
        use futures::TryStreamExt;
        let response = hyper::Client::new()
            .get("http://example.org".parse().unwrap())
            .await
            .unwrap();

        let mut body = response.into_body();

        while let Some(buffer) = body.try_next().await.unwrap() {
            println!("Read {} bytes", buffer.len());
        }
    }
    #[tokio::test]
    async fn test_hyper_stream_body_httpS() {
        let conn = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
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
    #[tokio::test]
    async fn raw() -> color_eyre::Result<()> {
        use nom::Offset;
        use rustls::{Certificate, ClientConfig, KeyLogFile, RootCertStore};
        use std::{str::FromStr, sync::Arc};

        use super::http11;
        use color_eyre::eyre::eyre;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
        };
        use tracing::info;
        /*
        let filter_layer =
            Targets::from_str(std::env::var("RUST_LOG").as_deref().unwrap_or("info")).unwrap();
        let format_layer = tracing_subscriber::fmt::layer();
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(format_layer)
            .init();
         */
        info!("Establishing a TCP connection...");
        let stream = TcpStream::connect("example.org:443").await.expect("msg");
        info!("Setting up TLS root certificate store");
        let mut root_store = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs")
        {
            root_store.add(&Certificate(cert.0));
        }

        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.key_log = Arc::new(KeyLogFile::new());
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        info!("Performing TLS handshake");
        let mut stream = connector
            .connect("example.org".try_into().expect("invalid DNS name"), stream)
            .await
            .expect("msg");

        info!("Sending HTTP/1.1 request");
        let req = [
            "GET / HTTP/1.1",
            "host: example.org",
            "user-agent: cool-bear/1.0",
            "connection: close",
            "",
            "",
        ]
        .join("\r\n"); // allocates gratuitously which is fine for a sample
        stream.write_all(req.as_bytes()).await;

        info!("Reading HTTP/1.1 response");
        let mut accum: Vec<u8> = Default::default();
        let mut rd_buf = [0u8; 1024];

        let (body_offset, res) = loop {
            let n = stream.read(&mut rd_buf[..]).await?;
            info!("Read {n} bytes");
            if n == 0 {
                return Err(eyre!(
                    "unexpected EOF (server closed connection during headers)"
                ));
            }

            accum.extend_from_slice(&rd_buf[..n]);

            match http11::response(&accum) {
                Err(e) => {
                    if e.is_incomplete() {
                        info!("Need to read more, continuing");
                        continue;
                    } else {
                        return Err(eyre!("parse error: {e}"));
                    }
                }
                Ok((remain, res)) => {
                    let body_offset = accum.offset(remain);
                    break (body_offset, res);
                }
            };
        };

        info!("Got HTTP/1.1 response: {:#?}", res);
        let mut body_accum = accum[body_offset..].to_vec();
        // header names are case-insensitive, let's get it right. we're assuming
        // that the absence of content-length means there's no body, and also we
        // don't support chunked transfer encoding.
        let content_length = res
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.parse::<usize>().unwrap())
            .unwrap_or_default();

        while body_accum.len() < content_length {
            let n = stream.read(&mut rd_buf[..]).await?;
            info!("Read {n} bytes");
            if n == 0 {
                return Err(eyre!("unexpected EOF (peer closed connection during body)"));
            }

            body_accum.extend_from_slice(&rd_buf[..n]);
        }

        info!("===== Response body =====");
        info!("{}", String::from_utf8_lossy(&body_accum));
        Ok(())
    }
}
