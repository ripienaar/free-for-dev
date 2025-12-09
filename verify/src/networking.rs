use reqwest::{Client, Error, StatusCode};

pub async fn url_is_valid(client: &Client, url: &str) -> bool {
    let Some(base_url) = base_url(url) else {
        return true;
    };

    let request = make_request(client, url).await;

    let status = match request {
        Ok(s) if s.is_success() => request,
        _ => {
            let robots = format!("{}/robots.txt", base_url);
            make_request(client, &robots).await
        }
    };
    let status = match status {
        Ok(status) => status,
        Err(e) => {
            println!("Error: {:?}", e);
            return false;
        }
    };
    println!("VALIDITY CHECKED FOR {:?} - {}", url.to_uppercase(), status);

    status != 404
}

async fn make_request(client: &Client, url: &str) -> Result<StatusCode, reqwest::Error> {
    let response = client
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                               AppleWebKit/537.36 (KHTML, like Gecko) \
                               Chrome/122.0.0.0 Safari/537.36")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "keep-alive")
        .header("Upgrade-Insecure-Requests", "1")
        .header("Sec-Fetch-Dest", "document")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Site", "none")
        .header("Sec-Fetch-User", "?1")
        .send()
        .await?;

    Ok(response.status())
}

fn base_url(url: &str) -> Option<String> {
    // Remove path after domain
    if let Some(pos) = url.find("://") {
        let scheme = &url[..pos + 3];
        let rest = &url[pos + 3..];
        let host = rest.split('/').next()?;
        return Some(format!("{}{}", scheme, host));
    }
    None
}
