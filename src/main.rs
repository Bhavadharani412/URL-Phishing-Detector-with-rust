use clap::Parser;
use regex::Regex;
use reqwest::blocking::Client;
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

#[derive(Parser, Debug)]
#[command(author, version, about = "Tiny URL Phishing Detector", long_about = None)]
struct Args {
    /// One or more URLs to analyze
    #[arg(required = true)]
    urls: Vec<String>,

    /// Follow redirects (will make HTTP requests)
    #[arg(short, long)]
    follow: bool,

    /// Output JSON
    #[arg(short, long)]
    json: bool,
}

#[derive(Serialize)]
struct Verdict {
    url: String,
    score: u8,
    verdict: String,
    reasons: Vec<String>,
    final_url: Option<String>,
}

fn is_ip_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

fn has_punycode(host: &str) -> bool {
    host.to_lowercase().contains("xn--")
}

fn count_subdomains(host: &str) -> usize {
    host.split('.').count()
}

fn suspicious_port(url: &Url) -> bool {
    if let Some(p) = url.port() {
        p != 80 && p != 443
    } else {
        false
    }
}

fn has_executable_path(path: &str) -> bool {
    let re = Regex::new(r"(?i)\.(exe|scr|zip|rar|msi|tar|gz)$").unwrap();
    re.is_match(path)
}

fn score_url(original: &Url, final_url_ref: Option<&Url>) -> (u8, Vec<String>) {
    let mut score: u8 = 0;
    let mut reasons = Vec::new();

    if original.as_str().contains('@') {
        score += 40;
        reasons.push("contains '@' (credential-trick)".into());
    }

    if let Some(host) = original.host_str() {
        if is_ip_host(host) {
            score += 30;
            reasons.push("host is raw IP".into());
        }

        if has_punycode(host) {
            score += 30;
            reasons.push("punycode in host (xn--), possible homograph".into());
        }

        let dots = count_subdomains(host);
        if dots > 3 {
            score += 10;
            reasons.push(format!("many subdomains ({} parts)", dots));
        }
    }

    if original.as_str().len() > 75 {
        score += 8;
        reasons.push("URL length > 75".into());
    }

    if suspicious_port(original) {
        score += 6;
        reasons.push(format!("non-standard port {:?}", original.port()));
    }

    if has_executable_path(original.path()) {
        score += 20;
        reasons.push("executable-like filename in path".into());
    }

    if let (Some(f), Some(o_host)) = (final_url_ref, original.host_str()) {
        if let Some(f_host) = f.host_str() {
            if f_host != o_host {
                score += 30;
                reasons.push(format!("redirects to different host ({})", f_host));
            }
        }
    }

    (score, reasons)
}

fn classify(score: u8) -> String {
    match score {
        0..=19 => "clean".into(),
        20..=49 => "suspicious".into(),
        _ => "phishy".into(),
    }
}

fn follow_redirects(client: &Client, url: &str) -> Option<String> {
    match client.get(url).send() {
        Ok(resp) => match resp.url().as_str().to_owned() {
            s if s.is_empty() => None,
            s => Some(s),
        },
        Err(_) => None,
    }
}

fn analyze_url(url_str: &str, follow: bool, client: &Client) -> Verdict {
    let parsed = Url::parse(url_str);
    let mut reasons = Vec::new();

    let url = match parsed {
        Ok(u) => u,
        Err(e) => {
            return Verdict {
                url: url_str.to_string(),
                score: 255,
                verdict: "invalid".into(),
                reasons: vec![format!("parse error: {}", e)],
                final_url: None,
            }
        }
    };

    let final_url = if follow {
        follow_redirects(client, url.as_str()).and_then(|s| Url::parse(&s).ok())
    } else {
        None
    };

    let (score, mut r) = score_url(&url, final_url.as_ref());
    reasons.append(&mut r);

    Verdict {
        url: url_str.to_string(),
        score,
        verdict: classify(score),
        reasons,
       final_url: final_url.map(|u| u.to_string()),


    }
}

fn main() {
    let args = Args::parse();
    let client = Client::builder()
        .timeout(Duration::from_secs(6))
        .danger_accept_invalid_certs(false)
        .build()
        .expect("reqwest client build failed");

    let mut results = Vec::new();
    for u in &args.urls {
        let v = analyze_url(u, args.follow, &client);
        if args.json {
            results.push(v);
        } else {
            // pretty print
            println!("URL: {}", v.url);
            println!("  Score: {} => {}", v.score, v.verdict);
            if !v.reasons.is_empty() {
                println!("  Reasons:");
                for r in &v.reasons {
                    println!("    - {}", r);
                }
            } else {
                println!("  Reasons: none");
            }
            if let Some(f) = &v.final_url {
                println!("  Final URL after redirects: {}", f);
            }
            println!();
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
    }
}
