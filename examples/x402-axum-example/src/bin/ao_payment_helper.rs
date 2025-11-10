use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bundles_rs::{
    ans104::{data_item::DataItem, tags::Tag},
    crypto::arweave::ArweaveSigner,
};
use dotenvy::dotenv;
use reqwest::Client;
use std::env;
use std::str::FromStr;
use x402_rs::network::Network;
use x402_rs::types::{
    ExactAoPayload, ExactPaymentPayload, MoneyAmount, PaymentPayload, Scheme, TokenAmount,
    X402Version,
};

const AO_REQUIRED_TAGS: &[(&str, &str)] = &[
    ("Action", "Transfer"),
    ("Client", "x402"),
    ("Data-Protocol", "ao"),
    ("Variant", "ao.TN.1"),
    ("Type", "Message"),
    ("Content-Type", "text/plain"),
    ("SDK", "x402-facilitator"),
];

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let facilitator_url = env::var("AO_PROTECTED_URL")
        .unwrap_or_else(|_| "http://localhost:3000/protected-route".to_string());
    let token_target = env::var("AO_TOKEN_TARGET")
        .unwrap_or_else(|_| "0syT13r0s0tgPmIed95bJnuSqaD29HQNN8D3ElLSrsc".to_string());
    let recipient = env::var("AO_RECIPIENT")
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
    let human_amount = env::var("AO_AMOUNT").unwrap_or_else(|_| "0.000000000001".to_string());
    let payload = env::var("AO_PAYLOAD").unwrap_or_else(|_| "premium access test".to_string());
    let wallet_path = env::var("AO_WALLET_PATH").unwrap_or_else(|_| "./wallet.json".to_string());

    let signer = ArweaveSigner::from_jwk_file(&wallet_path)
        .expect("wallet.json must exist with Arweave JWK");
    let target_bytes = arweave_b64_to_32(&token_target)?;

    let decimals = x402_rs::network::USDCDeployment::by_network(Network::Ao).decimals as u32;
    let money_amount = MoneyAmount::from_str(&human_amount)
        .map_err(|e| anyhow::anyhow!("invalid AO_AMOUNT: {e}"))?;
    let token_amount: TokenAmount = money_amount
        .as_token_amount(decimals)
        .map_err(|e| anyhow::anyhow!("failed to scale AO_AMOUNT: {e}"))?;
    let quantity = token_amount.to_string();

    let mut tags: Vec<Tag> = AO_REQUIRED_TAGS
        .iter()
        .map(|(name, value)| Tag::new(*name, *value))
        .collect();
    tags.push(Tag::new("Recipient", recipient));
    tags.push(Tag::new("Quantity", quantity));

    let data_item = DataItem::build_and_sign(
        &signer,
        Some(target_bytes),
        None,
        tags,
        payload.into_bytes(),
    )?;
    let transaction = URL_SAFE_NO_PAD.encode(data_item.to_bytes()?);

    let payment_payload = PaymentPayload {
        x402_version: X402Version::V1,
        scheme: Scheme::Exact,
        network: x402_rs::network::Network::Ao,
        payload: ExactPaymentPayload::Ao(ExactAoPayload { transaction }),
    };
    let payload_json = serde_json::to_vec(&payment_payload)?;
    let encoded_header = STANDARD.encode(payload_json);

    let response = Client::new()
        .get(&facilitator_url)
        .header("X-Payment", encoded_header)
        .send()
        .await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<empty body>".to_string());
    println!("status={status} body={body}");

    Ok(())
}

fn arweave_b64_to_32(target: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(target.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64url target: {e}"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("target must be 32 bytes"))
}
