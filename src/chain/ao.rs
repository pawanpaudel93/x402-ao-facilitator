use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bundles_rs::ans104::{data_item::DataItem, tags::Tag};
use reqwest::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::fmt::{Debug, Formatter};

use crate::chain::{FacilitatorLocalError, FromEnvByNetworkBuild};
use crate::facilitator::Facilitator;
use crate::from_env;
use crate::network::Network;
use crate::types::{
    ExactPaymentPayload, MixedAddress, PaymentRequirements, Scheme, SettleRequest, SettleResponse,
    SupportedPaymentKind, SupportedPaymentKindExtra, SupportedPaymentKindsResponse,
    TransactionHash, VerifyRequest, VerifyResponse, X402Version,
};

pub const AO_TOKEN_ADDRESS: &str = "0syT13r0s0tgPmIed95bJnuSqaD29HQNN8D3ElLSrsc";
pub const USDA_TOKEN_ADDRESS: &str = "FBt9A5GA_KXMMSxA2DJ0xZbAq8sLLU2ak-YJe9zDvg8";
pub const ARIO_TOKEN_ADDRESS: &str = "qNvAoz0TgcH7DMg8BCVn8jF32QH5L6T29VjHxhHqqGE";
pub const PIXL_TOKEN_ADDRESS: &str = "DM3FoZUq_yebASPhgd8pEIRIzDW6muXEhxz5-JwbZwo";
pub const WNDR_TOKEN_ADDRESS: &str = "7GoQfmSOct_aUOWKM4xbKGg6DzAmOgdKwg8Kf-CbHm4";

const AO_VARIANT: &str = "ao.TN.1";
const REQUIRED_STATIC_TAGS: &[(&str, &str)] = &[
    ("Action", "Transfer"),
    ("Client", "x402"),
    ("Data-Protocol", "ao"),
    ("Variant", AO_VARIANT),
    ("Type", "Message"),
    ("Content-Type", "text/plain"),
    ("SDK", "x402-facilitator"),
];
const TAG_RECIPIENT: &str = "Recipient";
const TAG_QUANTITY: &str = "Quantity";

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AoChain {
    pub network: Network,
    pub version: String,
}

#[allow(dead_code)]
impl AoChain {
    pub fn new(network: Network, version: String) -> Self {
        Self { network, version }
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

impl TryFrom<Network> for AoChain {
    type Error = FacilitatorLocalError;

    fn try_from(value: Network) -> Result<Self, Self::Error> {
        match value {
            Network::Ao => Ok(Self {
                network: value,
                version: AO_VARIANT.to_string(),
            }),
            _ => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
        }
    }
}

#[derive(Clone)]
pub struct AoProvider {
    client: Client,
    mu_url: String,
    chain: Network,
}

impl Debug for AoProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AoProvider")
            .field("mu_url", &self.mu_url)
            .field("network", &self.chain)
            .finish()
    }
}

impl FromEnvByNetworkBuild for AoProvider {
    async fn from_env(network: Network) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let env_var = from_env::rpc_env_name_from_network(network);
        let mu_url = match std::env::var(env_var).ok() {
            Some(mu_url) => mu_url,
            None => {
                tracing::warn!(network=%network, "no MU URL configured, skipping");
                return Ok(None);
            }
        };
        let provider = AoProvider::try_new(mu_url, network)?;
        Ok(Some(provider))
    }
}

impl AoProvider {
    pub fn try_new(mu_url: String, chain: Network) -> Result<Self, FacilitatorLocalError> {
        let client = Client::builder()
            .user_agent("x402-ao-facilitator")
            .build()
            .map_err(|e| {
                FacilitatorLocalError::ContractCall(format!("client build failed: {e}"))
            })?;
        Ok(Self {
            client,
            mu_url,
            chain,
        })
    }
    // dumb placeholder for backward compatibility
    // settling messages on ao (ANS-104 dataitems) doesnt require signing txs
    pub fn signer_address(&self) -> MixedAddress {
        MixedAddress::Offchain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string())
    }

    pub fn network(&self) -> Network {
        self.chain
    }

    fn parse_payment(&self, request: &VerifyRequest) -> Result<AoPayment, FacilitatorLocalError> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        if payload.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network(),
                payload.network,
            ));
        }
        if requirements.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network(),
                requirements.network,
            ));
        }
        if payload.scheme != requirements.scheme {
            return Err(FacilitatorLocalError::SchemeMismatch(
                None,
                requirements.scheme,
                payload.scheme,
            ));
        }

        let raw_payload = match &payload.payload {
            ExactPaymentPayload::Ao(payload) => payload.transaction.clone(),
            _ => return Err(FacilitatorLocalError::UnsupportedNetwork(None)),
        };

        let raw_bytes = URL_SAFE_NO_PAD.decode(raw_payload.trim()).map_err(|e| {
            FacilitatorLocalError::DecodingError(format!("invalid base64 data: {e}"))
        })?;

        let data_item = DataItem::from_bytes(raw_bytes.as_slice()).map_err(|e| {
            FacilitatorLocalError::DecodingError(format!("invalid ANS-104 dataitem: {e}"))
        })?;

        let encoded_target = data_item
            .target
            .as_ref()
            .map(|target| URL_SAFE_NO_PAD.encode(target))
            .ok_or_else(|| {
                FacilitatorLocalError::DecodingError(format!("dataitem missing target field"))
            })?;

        let payer = MixedAddress::Offchain(encoded_target);
        self.validate_data_item(&data_item, requirements, &payer)?;

        Ok(AoPayment {
            payer,
            bytes: raw_bytes,
        })
    }

    fn validate_data_item(
        &self,
        data_item: &DataItem,
        requirements: &PaymentRequirements,
        payer: &MixedAddress,
    ) -> Result<(), FacilitatorLocalError> {
        let encoded_target = data_item
            .target
            .as_ref()
            .map(|target| URL_SAFE_NO_PAD.encode(target))
            .ok_or_else(|| {
                FacilitatorLocalError::DecodingError(format!("dataitem missing target field"))
            })?;

        let expected_asset = expect_offchain(&requirements.asset, "asset")?;
        if encoded_target != expected_asset {
            return Err(FacilitatorLocalError::InvalidAddress(format!(
                "unsupported payment target {encoded_target}"
            )));
        }

        ensure_required_tags(&data_item.tags)?;

        let recipient = tag_value(&data_item.tags, TAG_RECIPIENT).ok_or_else(|| {
            FacilitatorLocalError::DecodingError("dataitem missing Recipient tag".to_string())
        })?;
        let expected_recipient = expect_offchain(&requirements.pay_to, "pay_to")?;
        if recipient != expected_recipient {
            return Err(FacilitatorLocalError::ReceiverMismatch(
                payer.clone(),
                recipient.to_string(),
                expected_recipient,
            ));
        }

        let quantity = tag_value(&data_item.tags, TAG_QUANTITY).ok_or_else(|| {
            FacilitatorLocalError::DecodingError("dataitem missing Quantity tag".to_string())
        })?;
        let normalized_quantity = normalize_numeric(quantity);
        let required_amount = requirements.max_amount_required.to_string();
        if normalized_quantity != required_amount {
            return Err(FacilitatorLocalError::InsufficientValue(payer.clone()));
        }

        Ok(())
    }

    async fn submit_to_mu(&self, bytes: &[u8]) -> Result<Option<String>, FacilitatorLocalError> {
        let response = self
            .client
            .post(&self.mu_url)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(ACCEPT, "application/json")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| FacilitatorLocalError::ContractCall(format!("MU request failed: {e}")))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "failed to read MU response body".to_string());

        if !status.is_success() {
            return Err(FacilitatorLocalError::ContractCall(format!(
                "MU rejected message ({status}): {body}"
            )));
        }

        Ok(extract_message_id(&body))
    }
}

impl Facilitator for AoProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let payment = self.parse_payment(request)?;
        Ok(VerifyResponse::valid(payment.payer))
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let payment = self.parse_payment(request)?;
        let message_id = self.submit_to_mu(&payment.bytes).await?;
        let settle_response = SettleResponse {
            success: true,
            error_reason: None,
            payer: payment.payer,
            transaction: message_id.map(TransactionHash::Offchain),
            network: self.network(),
        };
        Ok(settle_response)
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        let kinds = vec![SupportedPaymentKind {
            network: self.network().to_string(),
            scheme: Scheme::Exact,
            x402_version: X402Version::V1,
            extra: Some(SupportedPaymentKindExtra {
                fee_payer: self.signer_address(),
            }),
        }];
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}

struct AoPayment {
    payer: MixedAddress,
    bytes: Vec<u8>,
}

fn ensure_required_tags(tags: &[Tag]) -> Result<(), FacilitatorLocalError> {
    for (name, value) in REQUIRED_STATIC_TAGS {
        let matches = tags
            .iter()
            .any(|tag| tag.name == *name && tag.value == *value);
        if !matches {
            return Err(FacilitatorLocalError::DecodingError(format!(
                "dataitem missing required tag {name}={value}"
            )));
        }
    }
    Ok(())
}

#[allow(unused_variables)]
fn expect_offchain(address: &MixedAddress, field: &str) -> Result<String, FacilitatorLocalError> {
    match address {
        MixedAddress::Offchain(value) => Ok(value.clone()),
        MixedAddress::Evm(addr) => {
            #[cfg(feature = "telemetry")]
            tracing::warn!(%addr, "{} address provided for ao payment is EVM; treating as string", field);
            Ok(addr.to_string())
        }
        MixedAddress::Solana(addr) => {
            #[cfg(feature = "telemetry")]
            tracing::warn!(%addr, "{} address provided for ao payment is Solana; treating as string", field);
            Ok(addr.to_string())
        }
    }
}

fn tag_value<'a>(tags: &'a [Tag], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.name == name)
        .map(|tag| tag.value.as_str())
}

fn normalize_numeric(value: &str) -> String {
    let trimmed = value.trim();
    let without_leading = trimmed.trim_start_matches('0');
    if without_leading.is_empty() {
        "0".to_string()
    } else {
        without_leading.to_string()
    }
}

fn extract_message_id(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok().and_then(|value| {
        value
            .get("messageId")
            .or_else(|| value.get("message_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    })
}
