use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use dotenvy::dotenv;
use opentelemetry::trace::Status;
use serde_json::json;
use std::env;
use tower_http::trace::TraceLayer;
use tracing::instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use x402_axum::{IntoPriceTag, X402Middleware};
use x402_rs::network::{Network, USDCDeployment};
use x402_rs::telemetry::Telemetry;
use x402_rs::types::MixedAddress;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let _telemetry = Telemetry::new()
        .with_name(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .register();

    let facilitator_url =
        env::var("FACILITATOR_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let x402 = X402Middleware::try_from(facilitator_url)
        .unwrap()
        .with_base_url(url::Url::parse("https://localhost:3000/").unwrap());
    let usdc_ao = USDCDeployment::by_network(Network::Ao).pay_to(MixedAddress::Offchain(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    ));

    let app = Router::new()
        .route(
            "/protected-route",
            get(my_handler).layer(
                x402.with_description("Premium API - Discoverable")
                    .with_mime_type("application/json")
                    .with_input_schema(serde_json::json!({
                        "type": "http",
                        "method": "GET",
                        "discoverable": true,
                        "description": "Access premium content"
                    }))
                    .with_output_schema(serde_json::json!({
                        "type": "string",
                        "description": "VIP content response"
                    }))
                    .with_price_tag(usdc_ao.amount("0.000000000001").unwrap()), // 1 winston unit in $AO
            ),
        )
        .layer(
            // Usual HTTP tracing
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "http_request",
                        otel.kind = "server",
                        otel.name = %format!("{} {}", request.method(), request.uri()),
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
                    )
                })
                .on_response(
                    |response: &axum::http::Response<_>,
                     latency: std::time::Duration,
                     span: &tracing::Span| {
                        span.record("status", tracing::field::display(response.status()));
                        span.record("latency", tracing::field::display(latency.as_millis()));
                        span.record(
                            "http.status_code",
                            tracing::field::display(response.status().as_u16()),
                        );

                        // OpenTelemetry span status
                        if response.status().is_success()
                            || response.status() == StatusCode::PAYMENT_REQUIRED
                        {
                            span.set_status(Status::Ok);
                        } else {
                            span.set_status(Status::error(
                                response
                                    .status()
                                    .canonical_reason()
                                    .unwrap_or("unknown")
                                    .to_string(),
                            ));
                        }

                        tracing::info!(
                            "status={} elapsed={}ms",
                            response.status().as_u16(),
                            latency.as_millis()
                        );
                    },
                ),
        );

    tracing::info!("Using facilitator on {}", x402.facilitator_url());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Can not start server");
    tracing::info!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[instrument(skip_all)]
async fn my_handler() -> impl IntoResponse {
    (StatusCode::OK, "This is a VIP content!")
}

#[instrument(skip_all)]
async fn weather_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(json!({
            "temperature": 72,
            "conditions": "sunny",
            "humidity": 45
        })),
    )
}

#[instrument(skip_all)]
async fn internal_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(json!({
            "status": "admin_access_granted"
        })),
    )
}
