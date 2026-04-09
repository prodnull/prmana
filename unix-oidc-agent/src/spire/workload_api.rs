//! Hand-written protobuf stubs for the SPIFFE Workload API (JWT-SVID profile).
//!
//! Generated from the SPIFFE Workload API specification:
//! <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md>
//!
//! These stubs replace build-time protoc codegen to avoid adding a protoc build
//! dependency. Only the `FetchJWTSVID` RPC is implemented — that's all SpireSigner needs.

use prost::Message;

// ── Messages ────────────────────────────────────────────────────────────────

/// Request message for `FetchJWTSVID`.
#[derive(Clone, PartialEq, Message)]
pub struct JwtSvidRequest {
    /// Required. The audience(s) the workload intends to authenticate against.
    #[prost(string, repeated, tag = "1")]
    pub audience: Vec<String>,

    /// Optional. The requested SPIFFE ID. If unset, SVIDs for all entitled
    /// identities are returned.
    #[prost(string, tag = "2")]
    pub spiffe_id: String,
}

/// Response message for `FetchJWTSVID`.
#[derive(Clone, PartialEq, Message)]
pub struct JwtSvidResponse {
    /// The list of returned JWT-SVIDs.
    #[prost(message, repeated, tag = "1")]
    pub svids: Vec<JwtSvid>,
}

/// A single JWT-SVID returned by the Workload API.
#[derive(Clone, PartialEq, Message)]
pub struct JwtSvid {
    /// The SPIFFE ID of the JWT-SVID.
    #[prost(string, tag = "1")]
    pub spiffe_id: String,

    /// Encoded JWT using JWS Compact Serialization.
    #[prost(string, tag = "2")]
    pub svid: String,

    /// Optional. Operator-specified hint for identity disambiguation.
    #[prost(string, tag = "3")]
    pub hint: String,
}

// ── gRPC Client ─────────────────────────────────────────────────────────────

/// Generated gRPC client for `SpiffeWorkloadAPI.FetchJWTSVID`.
///
/// Only the `fetch_jwt_svid` method is exposed — we do not need
/// `ValidateJWTSVID` or `FetchJWTBundles` for the SpireSigner use case.
pub mod spiffe_workload_api_client {
    use super::{JwtSvidRequest, JwtSvidResponse};
    use tonic::codegen::*;

    #[derive(Debug, Clone)]
    pub struct SpiffeWorkloadApiClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl SpiffeWorkloadApiClient<tonic::transport::Channel> {
        /// Connect to a SPIRE agent Workload API endpoint.
        ///
        /// For Unix domain sockets, use `connect_uds()` instead.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> SpiffeWorkloadApiClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        /// Fetch JWT-SVIDs for the requested audience.
        ///
        /// The SPIFFE Workload API requires the `workload.spiffe.io: true`
        /// metadata header on every request (security gate).
        pub async fn fetch_jwt_svid(
            &mut self,
            request: impl tonic::IntoRequest<JwtSvidRequest>,
        ) -> std::result::Result<tonic::Response<JwtSvidResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| tonic::Status::new(tonic::Code::Unknown, e.into().to_string()))?;

            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/SpiffeWorkloadAPI/FetchJWTSVID",
            );

            let mut req = request.into_request();
            // Security: SPIRE Workload API mandates this header for workload attestation.
            req.metadata_mut().insert(
                "workload.spiffe.io",
                tonic::metadata::MetadataValue::from_static("true"),
            );

            self.inner.unary(req, path, codec).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_svid_request_roundtrip() {
        let req = JwtSvidRequest {
            audience: vec!["spiffe://example.com/server".to_string()],
            spiffe_id: String::new(),
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        let decoded = JwtSvidRequest::decode(&buf[..]).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_jwt_svid_response_roundtrip() {
        let resp = JwtSvidResponse {
            svids: vec![JwtSvid {
                spiffe_id: "spiffe://example.com/ns/default/sa/my-agent".to_string(),
                svid: "eyJhbGciOiJSUzI1NiJ9.e30.sig".to_string(),
                hint: String::new(),
            }],
        };
        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();
        let decoded = JwtSvidResponse::decode(&buf[..]).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_jwt_svid_request_with_spiffe_id() {
        let req = JwtSvidRequest {
            audience: vec!["aud1".to_string(), "aud2".to_string()],
            spiffe_id: "spiffe://td/ns/prod/sa/worker".to_string(),
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        let decoded = JwtSvidRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.audience, vec!["aud1", "aud2"]);
        assert_eq!(decoded.spiffe_id, "spiffe://td/ns/prod/sa/worker");
    }
}
