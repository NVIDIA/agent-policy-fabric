// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell extension protocol metadata and compatibility checks.

use std::collections::BTreeSet;

use apf_proto::extension_v1::{PeerMetadata, ProtocolVersion};
use thiserror::Error;

const PROTOCOL_MAJOR: u32 = 1;
const PROTOCOL_MINOR: u32 = 0;
const MAX_IMPLEMENTATION_NAME_BYTES: usize = 128;
const MAX_IMPLEMENTATION_VERSION_BYTES: usize = 128;
const MAX_CAPABILITY_BYTES: usize = 128;
const MAX_CAPABILITIES: usize = 128;

/// OpenShell extension contract implemented by an APF adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionFamily {
    GatewayInterceptor,
    SupervisorMiddleware,
}

impl ExtensionFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GatewayInterceptor => "gateway-interceptor",
            Self::SupervisorMiddleware => "supervisor-middleware",
        }
    }

    fn contract_capability(self) -> String {
        format!("openshell.{}.contract", self.as_str())
    }
}

/// A protocol incompatibility that makes the extension unsafe to register.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NegotiationError {
    #[error(
        "gateway did not provide protocol metadata to {family} extension '{name}'; upgrade the gateway and extension together"
    )]
    MissingGatewayMetadata { family: &'static str, name: String },
    #[error("{family} peer '{name}' did not provide a protocol version")]
    MissingProtocolVersion { family: &'static str, name: String },
    #[error(
        "{family} extension '{name}' uses unsupported protocol {remote_major}.{remote_minor}; gateway supports {local_major}.{local_minor}"
    )]
    IncompatibleProtocol {
        family: &'static str,
        name: String,
        remote_major: u32,
        remote_minor: u32,
        local_major: u32,
        local_minor: u32,
    },
    #[error("{family} peer '{name}' has invalid {field}: {reason}")]
    InvalidMetadata {
        family: &'static str,
        name: String,
        field: &'static str,
        reason: String,
    },
    #[error("{family} extension '{name}' is missing required capabilities: {capabilities}")]
    MissingExtensionCapabilities {
        family: &'static str,
        name: String,
        capabilities: String,
    },
    #[error(
        "gateway is missing capabilities required by {family} extension '{name}': {capabilities}"
    )]
    MissingGatewayCapabilities {
        family: &'static str,
        name: String,
        capabilities: String,
    },
}

/// Build the metadata APF advertises for one OpenShell extension family.
#[must_use]
pub fn extension_metadata(
    family: ExtensionFamily,
    implementation_name: impl Into<String>,
    implementation_version: impl Into<String>,
) -> PeerMetadata {
    let contract = family.contract_capability();
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: implementation_name.into(),
        implementation_version: implementation_version.into(),
        supported_capabilities: vec![contract.clone()],
        required_capabilities: vec![contract],
    }
}

/// Reject a gateway that cannot satisfy the extension's protocol contract.
pub fn validate_gateway_metadata(
    family: ExtensionFamily,
    extension_name: impl Into<String>,
    extension: &PeerMetadata,
    gateway: Option<PeerMetadata>,
) -> Result<(), NegotiationError> {
    let extension_name = extension_name.into();
    let gateway = gateway.ok_or_else(|| NegotiationError::MissingGatewayMetadata {
        family: family.as_str(),
        name: extension_name.clone(),
    })?;
    negotiate(family, extension_name, extension, &gateway)
}

fn negotiate(
    family: ExtensionFamily,
    extension_name: String,
    extension: &PeerMetadata,
    gateway: &PeerMetadata,
) -> Result<(), NegotiationError> {
    let family_name = family.as_str();
    let extension_version = protocol_version(family_name, &extension_name, extension)?;
    let gateway_version = protocol_version(family_name, "gateway", gateway)?;
    if extension_version.major != gateway_version.major {
        return Err(NegotiationError::IncompatibleProtocol {
            family: family_name,
            name: extension_name,
            remote_major: extension_version.major,
            remote_minor: extension_version.minor,
            local_major: gateway_version.major,
            local_minor: gateway_version.minor,
        });
    }

    validate_peer(family_name, &extension_name, extension)?;
    validate_peer(family_name, "gateway", gateway)?;
    let extension_supported = normalize_capabilities(
        family_name,
        &extension_name,
        "supported_capabilities",
        &extension.supported_capabilities,
    )?;
    let extension_required = normalize_capabilities(
        family_name,
        &extension_name,
        "required_capabilities",
        &extension.required_capabilities,
    )?;
    let gateway_supported = normalize_capabilities(
        family_name,
        "gateway",
        "supported_capabilities",
        &gateway.supported_capabilities,
    )?;
    let gateway_required = normalize_capabilities(
        family_name,
        "gateway",
        "required_capabilities",
        &gateway.required_capabilities,
    )?;

    let missing_extension = gateway_required
        .difference(&extension_supported)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_extension.is_empty() {
        return Err(NegotiationError::MissingExtensionCapabilities {
            family: family_name,
            name: extension_name,
            capabilities: missing_extension.join(", "),
        });
    }
    let missing_gateway = extension_required
        .difference(&gateway_supported)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_gateway.is_empty() {
        return Err(NegotiationError::MissingGatewayCapabilities {
            family: family_name,
            name: extension_name,
            capabilities: missing_gateway.join(", "),
        });
    }
    Ok(())
}

fn protocol_version<'a>(
    family: &'static str,
    name: &str,
    metadata: &'a PeerMetadata,
) -> Result<&'a ProtocolVersion, NegotiationError> {
    metadata
        .protocol_version
        .as_ref()
        .ok_or_else(|| NegotiationError::MissingProtocolVersion {
            family,
            name: name.to_string(),
        })
}

fn validate_peer(
    family: &'static str,
    name: &str,
    metadata: &PeerMetadata,
) -> Result<(), NegotiationError> {
    validate_text(
        family,
        name,
        "implementation_name",
        &metadata.implementation_name,
        MAX_IMPLEMENTATION_NAME_BYTES,
    )?;
    validate_text(
        family,
        name,
        "implementation_version",
        &metadata.implementation_version,
        MAX_IMPLEMENTATION_VERSION_BYTES,
    )
}

fn validate_text(
    family: &'static str,
    name: &str,
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), NegotiationError> {
    let reason = if value.trim().is_empty() {
        Some("must not be empty".to_string())
    } else if value.len() > max_bytes {
        Some(format!("must be at most {max_bytes} bytes"))
    } else if value.chars().any(char::is_control) {
        Some("must not contain control characters".to_string())
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(NegotiationError::InvalidMetadata {
            family,
            name: name.to_string(),
            field,
            reason,
        });
    }
    Ok(())
}

fn normalize_capabilities(
    family: &'static str,
    name: &str,
    field: &'static str,
    capabilities: &[String],
) -> Result<BTreeSet<String>, NegotiationError> {
    if capabilities.len() > MAX_CAPABILITIES {
        return Err(NegotiationError::InvalidMetadata {
            family,
            name: name.to_string(),
            field,
            reason: format!("must contain at most {MAX_CAPABILITIES} entries"),
        });
    }
    let mut normalized = BTreeSet::new();
    for capability in capabilities {
        if !valid_capability(capability) {
            return Err(NegotiationError::InvalidMetadata {
                family,
                name: name.to_string(),
                field,
                reason: format!("'{capability}' must be a lowercase namespaced identifier"),
            });
        }
        if !normalized.insert(capability.clone()) {
            return Err(NegotiationError::InvalidMetadata {
                family,
                name: name.to_string(),
                field,
                reason: format!("contains duplicate '{capability}'"),
            });
        }
    }
    Ok(normalized)
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CAPABILITY_BYTES
        && value.starts_with("openshell.")
        && value.split('.').count() >= 3
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway_metadata(family: ExtensionFamily) -> PeerMetadata {
        extension_metadata(family, "openshell/gateway", "0.0.117")
    }

    #[test]
    fn matching_contract_negotiates() {
        let family = ExtensionFamily::GatewayInterceptor;
        let extension = extension_metadata(family, "apf/policy-adapter", "0.1.0");
        assert!(
            validate_gateway_metadata(
                family,
                "apf/policy-adapter",
                &extension,
                Some(gateway_metadata(family)),
            )
            .is_ok()
        );
    }

    #[test]
    fn missing_gateway_metadata_is_rejected() {
        let family = ExtensionFamily::GatewayInterceptor;
        let extension = extension_metadata(family, "apf/policy-adapter", "0.1.0");
        assert!(matches!(
            validate_gateway_metadata(family, "apf/policy-adapter", &extension, None),
            Err(NegotiationError::MissingGatewayMetadata { .. })
        ));
    }

    #[test]
    fn major_skew_is_rejected() {
        let family = ExtensionFamily::SupervisorMiddleware;
        let extension = extension_metadata(family, "apf/content-policy", "0.1.0");
        let mut gateway = gateway_metadata(family);
        gateway.protocol_version.as_mut().unwrap().major = 2;
        assert!(matches!(
            validate_gateway_metadata(family, "apf/content-policy", &extension, Some(gateway)),
            Err(NegotiationError::IncompatibleProtocol { .. })
        ));
    }

    #[test]
    fn unmet_capability_requirements_are_rejected_in_both_directions() {
        let family = ExtensionFamily::SupervisorMiddleware;
        let mut extension = extension_metadata(family, "apf/content-policy", "0.1.0");
        let mut gateway = gateway_metadata(family);
        gateway
            .required_capabilities
            .push("openshell.supervisor-middleware.future".to_string());
        assert!(matches!(
            validate_gateway_metadata(
                family,
                "apf/content-policy",
                &extension,
                Some(gateway_metadata(family)),
            ),
            Ok(())
        ));
        assert!(matches!(
            validate_gateway_metadata(family, "apf/content-policy", &extension, Some(gateway),),
            Err(NegotiationError::MissingExtensionCapabilities { .. })
        ));

        let mut gateway = gateway_metadata(family);
        extension
            .required_capabilities
            .push("openshell.supervisor-middleware.future".to_string());
        gateway.required_capabilities.truncate(1);
        assert!(matches!(
            validate_gateway_metadata(family, "apf/content-policy", &extension, Some(gateway)),
            Err(NegotiationError::MissingGatewayCapabilities { .. })
        ));
    }
}
