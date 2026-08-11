// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::pedantic, clippy::doc_markdown, clippy::doc_lazy_continuation)]

pub use prost_types;

pub mod nvidia {
    pub mod agent_policy_fabric {
        pub mod policy {
            pub mod v1alpha1 {
                tonic::include_proto!("nvidia.agent_policy_fabric.policy.v1alpha1");
            }
        }
        pub mod runtime {
            pub mod v1alpha1 {
                tonic::include_proto!("nvidia.agent_policy_fabric.runtime.v1alpha1");
            }
        }
        pub mod pdp {
            pub mod v1alpha1 {
                tonic::include_proto!("nvidia.agent_policy_fabric.pdp.v1alpha1");
            }
        }
        pub mod policy_service {
            pub mod v1alpha1 {
                tonic::include_proto!("nvidia.agent_policy_fabric.policy_service.v1alpha1");
            }
        }
    }
}

pub mod openshell {
    pub mod sandbox {
        pub mod v1 {
            tonic::include_proto!("openshell.sandbox.v1");
        }
    }
}

pub use nvidia::agent_policy_fabric::policy::v1alpha1 as ir;
pub use nvidia::agent_policy_fabric::runtime::v1alpha1 as runtime_v1alpha1;
pub use nvidia::agent_policy_fabric::pdp::v1alpha1 as pdp_v1alpha1;
pub use nvidia::agent_policy_fabric::policy_service::v1alpha1 as policy_service_v1alpha1;
pub use openshell::sandbox::v1 as openshell_sandbox;

pub mod json;
pub mod spec_digest;

pub use pdp_v1alpha1::evaluation_service_client;
pub use pdp_v1alpha1::evaluation_service_server;
pub use policy_service_v1alpha1::policy_service_client;
pub use policy_service_v1alpha1::policy_service_server;
