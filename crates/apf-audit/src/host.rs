// SPDX-License-Identifier: Apache-2.0
//! Host-qualified component identity.

use crate::coercion::coerce_id;
use crate::sanitization::SanitizationGuard;

/// `instance_id` qualified by the machine, so records from two instances
/// sharing a log pipeline stay distinguishable. Falls back to the bare
/// enforcement point id when the hostname is unavailable.
#[must_use]
pub fn host_qualified_instance_id(enforcement_point_id: &str) -> String {
    let host = nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    qualify(enforcement_point_id, &host)
}

fn qualify(enforcement_point_id: &str, host: &str) -> String {
    if host.is_empty() {
        return enforcement_point_id.to_owned();
    }
    let qualified = coerce_id(&format!("{enforcement_point_id}@{host}"));
    // A credential-shaped hostname would fail sanitization and suppress
    // every record the component writes.
    if SanitizationGuard::accepts_string(&qualified) {
        qualified
    } else {
        enforcement_point_id.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::qualify;
    use crate::sanitization::SanitizationGuard;

    #[test]
    fn credential_shaped_hostname_falls_back_to_bare_id() {
        let qualified = qualify("apf-x:seam", "task-classification-worker9012345");
        assert_eq!(qualified, "apf-x:seam");
        assert!(SanitizationGuard::accepts_string(&qualified));
    }

    #[test]
    fn ordinary_hostname_is_appended() {
        assert_eq!(qualify("apf-x:seam", "build-42"), "apf-x:seam@build-42");
    }

    #[test]
    fn empty_hostname_falls_back_to_bare_id() {
        assert_eq!(qualify("apf-x:seam", ""), "apf-x:seam");
    }
}
