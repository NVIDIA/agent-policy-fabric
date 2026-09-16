// SPDX-License-Identifier: Apache-2.0
//! Coercion of request-derived values into the schema's string profiles.
//!
//! A value the schema rejects fails the whole record, letting a caller suppress
//! the event documenting their own request. Coercing costs the value instead.
//!
//! Lossy: distinct inputs can collapse onto one, including onto a legitimate
//! name. Producers that need the original must keep it themselves.

/// Sentinel for a value with nothing schema-valid left in it.
///
/// Forgeable: any caller can supply a value that coerces to it. Producers that
/// need an unforgeable marker set `reason`, which is not caller-influenced.
pub const UNSPECIFIED: &str = "unspecified";

fn coerce(value: &str, extra: &[char], max: usize) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || extra.contains(c))
        .collect();
    match cleaned.find(|c: char| c.is_ascii_alphanumeric()) {
        Some(start) => cleaned[start..].chars().take(max).collect(),
        None => UNSPECIFIED.to_owned(),
    }
}

/// `$defs/name`: alphanumerics plus `._:-`, 128 characters.
///
/// The narrower profile: `resource.type`, `component`, `runtime_substrate`.
/// Note `enforcement_point_id` is an `id`, not a `name`.
#[must_use]
pub fn coerce_name(value: &str) -> String {
    coerce(value, &['.', '_', ':', '-'], 128)
}

/// `$defs/id`: alphanumerics plus `._:@/+-=`, 512 characters.
///
/// The wider profile, for values that carry paths, emails or base64 — subject
/// identity and `resource.id`.
#[must_use]
pub fn coerce_id(value: &str) -> String {
    coerce(value, &['.', '_', ':', '@', '/', '+', '-', '='], 512)
}

/// `$defs/digest`'s opaque-token alternative: alphanumerics plus `._:@/+-=`,
/// 256 characters.
///
/// Fixes the charset only. A credential-shaped digest passes this and still
/// trips sanitizing, and the fallback reuses the same envelope — so a producer
/// must also replace the digest with a sentinel in its fallback, the way it
/// regenerates `correlation_id`.
#[must_use]
pub fn coerce_digest(value: &str) -> String {
    coerce(value, &['.', '_', ':', '@', '/', '+', '-', '='], 256)
}

/// `$defs/reason_code` and `$defs/verb`, which share one pattern:
/// dot-separated lowercase segments, 160 characters.
///
/// Worth coercing even where every caller passes a literal: these values are
/// typically reused verbatim in a producer's fallback record, so an invalid one
/// fails both attempts and erases the event.
#[must_use]
pub fn coerce_lower_dotted(value: &str) -> String {
    let joined = value
        .split('.')
        .map(|segment| {
            segment
                .chars()
                .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect::<String>()
        })
        .filter(|segment| segment.starts_with(|c: char| c.is_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join(".");
    // Truncation can strand a trailing separator, which the pattern rejects.
    let capped = joined.chars().take(160).collect::<String>();
    let trimmed = capped.trim_end_matches('.');
    if trimmed.is_empty() {
        UNSPECIFIED.to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The three schema patterns, written out rather than pulled in as regexes:
    // a dependency to check `[a-z0-9_]` would cost more than it explains.

    /// `^[A-Za-z0-9][A-Za-z0-9<extra>]{0,max-1}$`
    fn matches_profile(value: &str, extra: &[char], max: usize) -> bool {
        let mut chars = value.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && chars.all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
            && value.chars().count() <= max
    }

    /// `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`
    fn matches_lower_dotted(value: &str) -> bool {
        value.chars().count() <= 160
            && !value.is_empty()
            && value.split('.').all(|segment| {
                let mut chars = segment.chars();
                chars.next().is_some_and(|c| c.is_ascii_lowercase())
                    && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
    }

    /// The inputs a producer actually sees: URL segments, subject claims, and
    /// whatever a caller sends instead.
    fn hostile_inputs() -> Vec<String> {
        let mut v: Vec<String> = [
            "",
            "-",
            ".",
            "...",
            "!!!",
            "9leading-digit",
            "../../etc/shadow",
            "clé_secrète",
            "name with spaces",
            "UPPER.case",
            "trailing.dot.",
            "null\u{0}byte",
            "emoji-🙂-inside",
            "sk-abcdefghijklmnopqrstuvwx",
            "openshell.sandbox.v1",
            "user@example.com",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        v.push("x".repeat(2000));
        v.push("a.".repeat(200));
        v
    }

    /// Every profile must accept every coercion output. A single escaping input
    /// is a suppression primitive, so this is exhaustive over the corpus rather
    /// than a sample.
    #[test]
    fn coercion_output_always_satisfies_its_profile() {
        for input in hostile_inputs() {
            let n = coerce_name(&input);
            assert!(
                matches_profile(&n, &['.', '_', ':', '-'], 128),
                "name rejected {n:?} from {input:?}"
            );

            let i = coerce_id(&input);
            assert!(
                matches_profile(&i, &['.', '_', ':', '@', '/', '+', '-', '='], 512),
                "id rejected {i:?} from {input:?}"
            );

            let g = coerce_digest(&input);
            assert!(
                matches_profile(&g, &['.', '_', ':', '@', '/', '+', '-', '='], 256),
                "digest rejected {g:?} from {input:?}"
            );

            let d = coerce_lower_dotted(&input);
            assert!(
                matches_lower_dotted(&d),
                "verb rejected {d:?} from {input:?}"
            );
        }
    }

    /// Values already valid must survive unchanged, or coercion would quietly
    /// rewrite legitimate records.
    #[test]
    fn valid_values_pass_through_untouched() {
        assert_eq!(coerce_name("openshell.sandbox.v1"), "openshell.sandbox.v1");
        assert_eq!(coerce_id("user@example.com"), "user@example.com");
        assert_eq!(
            coerce_lower_dotted("policy.get_document"),
            "policy.get_document"
        );
    }

    /// The distinction that makes the pair worth having: `id` keeps characters
    /// `name` must not accept.
    #[test]
    fn the_two_profiles_are_not_interchangeable() {
        assert_eq!(coerce_id("a/b+c=d"), "a/b+c=d");
        assert_eq!(coerce_name("a/b+c=d"), "abcd");
    }

    /// Truncation is where a coercion most easily emits something invalid: the
    /// cut can land on a separator the pattern forbids at the end.
    #[test]
    fn truncation_cannot_strand_a_trailing_separator() {
        let long = "ab.".repeat(100);
        let out = coerce_lower_dotted(&long);
        assert!(!out.ends_with('.'), "{out}");
        assert!(out.chars().count() <= 160);
    }

    #[test]
    fn input_with_nothing_valid_left_becomes_the_sentinel() {
        for input in ["", "!!!", "...", "🙂", "-", "UPPER"] {
            assert_eq!(coerce_lower_dotted(input), UNSPECIFIED, "{input:?}");
        }
        for input in ["", "!!!", "🙂"] {
            assert_eq!(coerce_name(input), UNSPECIFIED, "{input:?}");
            assert_eq!(coerce_id(input), UNSPECIFIED, "{input:?}");
        }
    }
}
