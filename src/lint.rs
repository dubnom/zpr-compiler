use std::collections::HashMap;

use serde::Serialize;

use crate::ptypes::{AllowClause, Class, Policy};
use zpr::policy_types::Attribute;

#[derive(Debug, Serialize)]
/// Advisory source diagnostic, independent of compiler errors and Werror.
pub struct LintDiagnostic {
    pub code: &'static str,
    pub severity: &'static str,
    pub line: usize,
    pub message: String,
}

fn accessor_attributes<'policy>(
    rule: &'policy AllowClause,
    classes: &HashMap<&str, &'policy Class>,
) -> Vec<&'policy Attribute> {
    let mut attributes = Vec::new();
    for clause in &rule.client {
        attributes.extend(clause.with.iter());
        let mut name = clause.class.as_str();
        while let Some(class) = classes.get(name) {
            attributes.extend(class.with_attrs.iter());
            if class.parent == name {
                break;
            }
            name = &class.parent;
        }
    }
    attributes
}

fn rule_target_signature(rule: &AllowClause) -> String {
    let mut flavors: Vec<String> = rule
        .client
        .iter()
        .map(|clause| clause.flavor.to_string())
        .collect();
    flavors.sort();
    flavors.dedup();
    let mut server: Vec<String> = rule.server.iter().map(ToString::to_string).collect();
    server.sort();
    format!(
        "{flavors:?}/{server:?}/{:?}/{:?}",
        rule.link.as_ref().map(ToString::to_string),
        rule.signal.as_ref().map(ToString::to_string)
    )
}

fn accessor_signature(rule: &AllowClause, classes: &HashMap<&str, &Class>) -> Vec<String> {
    let mut attributes: Vec<String> = accessor_attributes(rule, classes)
        .into_iter()
        .map(Attribute::to_instance_string)
        .collect();
    attributes.sort();
    attributes.dedup();
    attributes
}

pub(crate) fn lint_policy(policy: &Policy) -> Vec<LintDiagnostic> {
    let classes: HashMap<&str, &Class> = policy
        .defines
        .iter()
        .map(|class| (class.name.as_str(), class))
        .collect();
    let mut diagnostics = Vec::new();
    let mut warn = |code, line, message| {
        diagnostics.push(LintDiagnostic {
            code,
            severity: "warning",
            line,
            message,
        })
    };
    for (effect, rules) in [("allow", &policy.allows), ("deny", &policy.nevers)] {
        let mut seen = HashMap::new();
        for rule in rules {
            let line = rule.span.0.line;
            let signature = format!(
                "{:?}/{}",
                accessor_signature(rule, &classes),
                rule_target_signature(rule)
            );
            if let Some(prior) = seen.insert(signature, line) {
                warn(
                    "POLICY_DUPLICATE",
                    line,
                    format!(
                        "Duplicates the {effect} rule on line {prior}; remove the repeated rule."
                    ),
                );
            }
            let attributes = accessor_attributes(rule, &classes);
            let identities: Vec<String> = attributes
                .iter()
                .filter_map(|attribute| {
                    let key = attribute.zpl_key().to_lowercase();
                    if !attribute.zpl_values().is_empty()
                        && matches!(
                            key.as_str(),
                            "device.zpr.adapter.cn"
                                | "device.zpr.addr"
                                | "device.zprmachineid"
                                | "device.demo.machine_id"
                                | "user.sub"
                                | "user.uid"
                                | "user.name"
                                | "user.cn"
                                | "user.mail"
                                | "user.email"
                        )
                    {
                        Some(key)
                    } else {
                        None
                    }
                })
                .collect();
            if !identities.is_empty() {
                warn(
                    "POLICY_SPECIFIC_IDENTITY",
                    line,
                    format!(
                        "Accessor predicates pin individual devices or users through {}; prefer group, role, department or posture attributes unless this is an intentional infrastructure exception.",
                        identities.join(", ")
                    ),
                );
            }
            if effect == "allow"
                && attributes.iter().all(|attribute| {
                    (attribute.zpl_key().ends_with(".zpr.authority")
                        || attribute.zpl_key() == "device.zpr.adapter.cn")
                        && attribute.zpl_values().is_empty()
                })
            {
                warn("POLICY_BROAD_GRANT", line, "This grant has no group, role, department or posture restrictions; review its intended scope.".into());
            }
        }
    }
    for rule in &policy.allows {
        let attributes = accessor_signature(rule, &classes);
        if let Some(prior) = policy.allows.iter().find(|prior| {
            let broader = accessor_signature(prior, &classes);
            prior.span.0.line != rule.span.0.line
                && rule_target_signature(prior) == rule_target_signature(rule)
                && broader.len() < attributes.len()
                && broader
                    .iter()
                    .all(|attribute| attributes.contains(attribute))
        }) {
            warn(
                "POLICY_REDUNDANT",
                rule.span.0.line,
                format!(
                    "A broader grant on line {} already covers these accessor constraints for the same target and path; review whether this narrower rule adds assurance.",
                    prior.span.0.line
                ),
            );
        }
    }
    for (name, line) in policy
        .service_definitions
        .iter()
        .map(|service| (&service.service_class, service.pos.line))
        .chain(
            policy
                .embedded_services
                .iter()
                .map(|service| (&service.service_class, service.pos.line)),
        )
    {
        if !policy
            .allows
            .iter()
            .chain(&policy.nevers)
            .any(|rule| rule.server.iter().any(|clause| &clause.class == name))
        {
            warn(
                "POLICY_EMPTY_SERVICE",
                line,
                format!(
                    "Service {name} has no access rules; confirm this intentionally declares a denied-by-default service."
                ),
            );
        }
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::lint_policy;
    use crate::{context::CompilationCtx, lex::tokenize_str, parser::parse};

    #[test]
    fn groups_are_preferred_to_individual_accessors() {
        let source = "define SpecificUser as user with user.sub:alice.\ndefine Operators as user with user.role:Operator.\ndefine API as service with device.zpr.adapter.cn:api.\nprovide API at api.svc.zpr over TCP 443.\nallow SpecificUser.\nallow Operators.\nallow Operators.";
        let context = CompilationCtx::default();
        let tokens = tokenize_str(source, &context).expect("lint fixture should tokenize");
        let policy = parse(tokens.tokens, &context)
            .expect("lint fixture should parse")
            .policy;
        let diagnostics = lint_policy(&policy);
        assert!(diagnostics.iter().any(
            |diagnostic| diagnostic.code == "POLICY_SPECIFIC_IDENTITY" && diagnostic.line == 5
        ));
        assert!(!diagnostics.iter().any(|diagnostic| diagnostic.code
            == "POLICY_SPECIFIC_IDENTITY"
            && diagnostic.line == 6));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "POLICY_DUPLICATE" && diagnostic.line == 7)
        );
    }

    #[test]
    fn broad_grants_redundancy_and_empty_services_are_reported() {
        let source = "define API as service.\ndefine ClosedAPI as service.\nprovide API at api.svc.zpr over TCP 443.\nallow users.\nallow user.role:Operator users.\nprovide ClosedAPI at closed.svc.zpr over TCP 443.";
        let context = CompilationCtx::default();
        let tokens = tokenize_str(source, &context).expect("lint fixture should tokenize");
        let policy = parse(tokens.tokens, &context)
            .expect("lint fixture should parse")
            .policy;
        let diagnostics = lint_policy(&policy);
        for code in [
            "POLICY_BROAD_GRANT",
            "POLICY_REDUNDANT",
            "POLICY_EMPTY_SERVICE",
        ] {
            assert!(
                diagnostics.iter().any(|diagnostic| diagnostic.code == code),
                "missing {code}"
            );
        }
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "POLICY_SPECIFIC_IDENTITY")
        );
    }
}
