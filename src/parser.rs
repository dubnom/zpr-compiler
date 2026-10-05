use std::collections::HashMap;

use crate::allow::parse_allow;
use crate::context::CompilationCtx;
use crate::define::{parse_define, resolve_class_flavors};
use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::never::parse_never;
use crate::ptypes::{AllowClause, Class, ClassFlavor, EmbeddedService, Policy, ServiceDefinition};

#[derive(Default)]
pub struct ParsingResult {
    pub policy: Policy,
}

// State of statement
enum StatementState {
    Waiting,
    InStatement,
}
pub fn parse(tokens: Vec<Token>, ctx: &CompilationCtx) -> Result<ParsingResult, CompilationError> {
    let mut result = ParsingResult::default();
    let mut statements = Vec::new();
    let mut current_statement = Vec::new();

    // Convert the tokens into statements, which are just sub-lists of the tokens.
    // Every statement begins on a new line and is terminated by a
    // period followed by a newline (end of input also qualifies). Blank lines
    // and comment-only lines are insignificant.
    let mut state = StatementState::Waiting;
    let mut in_never = false;
    let mut period_line = 0;
    for tok in tokens {
        match tok.tt {
            TokenType::Period => match state {
                StatementState::InStatement => {
                    statements.push(current_statement);
                    current_statement = Vec::new();
                    in_never = false;
                    period_line = tok.line;
                    state = StatementState::Waiting;
                }
                _ => {
                    return Err(CompilationError::ParseError(
                        "unexpected '.'".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
            },
            TokenType::Allow if in_never => {
                in_never = false;
                current_statement.push(tok);
            }
            TokenType::Allow | TokenType::Define | TokenType::Never | TokenType::Provide => {
                match state {
                    StatementState::Waiting => {
                        if tok.line == period_line {
                            return Err(CompilationError::MissingNewline(tok.line, tok.col));
                        }
                        in_never = tok.tt == TokenType::Never;
                        current_statement.push(tok);
                        state = StatementState::InStatement;
                    }
                    StatementState::InStatement => {
                        return Err(CompilationError::MissingStatementTerminator(
                            tok.line, tok.col,
                        ));
                    }
                }
            }
            TokenType::Literal(ref keyword)
                if keyword.eq_ignore_ascii_case("service")
                    && matches!(state, StatementState::Waiting) =>
            {
                if tok.line == period_line {
                    return Err(CompilationError::MissingNewline(tok.line, tok.col));
                }
                current_statement.push(tok);
                state = StatementState::InStatement;
            }
            _ => match state {
                StatementState::InStatement => current_statement.push(tok),
                StatementState::Waiting => {
                    if tok.line == period_line {
                        return Err(CompilationError::MissingNewline(tok.line, tok.col));
                    }
                    return Err(CompilationError::ParseError(
                        "unexpected token".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
            },
        }
    }
    if let StatementState::InStatement = state {
        let last = current_statement.last().expect("open statement has tokens");
        return Err(CompilationError::MissingStatementTerminator(
            last.line, last.col,
        ));
    }

    if statements.is_empty() {
        ctx.warn("empty policy")?;
    }

    let mut policy = Policy::default();

    let mut classes: HashMap<String, Class> = HashMap::new();

    // Add default classes:
    for defclass in Class::defaults() {
        classes.insert(defclass.name.clone(), defclass);
    }

    // Construct an index that adds entries for all the AKAs.
    let mut class_index: HashMap<String, String> = HashMap::new();
    for (name, class) in classes.iter() {
        for n in class.iterate_all_names() {
            class_index.insert(n.to_lowercase(), name.clone());
        }
    }

    // Define statements create classes.
    for (i, statement) in statements.iter().enumerate() {
        if statement[0].tt == TokenType::Define {
            let class = parse_define(statement, i + 1)?;
            for new_name in class.iterate_all_names() {
                if class_index.contains_key(&new_name.to_lowercase()) {
                    return Err(CompilationError::Redefinition(
                        new_name.clone(),
                        statement[0].line,
                        statement[0].col,
                    ));
                }
            }
            let cname = class.name.clone();
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), cname.clone());
            }
            classes.insert(cname, class);
        }
    }

    // Take a pass over the defines to resolve all the child/parent relationships and
    // compute the correct flavors.
    resolve_class_flavors(&mut classes)?;

    // Now make sure all attributes have a domain.
    for (_, class) in classes.iter_mut() {
        for attr in class.with_attrs.iter_mut() {
            if attr.is_unspecified_domain() {
                attr.set_domain(class.flavor.into());
            }
            if attr.is_unspecified_domain() {
                return Err(CompilationError::ParseError(
                    format!("attribute {} has no domain", attr.zpl_key()),
                    class.pos.line,
                    class.pos.col,
                ));
            }
        }
    }

    let mut declared_service_classes = HashMap::new();
    let mut declared_dns_names = HashMap::new();
    let mut scoped_service_classes = vec![None; statements.len()];
    let mut active_service_class = None;
    for (statement_index, statement) in statements.iter().enumerate() {
        if matches!(&statement[0].tt, TokenType::Literal(keyword) if keyword.eq_ignore_ascii_case("service"))
        {
            let embedded = parse_embedded_service(statement, &class_index, &classes)?;
            if policy
                .embedded_services
                .iter()
                .any(|existing: &EmbeddedService| existing.service_class == embedded.service_class)
            {
                return Err(CompilationError::ParseError(
                    format!(
                        "service class {} has more than one JSON definition",
                        embedded.service_class
                    ),
                    embedded.pos.line,
                    embedded.pos.col,
                ));
            }
            active_service_class = Some(embedded.service_class.clone());
            policy.embedded_services.push(embedded);
            continue;
        }
        match statement[0].tt {
            TokenType::Provide => {
                let definition = parse_service_definition(statement, &class_index, &classes)?;
                if declared_service_classes
                    .insert(definition.service_class.clone(), definition.pos.clone())
                    .is_some()
                {
                    return Err(CompilationError::ParseError(
                        format!(
                            "service class {} is declared more than once",
                            definition.service_class
                        ),
                        definition.pos.line,
                        definition.pos.col,
                    ));
                }
                if declared_dns_names
                    .insert(definition.dns_name.clone(), definition.pos.clone())
                    .is_some()
                {
                    return Err(CompilationError::ParseError(
                        format!(
                            "DNS name {} is declared more than once",
                            definition.dns_name
                        ),
                        definition.pos.line,
                        definition.pos.col,
                    ));
                }
                active_service_class = Some(definition.service_class.clone());
                if definition.service_class != crate::zpl::DEF_CLASS_VISA_SERVICE_NAME {
                    policy.service_definitions.push(definition);
                }
            }
            TokenType::Allow | TokenType::Never => {
                scoped_service_classes[statement_index] = active_service_class.clone();
            }
            _ => active_service_class = None,
        }
    }

    // Parse access rules in source order so each target-free rule inherits the
    // service from the immediately preceding provide or embedded-service declaration.
    for (i, statement) in statements.iter().enumerate() {
        if statement[0].tt == TokenType::Never {
            let never = parse_access_rule(
                statement,
                i + 1,
                scoped_service_classes[i].as_deref(),
                &class_index,
                &classes,
            )?;
            if ctx.verbose {
                println!("{}", never.to_string_never());
            }
            policy.nevers.push(never);
        } else if statement[0].tt == TokenType::Allow {
            let allow = parse_access_rule(
                statement,
                i + 1,
                scoped_service_classes[i].as_deref(),
                &class_index,
                &classes,
            )?;
            if ctx.verbose {
                println!("{}", allow);
            }
            policy.allows.push(allow);
        }
    }

    if ctx.verbose {
        println!()
    }

    // Move all the classes in the policy, in ZPL source order. `classes` is a HashMap, so
    // draining it directly randomizes `defines`, which in turn randomizes the `#N` suffix
    // assigned to same-config-id services downstream.
    let mut ordered_classes: Vec<Class> = classes.into_values().collect();
    ordered_classes
        .sort_by(|a, b| (a.pos.line, a.pos.col, &a.name).cmp(&(b.pos.line, b.pos.col, &b.name)));
    for class in ordered_classes.into_iter() {
        // Not sure i need the built in ones?
        if class.is_builtin() {
            continue;
        }
        if ctx.verbose {
            println!("defined class: {} (is a {:?})", class.name, class.flavor);
            for attr in &class.with_attrs {
                println!("  with: {}", attr.to_instance_string());
            }
        }
        policy.defines.push(class);
    }

    result.policy = policy;
    Ok(result)
}

fn parse_access_rule(
    statement: &[Token],
    statement_id: usize,
    service_context: Option<&str>,
    class_index: &HashMap<String, String>,
    classes: &HashMap<String, Class>,
) -> Result<AllowClause, CompilationError> {
    let clause_start = usize::from(statement[0].tt == TokenType::Never);
    let signal_start = statement
        .iter()
        .position(|token| token.tt == TokenType::Signal)
        .map(|index| {
            if index > clause_start && statement[index - 1].tt == TokenType::And {
                index - 1
            } else {
                index
            }
        });
    let boundary = statement
        .iter()
        .position(|token| token.tt == TokenType::Over)
        .into_iter()
        .chain(signal_start)
        .min()
        .unwrap_or(statement.len());
    let access_start = statement[clause_start..boundary]
        .iter()
        .position(|token| token.tt == TokenType::To)
        .map(|index| clause_start + index);
    let has_optional_access = access_start
        .is_some_and(|index| index + 2 == boundary && statement[index + 1].tt == TokenType::Access);

    if access_start.is_some() && !has_optional_access {
        let root = &statement[0];
        return Err(CompilationError::ParseError(
            "access rules cannot specify a service target; follow a `provide` declaration and omit `to access <service>`".into(),
            root.line,
            root.col,
        ));
    }

    let mut normalized_statement = statement.to_vec();
    let Some(service_class) = service_context else {
        let root = &statement[0];
        return Err(CompilationError::ParseError(
            "an access rule must immediately follow a service declaration".into(),
            root.line,
            root.col,
        ));
    };
    let root = &statement[0];
    let last = statement.last().expect("access rule has a final token");
    normalized_statement.splice(
        access_start.unwrap_or(boundary)..boundary,
        [
            Token::new(TokenType::To, root.line, root.col, 2),
            Token::new(TokenType::Access, root.line, root.col, 6),
            Token::new(
                TokenType::Literal(service_class.to_string()),
                last.line,
                last.col + last.size - 1,
                1,
            ),
        ],
    );

    let clause = if statement[0].tt == TokenType::Never {
        parse_never(&normalized_statement, statement_id, class_index, classes)?
    } else {
        parse_allow(&normalized_statement, statement_id, class_index, classes)?
    };

    Ok(clause)
}

fn parse_embedded_service(
    statement: &[Token],
    class_index: &HashMap<String, String>,
    classes: &HashMap<String, Class>,
) -> Result<EmbeddedService, CompilationError> {
    let start = &statement[0];
    let json_form = statement.len() == 5
        && statement[2].tt == TokenType::As
        && literal(&statement[3]).is_some_and(|value| value.eq_ignore_ascii_case("json"));
    let fields_form = statement.len() >= 4 && statement[2].tt == TokenType::With;
    if !json_form && !fields_form {
        return Err(CompilationError::ParseError(
            "expected `service <service-class> as json <JSON object>` or `service <service-class> with <field>:<value>`".into(),
            start.line,
            start.col,
        ));
    }
    let name = literal(&statement[1]).ok_or_else(|| {
        CompilationError::ParseError(
            "expected service class name".into(),
            statement[1].line,
            statement[1].col,
        )
    })?;
    let canonical = class_index.get(&name.to_lowercase()).ok_or_else(|| {
        CompilationError::ParseError(
            format!("unknown service class {name}"),
            statement[1].line,
            statement[1].col,
        )
    })?;
    let class = classes
        .get(canonical)
        .expect("indexed service class exists");
    if class.flavor != ClassFlavor::Service || class.is_builtin() {
        return Err(CompilationError::ParseError(
            format!("{name} must be a user-defined service class"),
            statement[1].line,
            statement[1].col,
        ));
    }
    let record = if json_form {
        let TokenType::Json(raw) = &statement[4].tt else {
            return Err(CompilationError::ParseError(
                "expected JSON object".into(),
                start.line,
                start.col,
            ));
        };
        let record: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
            CompilationError::ParseError(
                format!("invalid service JSON: {error}"),
                statement[4].line,
                statement[4].col,
            )
        })?;
        let Some(object) = record.as_object() else {
            return Err(CompilationError::ParseError(
                "service JSON must be an object".into(),
                start.line,
                start.col,
            ));
        };
        if object
            .get("service_class")
            .and_then(serde_json::Value::as_str)
            != Some(canonical.as_str())
        {
            return Err(CompilationError::ParseError(
                format!("service JSON service_class must match {canonical}"),
                start.line,
                start.col,
            ));
        }
        record
    } else {
        let mut object = serde_json::Map::new();
        object.insert(
            "service_class".into(),
            serde_json::Value::String(canonical.clone()),
        );
        let supported_fields = ["actor_cn", "endpoint", "summary", "status"];
        let mut field_count = 0;
        let mut expect_field = true;
        for token in &statement[3..] {
            match &token.tt {
                TokenType::Tuple((field, values)) => {
                    let field = field.to_ascii_lowercase();
                    if !expect_field {
                        return Err(CompilationError::ParseError(
                            "service fields must be separated by commas".into(),
                            token.line,
                            token.col,
                        ));
                    }
                    if !supported_fields.contains(&field.as_str()) {
                        return Err(CompilationError::ParseError(
                            format!("unsupported service field {field}"),
                            token.line,
                            token.col,
                        ));
                    }
                    if values.len() != 1 {
                        return Err(CompilationError::ParseError(
                            format!("service field {field} requires exactly one value"),
                            token.line,
                            token.col,
                        ));
                    }
                    if object.contains_key(&field) {
                        return Err(CompilationError::ParseError(
                            format!("duplicate service field {field}"),
                            token.line,
                            token.col,
                        ));
                    }
                    object.insert(field, serde_json::Value::String(values[0].clone()));
                    field_count += 1;
                    expect_field = false;
                }
                TokenType::Comma if !expect_field => expect_field = true,
                TokenType::Comma => {
                    return Err(CompilationError::ParseError(
                        "expected a service field before comma".into(),
                        token.line,
                        token.col,
                    ));
                }
                _ => {
                    return Err(CompilationError::ParseError(
                        "expected service field as key:value".into(),
                        token.line,
                        token.col,
                    ));
                }
            }
        }
        if field_count == 0 || expect_field {
            return Err(CompilationError::ParseError(
                "service with-form requires fields and cannot end with a comma".into(),
                start.line,
                start.col,
            ));
        }
        serde_json::Value::Object(object)
    };
    Ok(EmbeddedService {
        service_class: canonical.clone(),
        record,
        pos: start.into(),
    })
}

fn parse_service_definition(
    statement: &[Token],
    class_index: &HashMap<String, String>,
    classes: &HashMap<String, Class>,
) -> Result<ServiceDefinition, CompilationError> {
    let start = &statement[0];
    if statement.len() != 7
        || statement[2].tt != TokenType::At
        || statement[4].tt != TokenType::Over
    {
        return Err(CompilationError::ParseError(
            "expected `provide <service-class> at <dns-name> over <TCP|UDP> <port>`".to_string(),
            start.line,
            start.col,
        ));
    }
    let service_name = literal(&statement[1]).ok_or_else(|| {
        CompilationError::ParseError(
            "expected service class name".to_string(),
            statement[1].line,
            statement[1].col,
        )
    })?;
    let canonical_class = class_index
        .get(&service_name.to_lowercase())
        .ok_or_else(|| {
            CompilationError::ParseError(
                format!("unknown service class {service_name}"),
                statement[1].line,
                statement[1].col,
            )
        })?;
    let class = classes.get(canonical_class).ok_or_else(|| {
        CompilationError::BuildError(format!("class {canonical_class} missing from class table"))
    })?;
    if class.flavor != ClassFlavor::Service
        || (class.is_builtin() && class.name != crate::zpl::DEF_CLASS_VISA_SERVICE_NAME)
    {
        return Err(CompilationError::ParseError(
            format!("{} must be a user-defined service class", service_name),
            statement[1].line,
            statement[1].col,
        ));
    }

    let dns_name = literal(&statement[3])
        .ok_or_else(|| {
            CompilationError::ParseError(
                "expected DNS name".to_string(),
                statement[3].line,
                statement[3].col,
            )
        })?
        .to_ascii_lowercase();
    validate_dns_name(&dns_name, &statement[3])?;

    let protocol = literal(&statement[5])
        .ok_or_else(|| {
            CompilationError::ParseError(
                "expected TCP or UDP".to_string(),
                statement[5].line,
                statement[5].col,
            )
        })?
        .to_ascii_lowercase();
    if !matches!(protocol.as_str(), "tcp" | "udp") {
        return Err(CompilationError::ParseError(
            format!("unsupported service transport {protocol}; expected TCP or UDP"),
            statement[5].line,
            statement[5].col,
        ));
    }
    let port_text = literal(&statement[6]).ok_or_else(|| {
        CompilationError::ParseError(
            "expected service port".to_string(),
            statement[6].line,
            statement[6].col,
        )
    })?;
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            CompilationError::ParseError(
                format!("invalid service port {port_text}"),
                statement[6].line,
                statement[6].col,
            )
        })?;

    Ok(ServiceDefinition {
        service_class: canonical_class.clone(),
        dns_name,
        protocol,
        port,
        pos: start.into(),
    })
}

fn literal(token: &Token) -> Option<&str> {
    match &token.tt {
        TokenType::Literal(value) => Some(value),
        _ => None,
    }
}

fn validate_dns_name(name: &str, token: &Token) -> Result<(), CompilationError> {
    let labels: Vec<&str> = name.split('.').collect();
    let valid = name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(CompilationError::ParseError(
            format!("invalid DNS name {name}; use lowercase ASCII DNS labels"),
            token.line,
            token.col,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::lex::{Tokenization, tokenize_str};
    use crate::ptypes::ClassFlavor;
    use crate::zpl;

    // Existing parser unit cases focus on subject-clause behavior. Re-scope their
    // legacy fixture shorthand to synthetic services; strict syntax is tested below.
    fn parse(tokens: Vec<Token>, ctx: &CompilationCtx) -> Result<ParsingResult, CompilationError> {
        let mut statements = Vec::new();
        let mut statement = Vec::new();
        for token in tokens {
            let is_period = token.tt == TokenType::Period;
            statement.push(token);
            if is_period {
                statements.push(std::mem::take(&mut statement));
            }
        }
        if !statement.is_empty() {
            statements.push(statement);
        }

        let mut normalized = Vec::new();
        let mut line_shift = 0;
        let mut generated_services = 0;
        let mut generated_names = Vec::new();
        for mut statement in statements {
            let access = statement.windows(2).position(|tokens| {
                tokens[0].tt == TokenType::To && tokens[1].tt == TokenType::Access
            });
            let nested_statement = statement.iter().enumerate().any(|(index, token)| {
                index > 0
                    && matches!(
                        token.tt,
                        TokenType::Allow
                            | TokenType::Define
                            | TokenType::Never
                            | TokenType::Provide
                    )
                    && !(index == 1
                        && statement
                            .first()
                            .is_some_and(|first| first.tt == TokenType::Never)
                        && token.tt == TokenType::Allow)
            });
            if matches!(
                statement.first().map(|token| &token.tt),
                Some(TokenType::Allow | TokenType::Never)
            ) && let Some(access) = access
                && !nested_statement
            {
                let root_line = statement[0].line + line_shift;
                let service_name = format!("ParserFixtureService{generated_services}");
                let dns_name = format!("parser-fixture-{generated_services}.svc.zpr");
                generated_services += 1;
                generated_names.push(service_name.clone());
                let token = |tt, line, col, size| Token::new(tt, line, col, size);
                normalized.extend([
                    token(TokenType::Define, root_line, 1, 6),
                    token(
                        TokenType::Literal(service_name.clone()),
                        root_line,
                        8,
                        service_name.len(),
                    ),
                    token(TokenType::As, root_line, 1, 2),
                    token(TokenType::Literal("service".into()), root_line, 1, 7),
                    token(TokenType::Period, root_line, 1, 1),
                    token(TokenType::Provide, root_line + 1, 1, 7),
                    token(
                        TokenType::Literal(service_name),
                        root_line + 1,
                        9,
                        dns_name.len(),
                    ),
                    token(TokenType::At, root_line + 1, 1, 2),
                    token(
                        TokenType::Literal(dns_name.clone()),
                        root_line + 1,
                        1,
                        dns_name.len(),
                    ),
                    token(TokenType::Over, root_line + 1, 1, 4),
                    token(TokenType::Literal("TCP".into()), root_line + 1, 1, 3),
                    token(TokenType::Literal("80".into()), root_line + 1, 1, 2),
                    token(TokenType::Period, root_line + 1, 1, 1),
                ]);
                line_shift += 2;
                let clause_end = statement[access + 1..]
                    .iter()
                    .position(|token| {
                        matches!(
                            token.tt,
                            TokenType::Over | TokenType::Signal | TokenType::Period
                        )
                    })
                    .map(|offset| access + 1 + offset)
                    .unwrap_or(statement.len());
                statement.drain(access..clause_end);
            }
            for token in &mut statement {
                token.line += line_shift;
            }
            normalized.extend(statement);
        }
        let mut parsed = super::parse(normalized, ctx)?;
        parsed
            .policy
            .defines
            .retain(|class| !generated_names.contains(&class.name));
        Ok(parsed)
    }

    #[test]
    fn test_parse_define() {
        let valids = vec![
            "define employee as a user with an id.",
            "define employee as a user with an id.\ndefine marketing-emp as an employee with rule:marketing and tag full-time.",
            "define employee as a user with an ID-number, multiple roles and optional tags full-time, part-time, and intern.",
            "define employee as a user with an `ID number`, multiple roles and optional tags full-time, part-time, and intern and with color:purple, size:`extra:large`.",
            "define gateway as a service with an external-network-connection.",
            "define gateway as a service with an external-network-connection.\ndefine internet-gateway as a gateway with external-network-connection:public-internet.",
            "define peripheral as a user with function.\ndefine mouse AKA mice as a peripheral with function:pointing.",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tz: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tz.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_parse_service_definition() {
        let source = "define PayrollAPI as a service with data-class:confidential.\nprovide PayrollAPI at Payroll.Finance.svc.zpr over TCP 443.";
        let ctx = CompilationCtx::default();
        let tokens = tokenize_str(source, &ctx).expect("service definition should tokenize");
        let policy = parse(tokens.tokens, &ctx)
            .expect("service definition should parse")
            .policy;

        assert_eq!(policy.service_definitions.len(), 1);
        let definition = &policy.service_definitions[0];
        assert_eq!(definition.service_class, "PayrollAPI");
        assert_eq!(definition.dns_name, "payroll.finance.svc.zpr");
        assert_eq!(definition.protocol, "tcp");
        assert_eq!(definition.port, 443);
    }

    #[test]
    fn test_optional_to_access() {
        let ctx = CompilationCtx::default();
        for keyword in ["allow", "never allow"] {
            for suffix in [
                "",
                " over secure links",
                " and signal \"audit\" to PayrollAPI",
            ] {
                for wording in ["", " to access", " TO ACCESS"] {
                    let source = format!(
                        "define PayrollAPI as a service.\nprovide PayrollAPI at payroll.svc.zpr over TCP 443.\n{keyword} users{wording}{suffix}."
                    );
                    let tokens = tokenize_str(&source, &ctx).expect("rule should tokenize");
                    let policy = super::parse(tokens.tokens, &ctx)
                        .expect("optional access wording should parse")
                        .policy;
                    let clauses = if keyword == "allow" {
                        &policy.allows
                    } else {
                        &policy.nevers
                    };
                    assert_eq!(clauses.len(), 1);
                    assert_eq!(
                        clauses[0].get_server_service_clause().unwrap().class,
                        "PayrollAPI"
                    );
                    assert_eq!(clauses[0].link.is_some(), suffix.contains("over"));
                    assert_eq!(clauses[0].signal.is_some(), suffix.contains("signal"));
                }
            }
        }
    }

    #[test]
    fn test_explicit_service_target_is_rejected() {
        let source = "define PayrollAPI as a service.\nprovide PayrollAPI at payroll.svc.zpr over TCP 443.\nallow users to access PayrollAPI.";
        let ctx = CompilationCtx::default();
        let tokens = tokenize_str(source, &ctx).expect("explicit-target fixture should tokenize");
        let error = match super::parse(tokens.tokens, &ctx) {
            Ok(_) => panic!("explicit service target unexpectedly parsed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("access rules cannot specify a service target")
        );
    }

    #[test]
    fn test_embedded_service_json() {
        let source = "define PayrollRecords as a service with device.zpr.adapter.cn:payroll-records.\nservice PayrollRecords as json {\n  \"service_class\": \"PayrollRecords\",\n  \"endpoint\": \"zpr://payroll-records\",\n  \"details\": {\"path\": \"/v1.0\", \"items\": [1, 2]}\n}.\nallow users.";
        let ctx = CompilationCtx::default();
        let tokens = tokenize_str(source, &ctx).expect("embedded JSON should tokenize");
        let policy = parse(tokens.tokens, &ctx)
            .expect("embedded JSON should parse")
            .policy;
        assert_eq!(policy.embedded_services.len(), 1);
        assert_eq!(policy.embedded_services[0].service_class, "PayrollRecords");
        assert_eq!(policy.embedded_services[0].record["details"]["items"][1], 2);
        assert_eq!(policy.allows.len(), 1);
        assert_eq!(
            policy.allows[0]
                .get_server_service_clause()
                .expect("embedded service should scope the following policy")
                .class,
            "PayrollRecords"
        );
    }

    #[test]
    fn test_embedded_service_with_fields() {
        let source = "define PayrollRecords as a service with device.zpr.adapter.cn:payroll-records.\nservice PayrollRecords with actor_cn:payroll-records, endpoint:\"zpr://payroll-records\", summary:\"Payroll records\".\nallow users.";
        let ctx = CompilationCtx::default();
        let tokens = tokenize_str(source, &ctx).expect("service fields should tokenize");
        let policy = parse(tokens.tokens, &ctx)
            .expect("service fields should parse")
            .policy;
        assert_eq!(policy.embedded_services.len(), 1);
        let record = &policy.embedded_services[0].record;
        assert_eq!(record["service_class"], "PayrollRecords");
        assert_eq!(record["actor_cn"], "payroll-records");
        assert_eq!(record["endpoint"], "zpr://payroll-records");
        assert_eq!(record["summary"], "Payroll records");
        assert_eq!(policy.allows.len(), 1);
        assert_eq!(
            policy.allows[0]
                .get_server_service_clause()
                .expect("embedded service should scope the following policy")
                .class,
            "PayrollRecords"
        );
    }

    #[test]
    fn test_embedded_service_rejects_invalid_json_and_classes() {
        let cases = [
            (
                "service PayrollRecords as json {\"service_class\":\"PayrollRecords\",}.",
                "invalid service JSON",
            ),
            (
                "service PayrollRecords as json {\"service_class\":\"Other\"}.",
                "must match PayrollRecords",
            ),
            (
                "service PayrollRecords as json {\"service_class\":\"PayrollRecords\"}.",
                "more than one JSON definition",
            ),
            (
                "service PayrollRecords as json {\"service_class\":\"PayrollRecords\"",
                "unterminated service JSON object",
            ),
            (
                "service PayrollRecords with unknown:value.",
                "unsupported service field unknown",
            ),
        ];
        let ctx = CompilationCtx::default();
        for (statement, expected) in cases {
            let source = if expected == "more than one JSON definition" {
                format!("define PayrollRecords as a service.\n{statement}\n{statement}")
            } else {
                format!("define PayrollRecords as a service.\n{statement}")
            };
            let error =
                match tokenize_str(&source, &ctx).and_then(|tokens| parse(tokens.tokens, &ctx)) {
                    Ok(_) => panic!("unexpectedly accepted {source}"),
                    Err(error) => error,
                };
            assert!(
                error.to_string().contains(expected),
                "expected {expected}, got {error}"
            );
        }
    }

    #[test]
    fn test_service_definition_requires_service_class_and_valid_scope() {
        let invalid = [
            (
                "define payroll as a user with id.\nprovide payroll at payroll.svc.zpr over TCP 443.",
                "user-defined service class",
            ),
            (
                "define payroll as a service with id.\nprovide payroll at bad_name.svc.zpr over TCP 443.",
                "invalid DNS name",
            ),
            (
                "define payroll as a service with id.\nprovide payroll at payroll.svc.zpr over ICMP 443.",
                "expected TCP or UDP",
            ),
            (
                "define payroll as a service with id.\nprovide payroll at payroll.svc.zpr over TCP 0.",
                "invalid service port",
            ),
        ];
        let ctx = CompilationCtx::default();
        for (source, expected_error) in invalid {
            let tokens = tokenize_str(source, &ctx).expect("invalid declaration should tokenize");
            let error = match parse(tokens.tokens, &ctx) {
                Ok(_) => panic!("invalid declaration unexpectedly parsed: {source}"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected_error),
                "expected error containing {expected_error:?}, got {error}"
            );
        }
    }

    #[test]
    fn test_service_definition_rejects_duplicate_name_or_class() {
        let duplicate_class = "define payroll as a service with id.\nprovide payroll at payroll.svc.zpr over TCP 443.\nprovide payroll at payroll-alt.svc.zpr over TCP 443.";
        let duplicate_name = "define payroll as a service with id.\ndefine finance as a service with id.\nprovide payroll at shared.svc.zpr over TCP 443.\nprovide finance at shared.svc.zpr over TCP 443.";
        let ctx = CompilationCtx::default();
        for (source, expected_error) in [
            (duplicate_class, "declared more than once"),
            (duplicate_name, "declared more than once"),
        ] {
            let tokens =
                tokenize_str(source, &ctx).expect("duplicate declarations should tokenize");
            let error = match parse(tokens.tokens, &ctx) {
                Ok(_) => panic!("duplicate declaration unexpectedly parsed: {source}"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn test_short_policy() {
        let pp = r#"
define employee as a user with an ID-number, multiple roles and
optional tags full-time, part-time, and intern.

define marketing-emp as an employee with rule:marketing and tag full-time.

allow marketing-emps to access role:marketing services.
"#;
        let ctx = CompilationCtx::default();
        let tz: Result<Tokenization, CompilationError> = tokenize_str(pp, &ctx).or_else(|e| {
            panic!("failed to tokenize '{}': {:?}", pp, e);
        });
        let pol = match parse(tz.unwrap().tokens, &ctx) {
            Ok(pr) => pr.policy,
            Err(e) => {
                panic!("failed to parse '{}': {:?}", pp, e);
            }
        };
        assert_eq!(pol.defines.len(), 2);
        assert_eq!(pol.allows.len(), 1);

        let emp = match pol.defines[0].name.as_str() {
            "employee" => &pol.defines[0],
            "marketing-emp" => &pol.defines[1],
            _ => panic!("unexpected class name: {}", pol.defines[0].name),
        };
        assert_eq!(emp.name, "employee");
        assert_eq!(emp.flavor, ClassFlavor::User);
        assert_eq!(emp.with_attrs.len(), 5);
        for attr in &emp.with_attrs {
            match attr.zpl_key().as_str() {
                "user.ID-number" => {
                    assert_eq!(attr.is_multi_valued(), false);
                    assert_eq!(attr.is_tag(), false);
                    assert_eq!(attr.optional, false);
                }
                "user.roles" => {
                    assert_eq!(attr.is_multi_valued(), true);
                    assert_eq!(attr.is_tag(), false);
                    assert_eq!(attr.optional, false);
                }
                "user.zpr.tag.full-time" | "user.zpr.tag.part-time" | "user.zpr.tag.intern" => {
                    assert_eq!(attr.is_multi_valued(), false);
                    assert_eq!(attr.is_tag(), true);
                    assert_eq!(attr.optional, true);
                }
                _ => panic!("unexpected attribute name: {}", attr.zpl_key()),
            }
        }
    }

    #[test]
    fn test_base_allow() {
        let valids = vec!["allow color:green users to access services."];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let toks = tokens.unwrap().tokens;
            assert_eq!(7, toks.len());
            let _pol = match parse(toks, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_postifx_attr_prohibited() {
        let valids = vec![
            "allow devices with users with loc:italy to access services.",
            "allow devices with users to access services with color:green.",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let toks = tokens.unwrap().tokens;
            let _pol = match parse(toks, &ctx) {
                Ok(_) => panic!("should not have parsed postfix notation: {}", valid),
                Err(e) => {
                    assert!(
                        e.to_string().contains("postfix"),
                        "unexpected error: {:?}",
                        e
                    );
                }
            };
        }
    }

    #[test]
    fn test_omit_device() {
        let valids = vec![
            "allow color:red users to access services.",
            "allow managed users to access services.",
            "allow color:red users to access services.",
            "allow managed, color:red users to access services.",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_omit_user() {
        let valids = vec![
            "allow managed devices to access services.",
            "allow color:red devices to access services.",
            "allow managed, color:red devices to access services.",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_verbose_device() {
        let valids = vec![
            "allow managed, color:red users on color:green devices to access green services.",
            "allow color:red, managed users on color:green devices to access color:blue services.",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    // Statements must be terminated by a period followed by a newline
    // (end of input also qualifies). Blank lines are insignificant.
    #[test]
    fn test_use_periods() {
        let valids = vec![
            // A newline after the period is all that is required between statements.
            "Define Alien as a user with color:green.\nAllow Aliens to access services.",
            // Blank lines between, before, and after statements are fine.
            "\n\nDefine Alien as a user with color:green.\n\n\n\nAllow Aliens to access services.\n\n",
            // Even a blank line inside a multi-line statement is fine.
            "Allow users\n\nto access services.",
            // A comment-only line does not interrupt a multi-line statement...
            "Allow users\n# comment\nto access services.",
            // ...nor a statement boundary.
            "Define Alien as a user with color:green.\n# comment\nAllow Aliens to access services.",
            // A trailing comment may follow the terminating period.
            "Allow users to access services. # comment",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    // Violations of the ZRFC 15 statement layout rules.
    #[test]
    fn test_statement_delimiter_errors() {
        use std::mem::discriminant;

        // (input, expected error variant — fields are ignored, only the variant matters)
        let cases = [
            // Two statements sharing a line: the period must be followed by a newline.
            (
                "Define Alien as a user with color:green. Allow Aliens to access services.",
                CompilationError::MissingNewline(0, 0),
            ),
            // Any trailing token after the period, keyword or not, is rejected the same way.
            (
                "Allow Aliens to access services. foo",
                CompilationError::MissingNewline(0, 0),
            ),
            // Missing period: at end of input, and before the next statement keyword.
            (
                "Allow Aliens to access services",
                CompilationError::MissingStatementTerminator(0, 0),
            ),
            (
                "Define Alien as a user with color:green\nAllow Aliens to access services.",
                CompilationError::MissingStatementTerminator(0, 0),
            ),
            // An unterminated "never allow" must not swallow the next allow statement.
            (
                "never allow color:green users to access services\nallow color:red users to access services.",
                CompilationError::MissingStatementTerminator(0, 0),
            ),
            // A bare period with no statement before it.
            (".", CompilationError::ParseError(String::new(), 0, 0)),
        ];

        let ctx = CompilationCtx::default();
        for (input, expected) in cases {
            let tz = tokenize_str(input, &ctx).unwrap();
            let err = match parse(tz.tokens, &ctx) {
                Ok(_) => panic!("should not have parsed '{input}'"),
                Err(e) => e,
            };
            assert_eq!(
                discriminant(&err),
                discriminant(&expected),
                "wrong error for '{input}': {err:?}"
            );
        }
    }

    // Put periods in where they don't belong. Should fail.
    #[test]
    fn test_use_periods_in_error() {
        let invalids = vec![
            "Define Alien. as a user with color:green. Allow Aliens to. access services",
            "Define alien as a user. with color:green.",
        ];
        let ctx = CompilationCtx::default();
        for valid in invalids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(_policy) => {
                    panic!("should not have parsed '{}'", valid);
                }
                Err(_e) => (),
            };
        }
    }

    #[test]
    fn test_cannot_subclass_visa_service() {
        let invalids = vec!["Define MyVs as a VisaService with device.color:green."];
        let ctx = CompilationCtx::default();
        for valid in invalids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(_policy) => {
                    panic!("should not have parsed '{}'", valid);
                }
                Err(e) => {
                    assert!(
                        e.to_string().contains("is not extensible"),
                        "unexpected error: {:?}",
                        e
                    );
                }
            };
        }
    }

    // A custom class defined with "define" must be usable as the subject class
    // in an allow statement by its canonical name.  This exercises the class
    // registry lookup path in parse_allow.
    #[test]
    fn test_custom_class_in_allow() {
        let input = "define employee as a user with id.\nallow employees to access services.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.defines.len(), 1);
        assert_eq!(pr.policy.allows.len(), 1);

        // The user clause on the LHS must name the custom class, not the base "user".
        let allow = &pr.policy.allows[0];
        let user_clause = allow
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        assert_eq!(user_clause.class, "employee");
    }

    // The AKA name of a custom class must be accepted wherever the canonical
    // name is accepted in an allow statement and must resolve to the canonical name.
    #[test]
    fn test_aka_name_in_allow() {
        // "mice" is the AKA for "mouse"; the allow statement uses the AKA.
        let input =
            "define mouse AKA mice as a user with device-id.\nallow mice to access services.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 1);

        let allow = &pr.policy.allows[0];
        let user_clause = allow
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        // The AKA "mice" must resolve to the canonical class name "mouse".
        assert_eq!(user_clause.class, "mouse");
    }

    // The auto-plural must resolve in an allow statement even when the class
    // also has an explicit AKA.
    #[test]
    fn test_plural_in_allow_with_aka() {
        let input =
            "define mouse AKA mice as a user with device-id.\nallow mice to access services.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 1);

        let allow = &pr.policy.allows[0];
        let user_clause = allow
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        assert_eq!(user_clause.class, "mouse");
    }

    // resolve_class_flavors must iterate until all classes are resolved, even
    // when the inheritance chain is more than two levels deep.  This tests a
    // three-level chain: engineer → employee → worker → user (built-in).
    #[test]
    fn test_multi_level_inheritance() {
        let input = "\
            define worker as a user with id.\n\
            define employee as a worker with role.\n\
            define engineer as an employee with specialty.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.defines.len(), 3);

        // After multi-pass flavor resolution every class must end up as User.
        for class in &pr.policy.defines {
            assert_eq!(
                class.flavor,
                ClassFlavor::User,
                "class '{}' should have User flavor but got {:?}",
                class.name,
                class.flavor
            );
        }
    }

    // Defining the same class name twice in one policy must fail with a
    // Redefinition error, not silently overwrite the first definition.
    #[test]
    fn test_redefinition_error() {
        let input = "define employee as a user with id.\ndefine employee as a user with id.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: class defined twice"),
            Err(e) => assert!(
                matches!(e, CompilationError::Redefinition(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // Class names match case-insensitively. A miscased reference in an
    // allow statement resolves to the class (not a tag), and a define whose name
    // differs from an existing class only by case is a redefinition.
    #[test]
    fn test_class_name_case_insensitive() {
        let ctx = CompilationCtx::default();

        let input = "define employee as a user with id.\nallow EMPLOYEES to access services.";
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        let user_clause = pr.policy.allows[0]
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        assert_eq!(user_clause.class, "employee");
        // Since #144 a written user spec carries the injected `has
        // user.zpr.authority` marker, so `with` is no longer empty -- assert
        // instead that no TAG was created from the miscased class name.
        assert!(
            !user_clause.with.iter().any(|a| a.is_tag()),
            "'EMPLOYEES' must not be a tag"
        );
        assert!(
            user_clause
                .with
                .iter()
                .any(|a| a.zpl_key() == zpl::KATTR_USER_AUTHORITY),
            "subclass spec must carry the user authority marker"
        );

        let input = "define employee as a user with id.\ndefine Employee as a user with id.";
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: class redefined with different case"),
            Err(e) => assert!(
                matches!(e, CompilationError::Redefinition(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // A device subclass written on the LHS gets the device authority marker,
    // same as the builtin `devices` class (issue #144).
    #[test]
    fn test_device_subclass_gets_authority_marker() {
        let ctx = CompilationCtx::default();
        let input = "define laptop as a device with id.\nallow laptops to access services.";
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        let device_clause = pr.policy.allows[0]
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::Device)
            .expect("device clause missing from LHS");
        assert_eq!(device_clause.class, "laptop");
        assert!(
            device_clause
                .with
                .iter()
                .any(|a| a.zpl_key() == zpl::KATTR_DEVICE_AUTHORITY),
            "device subclass spec must carry the device authority marker"
        );
        // The synthesized user clause must NOT get a marker.
        let user_clause = pr.policy.allows[0]
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        assert!(
            user_clause.with.is_empty(),
            "synthesized user clause must stay empty: {:?}",
            user_clause.with
        );
    }

    // An AKA colliding with an existing name/AKA must be a Redefinition error,
    #[test]
    fn test_aka_collision_error() {
        let input = "define bad AKA Users as device.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: AKA collides with built-in 'users'"),
            Err(e) => assert!(
                matches!(e, CompilationError::Redefinition(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // A class name colliding with another class's auto-plural must be a
    // Redefinition error, not a silent overwrite of the index entry.
    #[test]
    fn test_plural_collision_error() {
        let input = "define box as a user with id.\ndefine boxes as a user with id.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: 'boxes' collides with plural of 'box'"),
            Err(e) => assert!(
                matches!(e, CompilationError::Redefinition(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // An explicit AKA that happens to equal the class's own auto-plural must
    // NOT be treated as a collision with itself.
    #[test]
    fn test_aka_equal_to_own_plural_ok() {
        let input = "define box AKA boxes as a user with id.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("AKA matching own plural should parse");
        assert_eq!(pr.policy.defines.len(), 1);
    }

    // A literal token that appears before any statement keyword (allow/define/never)
    // has no valid enclosing statement and must be rejected immediately.
    #[test]
    fn test_token_before_keyword_fails() {
        let input = "foo allow users to access services";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: literal before any keyword"),
            Err(e) => assert!(
                matches!(e, CompilationError::ParseError(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // A "never" statement not followed by "allow" must produce a NeverStmtParseError
    // at the top-level parse stage (the error propagates up from parse_never).
    #[test]
    fn test_never_without_allow_at_parser_level() {
        let input = "never users to access services.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: never without allow"),
            Err(e) => assert!(
                matches!(e, CompilationError::NeverStmtParseError(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    #[test]
    fn test_base_never() {
        let valids = vec!["never allow color:green users to access services."];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let toks = tokens.unwrap().tokens;
            assert_eq!(8, toks.len());
            let pol = match parse(toks, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
            assert_eq!(pol.policy.nevers.len(), 1);
            assert_eq!(pol.policy.allows.len(), 0);
        }
    }

    // DEFINE statements are collected in a first pass before any ALLOW or NEVER
    // statements are processed, so a class reference in an allow that appears
    // before its define in the source file must still resolve correctly.
    #[test]
    fn test_forward_reference_in_allow() {
        let input = "allow employees to access services.\ndefine employee as a user with id.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("forward reference should resolve");
        assert_eq!(pr.policy.allows.len(), 1);
        assert_eq!(pr.policy.defines.len(), 1);
    }

    #[test]
    fn test_provided_service_scopes_target_free_access_rules() {
        let input = "provide payroll at payroll.finance.svc.zpr over TCP 443.\n\
            allow finance users.\n\
            never allow contractor users.\n\
            define payroll as a service with device.zpr.adapter.cn:payroll.";
        let ctx = CompilationCtx::default();
        let tokens = tokenize_str(input, &ctx).unwrap();
        let parsed = parse(tokens.tokens, &ctx).expect("scoped rules should parse");

        assert_eq!(parsed.policy.service_definitions.len(), 1);
        assert_eq!(parsed.policy.allows.len(), 1);
        assert_eq!(parsed.policy.nevers.len(), 1);
        assert_eq!(
            parsed.policy.allows[0]
                .get_server_service_clause()
                .expect("implicit allow target should be present")
                .class,
            "payroll"
        );
        assert_eq!(
            parsed.policy.nevers[0]
                .get_server_service_clause()
                .expect("implicit deny target should be present")
                .class,
            "payroll"
        );
    }

    #[test]
    fn test_service_scoped_rules_must_immediately_follow_provide() {
        let input = "define payroll as a service with device.zpr.adapter.cn:payroll.\n\
            provide payroll at payroll.finance.svc.zpr over TCP 443.\n\
            define employee as a user with id.\n\
            allow employees.";
        let ctx = CompilationCtx::default();
        let tokens = tokenize_str(input, &ctx).unwrap();
        let error = match parse(tokens.tokens, &ctx) {
            Ok(_) => panic!("intervening define should close service scope"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("immediately follow a service declaration")
        );
    }

    #[test]
    fn test_explicit_service_targets_are_rejected() {
        let inputs = [
            "define payroll as a service with device.zpr.adapter.cn:payroll.\n\
                provide payroll at payroll.finance.svc.zpr over TCP 443.\n\
                allow users to access payroll.",
            "allow users to access services.",
        ];
        let ctx = CompilationCtx::default();
        for input in inputs {
            let tokens = tokenize_str(input, &ctx).unwrap();
            let error = match super::parse(tokens.tokens, &ctx) {
                Ok(_) => panic!("explicit service target should be rejected: {input}"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("cannot specify a service target")
            );
        }
    }

    // A signal clause must survive the full parse() pipeline intact and be
    // accessible on the resulting AllowClause with the correct message and target.
    #[test]
    fn test_signal_clause_through_full_parse() {
        let input = r#"allow users to access services and signal "hello" to service."#;
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 1);

        let signal = pr.policy.allows[0]
            .signal
            .as_ref()
            .expect("signal clause should be present on the allow");
        assert_eq!(signal.message, "hello");
        assert_eq!(signal.service_class_name, "service");
    }

    // A policy containing multiple allows and a never must produce the correct
    // counts in each respective vector of the Policy struct.
    #[test]
    fn test_multi_statement_counts() {
        let input = "\
            allow users to access services.\n\
            allow color:green users to access services.\n\
            never allow color:red users to access services.";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 2, "expected 2 allow clauses");
        assert_eq!(pr.policy.nevers.len(), 1, "expected 1 never clause");
    }
}
