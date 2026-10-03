/// Apply the currently supported ZPL layout rules without changing statement text.
pub fn format_zpl(source: &str) -> String {
    let mut formatted = String::with_capacity(source.len());
    let mut previous_line_is_blank = true;
    let mut is_first_line = true;

    for line in source.split_inclusive('\n') {
        let content = line
            .strip_suffix('\n')
            .unwrap_or(line)
            .strip_suffix('\r')
            .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));
        let is_service_declaration = is_statement_start(content, &["provide", "service"]);
        let is_policy_statement = is_statement_start(content, &["allow", "deny", "never"]);

        if !is_first_line && is_service_declaration && !previous_line_is_blank {
            if line.ends_with("\r\n") || formatted.ends_with("\r\n") {
                formatted.push_str("\r\n");
            } else {
                formatted.push('\n');
            }
        }

        if is_policy_statement {
            formatted.push_str("  ");
            formatted.push_str(line.trim_start());
        } else {
            formatted.push_str(line);
        }
        previous_line_is_blank = content.trim().is_empty();
        is_first_line = false;
    }

    formatted
}

fn starts_with_keyword(line: &str, keyword: &str) -> bool {
    let line = line.trim_start();
    line.get(..keyword.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(keyword))
        && line[keyword.len()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
}

fn is_statement_start(line: &str, keywords: &[&str]) -> bool {
    keywords
        .iter()
        .any(|keyword| starts_with_keyword(line, keyword))
}

#[cfg(test)]
mod tests {
    use super::format_zpl;

    #[test]
    fn inserts_blank_lines_before_service_declarations() {
        let source = "define staff as user.\nprovide Api at api.example over TCP 443.\nservice Api as json {}\n";

        assert_eq!(
            format_zpl(source),
            "define staff as user.\n\nprovide Api at api.example over TCP 443.\n\nservice Api as json {}\n"
        );
        assert_eq!(
            format_zpl(
                "define staff as user.\n\nprovide Api at api.example over TCP 443.\n\nservice Api as json {}\n"
            ),
            "define staff as user.\n\nprovide Api at api.example over TCP 443.\n\nservice Api as json {}\n"
        );
    }

    #[test]
    fn indents_only_permission_lines_and_preserves_other_lines() {
        let source = "# policy\ndefine team as user.\nallow staff\n  on managed devices.\ndeny guests.\nnever allow guests.\nservice Api as json {}\n";

        assert_eq!(
            format_zpl(source),
            "# policy\ndefine team as user.\n  allow staff\n  on managed devices.\n  deny guests.\n  never allow guests.\n\nservice Api as json {}\n"
        );
    }

    #[test]
    fn does_not_add_a_blank_line_before_a_first_line_service_or_duplicate_one() {
        let source = "provide Api at api.example over TCP 443.\n\nservice Api as json {}\n";

        assert_eq!(
            format_zpl(source),
            "provide Api at api.example over TCP 443.\n\nservice Api as json {}\n"
        );
    }

    #[test]
    fn preserves_crlf_line_endings() {
        let source = "define staff as user.\r\nprovide Api at api.example over TCP 443.\r\n";

        assert_eq!(
            format_zpl(source),
            "define staff as user.\r\n\r\nprovide Api at api.example over TCP 443.\r\n"
        );
    }
}
