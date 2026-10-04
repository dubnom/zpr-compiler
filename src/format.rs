/// Apply the currently supported ZPL layout rules without changing statement text.
pub fn format_zpl(source: &str) -> String {
    let mut formatted = String::with_capacity(source.len());
    let mut previous_line_is_blank = true;
    let mut is_first_line = true;
    let mut permission_block_is_open = false;
    let mut previous_statement_was_define = false;
    let mut service_block_is_open = false;
    let mut pending_lines = Vec::new();

    for line in source.trim_start().split_inclusive('\n') {
        let content = line
            .strip_suffix('\n')
            .unwrap_or(line)
            .strip_suffix('\r')
            .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));
        if content.trim().is_empty()
            || content.trim_start().starts_with('#')
            || content.trim_start().starts_with("//")
        {
            pending_lines.push(line);
            continue;
        }
        let is_define = is_statement_start(content, &["define"]);
        let is_service_declaration = is_statement_start(content, &["provide", "service"]);
        let ends_permission_block = is_statement_start(content, &["define", "provide", "service"]);
        let is_policy_statement = is_statement_start(content, &["allow", "deny", "never"]);
        let remove_blank_lines = (is_define && previous_statement_was_define)
            || (is_policy_statement && service_block_is_open);
        for pending_line in pending_lines.drain(..) {
            if pending_line.trim().is_empty() && (remove_blank_lines || previous_line_is_blank) {
                continue;
            }
            formatted.push_str(pending_line);
            previous_line_is_blank = pending_line.trim().is_empty();
            is_first_line = false;
        }

        if !is_first_line
            && !previous_line_is_blank
            && (is_service_declaration || (permission_block_is_open && ends_permission_block))
        {
            if line.ends_with("\r\n") || formatted.ends_with("\r\n") {
                formatted.push_str("\r\n");
            } else {
                formatted.push('\n');
            }
        }

        if ends_permission_block {
            permission_block_is_open = false;
            previous_statement_was_define = is_define;
            service_block_is_open = is_service_declaration;
        }
        if is_policy_statement {
            formatted.push_str("  ");
            formatted.push_str(line.trim_start());
            permission_block_is_open = true;
            previous_statement_was_define = false;
            service_block_is_open = true;
        } else {
            formatted.push_str(line);
        }
        previous_line_is_blank = content.trim().is_empty();
        is_first_line = false;
    }
    for pending_line in pending_lines {
        if pending_line.trim().is_empty() && previous_line_is_blank {
            continue;
        }
        formatted.push_str(pending_line);
        previous_line_is_blank = pending_line.trim().is_empty();
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
    fn separates_permission_blocks_from_following_definitions_and_services() {
        let source = "provide Api at api.example over TCP 443.\nallow staff.\ndeny guests.\ndefine team as user.\nservice Other as json {}\n";

        assert_eq!(
            format_zpl(source),
            "provide Api at api.example over TCP 443.\n  allow staff.\n  deny guests.\n\ndefine team as user.\n\nservice Other as json {}\n"
        );
    }

    #[test]
    fn keeps_existing_single_separator_after_permission_blocks() {
        let source =
            "provide Api at api.example over TCP 443.\n  allow staff.\n\ndefine team as user.\n";

        assert_eq!(
            format_zpl(source),
            "provide Api at api.example over TCP 443.\n  allow staff.\n\ndefine team as user.\n"
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

    #[test]
    fn removes_leading_whitespace_and_blank_lines_between_definitions() {
        let source = " \n\t\n  define staff as user.\n\n# Members\n\ndefine team as user.\n";
        let expected = "define staff as user.\n# Members\ndefine team as user.\n";
        assert_eq!(format_zpl(source), expected);
        assert_eq!(format_zpl(expected), expected);
        assert_eq!(format_zpl(" \r\n\t\n"), "");
    }

    #[test]
    fn removes_blank_lines_inside_service_permission_groups() {
        let source = "\r\nprovide Api at api.example over TCP 443.\r\n\r\n# Callers\r\n\r\nallow staff.\r\n\r\ndeny guests.\r\n\r\nnever allow interns.\r\nservice Other as json {}.\r\n\r\nallow team.\r\n";
        let expected = "provide Api at api.example over TCP 443.\r\n# Callers\r\n  allow staff.\r\n  deny guests.\r\n  never allow interns.\r\n\r\nservice Other as json {}.\r\n  allow team.\r\n";
        assert_eq!(format_zpl(source), expected);
        assert_eq!(format_zpl(expected), expected);
    }

    #[test]
    fn preserves_blank_lines_inside_multiline_statements() {
        let source = "define staff as user\n\n  with department:finance.\n\ndefine team as user.\n";
        assert_eq!(
            format_zpl(source),
            "define staff as user\n\n  with department:finance.\ndefine team as user.\n"
        );
    }

    #[test]
    fn condenses_blank_line_runs_around_comments_and_at_end_of_file() {
        let source = "define staff as user.\n\n\n# Services\n\n\nprovide Api at api.example over TCP 443.\n\nallow staff.\n\n\nprovide Other at other.example over TCP 80.\nallow staff.\n\n\n";
        let expected = "define staff as user.\n\n# Services\n\nprovide Api at api.example over TCP 443.\n  allow staff.\n\nprovide Other at other.example over TCP 80.\n  allow staff.\n\n";
        assert_eq!(format_zpl(source), expected);
        assert_eq!(format_zpl(expected), expected);
    }

    #[test]
    fn condenses_whitespace_only_blank_lines_with_crlf() {
        let source = "# Heading\r\n \r\n\t\r\n\r\ndefine staff as user\r\n\r\n\r\n  with department:finance.\r\n\r\n\r\n";
        let expected =
            "# Heading\r\n \r\ndefine staff as user\r\n\r\n  with department:finance.\r\n\r\n";
        assert_eq!(format_zpl(source), expected);
        assert_eq!(format_zpl(expected), expected);
    }
}
