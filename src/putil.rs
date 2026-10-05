use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use pluralizer::pluralize as pluralize_word;

// Given the next token in the list, we error out if that token is not of the expected type.
pub fn require_tt(
    parent_tok: &Token,
    next_tok: Option<&Token>,
    expect: &str,
    statement_type: &str,
    expect_tt: TokenType,
) -> Result<Token, CompilationError> {
    match next_tok {
        Some(tok) => {
            if tok.tt == expect_tt {
                Ok(tok.clone())
            } else {
                Err(CompilationError::ParseError(
                    format!("expected {expect}, found {:?}", tok.tt),
                    tok.line,
                    tok.col,
                ))
            }
        }
        None => Err(CompilationError::ParseError(
            format!("malformed {} (expected {})", statement_type, expect),
            parent_tok.line,
            parent_tok.col,
        )),
    }
}

// Expect the next token in the list to be a literal, and if so we return a copy of the value.
pub fn return_literal(
    parent_tok: &Token,
    next_tok: Option<&Token>,
    expect_desc: &str,
    statement_type: &str,
) -> Result<String, CompilationError> {
    let value = match next_tok {
        Some(tok) => match &tok.tt {
            TokenType::Literal(s) => s,
            _ => {
                return Err(CompilationError::ParseError(
                    format!("expected {} to follow {}", expect_desc, statement_type),
                    tok.line,
                    tok.col,
                ));
            }
        },
        None => {
            return Err(CompilationError::ParseError(
                format!("malformed {}", statement_type),
                parent_tok.line,
                parent_tok.col,
            ));
        }
    };
    Ok(value.clone())
}

pub fn pluralize(s: &str) -> String {
    pluralize_word(s, 2, false)
}

#[test]
fn test_pluralize() {
    assert_eq!(pluralize("mobile-phone"), "mobile-phones");
    assert_eq!(pluralize("box"), "boxes");
    assert_eq!(pluralize("bus"), "buses");
    assert_eq!(pluralize("match"), "matches");
    assert_eq!(pluralize("dish"), "dishes");
    assert_eq!(pluralize("potato"), "potatoes");
    assert_eq!(pluralize("radio"), "radios");
    assert_eq!(pluralize("VisaService"), "VisaServices");
    assert_eq!(pluralize("mouse"), "mice");
    assert_eq!(pluralize("Mouse"), "Mice");
    assert_eq!(pluralize("person"), "people");
    assert_eq!(pluralize("BOX"), "BOXES");
    assert_eq!(pluralize("POTATO"), "POTATOES");
    assert_eq!(pluralize("o"), "os");
    assert_eq!(pluralize(""), "");
}
