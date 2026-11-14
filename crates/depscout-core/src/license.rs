//! SPDX license expressions, enough to check a license policy.
//!
//! Supports `OR`, `AND`, `WITH`, parentheses, and the legacy `/` separator
//! (`MIT/Apache-2.0`, read as `OR`). Identifiers are compared without case.

/// A parsed license expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// One license, with an optional exception (`Apache-2.0 WITH LLVM-exception`).
    License {
        /// License identifier.
        id: String,
        /// Exception identifier after `WITH`.
        exception: Option<String>,
    },
    /// Any of the alternatives may be chosen.
    Or(Vec<Expression>),
    /// All of the parts apply.
    And(Vec<Expression>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Id(String),
    Or,
    And,
    With,
    Open,
    Close,
}

fn tokenize(text: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if word.is_empty() {
            return;
        }
        tokens.push(match word.to_ascii_uppercase().as_str() {
            "OR" => Token::Or,
            "AND" => Token::And,
            "WITH" => Token::With,
            _ => Token::Id(word.clone()),
        });
        word.clear();
    };
    for character in text.chars() {
        match character {
            '(' | ')' | '/' => {
                flush(&mut word, &mut tokens);
                tokens.push(match character {
                    '(' => Token::Open,
                    ')' => Token::Close,
                    _ => Token::Or,
                });
            }
            c if c.is_whitespace() => flush(&mut word, &mut tokens),
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | ':') => word.push(c),
            other => return Err(format!("unexpected character `{other}`")),
        }
    }
    flush(&mut word, &mut tokens);
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += 1;
        token
    }

    fn or(&mut self) -> Result<Expression, String> {
        let mut parts = vec![self.and()?];
        while self.peek() == Some(&Token::Or) {
            self.position += 1;
            parts.push(self.and()?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expression::Or(parts)
        })
    }

    fn and(&mut self) -> Result<Expression, String> {
        let mut parts = vec![self.with()?];
        while self.peek() == Some(&Token::And) {
            self.position += 1;
            parts.push(self.with()?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expression::And(parts)
        })
    }

    fn with(&mut self) -> Result<Expression, String> {
        let atom = self.atom()?;
        if self.peek() != Some(&Token::With) {
            return Ok(atom);
        }
        self.position += 1;
        match (atom, self.next()) {
            (
                Expression::License {
                    id,
                    exception: None,
                },
                Some(Token::Id(exception)),
            ) => Ok(Expression::License {
                id,
                exception: Some(exception),
            }),
            _ => Err("`WITH` must join a license and an exception".to_owned()),
        }
    }

    fn atom(&mut self) -> Result<Expression, String> {
        match self.next() {
            Some(Token::Id(id)) => Ok(Expression::License {
                id,
                exception: None,
            }),
            Some(Token::Open) => {
                let inner = self.or()?;
                match self.next() {
                    Some(Token::Close) => Ok(inner),
                    _ => Err("missing `)`".to_owned()),
                }
            }
            Some(other) => Err(format!("unexpected {other:?}")),
            None => Err("unexpected end of expression".to_owned()),
        }
    }
}

/// Parses an SPDX license expression.
///
/// # Errors
///
/// Returns a description of the first syntax error.
pub fn parse(text: &str) -> Result<Expression, String> {
    let mut parser = Parser {
        tokens: tokenize(text)?,
        position: 0,
    };
    let expression = parser.or()?;
    if parser.position < parser.tokens.len() {
        return Err("unexpected text after the expression".to_owned());
    }
    Ok(expression)
}

impl Expression {
    /// Whether some choice of alternatives uses only acceptable licenses.
    pub fn is_satisfied_by(&self, acceptable: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Self::License { id, .. } => acceptable(id),
            Self::Or(parts) => parts.iter().any(|part| part.is_satisfied_by(acceptable)),
            Self::And(parts) => parts.iter().all(|part| part.is_satisfied_by(acceptable)),
        }
    }
}

/// Checks `expression` against an allow list (empty: every license that is
/// not denied) and a deny list. Comparison ignores case; an exception
/// (`WITH ...`) never makes a license unacceptable.
///
/// # Errors
///
/// Returns the parse error of an invalid expression.
pub fn is_allowed(expression: &str, allow: &[String], deny: &[String]) -> Result<bool, String> {
    let parsed = parse(expression)?;
    let listed =
        |list: &[String], id: &str| list.iter().any(|entry| entry.eq_ignore_ascii_case(id));
    Ok(parsed
        .is_satisfied_by(&|id: &str| !listed(deny, id) && (allow.is_empty() || listed(allow, id))))
}

#[cfg(test)]
mod tests {
    use super::{Expression, is_allowed, parse};

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn parses_precedence_parentheses_exceptions_and_legacy_slashes() {
        assert_eq!(
            parse("MIT OR Apache-2.0 AND BSD-3-Clause").expect("valid"),
            Expression::Or(vec![
                Expression::License {
                    id: "MIT".to_owned(),
                    exception: None
                },
                Expression::And(vec![
                    Expression::License {
                        id: "Apache-2.0".to_owned(),
                        exception: None
                    },
                    Expression::License {
                        id: "BSD-3-Clause".to_owned(),
                        exception: None
                    },
                ]),
            ])
        );
        assert!(matches!(
            parse("Apache-2.0 WITH LLVM-exception").expect("valid"),
            Expression::License {
                exception: Some(_),
                ..
            }
        ));
        assert!(matches!(
            parse("MIT/Apache-2.0").expect("valid"),
            Expression::Or(_)
        ));
        assert!(parse("(MIT OR Apache-2.0) AND Unicode-3.0").is_ok());
        assert!(parse("MIT OR").is_err());
        assert!(parse("(MIT").is_err());
        assert!(parse("MIT; rm").is_err());
    }

    #[test]
    fn checks_allow_and_deny_lists() {
        let allow = list(&["MIT", "Apache-2.0", "Unicode-3.0"]);
        assert_eq!(is_allowed("MIT OR GPL-3.0", &allow, &[]), Ok(true));
        assert_eq!(is_allowed("GPL-3.0", &allow, &[]), Ok(false));
        assert_eq!(
            is_allowed("(MIT OR Apache-2.0) AND Unicode-3.0", &allow, &[]),
            Ok(true)
        );
        assert_eq!(is_allowed("MIT AND BSD-3-Clause", &allow, &[]), Ok(false));
        assert_eq!(is_allowed("mit/apache-2.0", &allow, &[]), Ok(true));
        assert_eq!(
            is_allowed("Apache-2.0 WITH LLVM-exception", &allow, &[]),
            Ok(true)
        );

        let deny = list(&["GPL-3.0"]);
        assert_eq!(is_allowed("GPL-3.0", &[], &deny), Ok(false));
        assert_eq!(is_allowed("GPL-3.0 OR MIT", &[], &deny), Ok(true));
        assert_eq!(is_allowed("BSD-3-Clause", &[], &deny), Ok(true));
    }
}
