//! SQRT parser: converts source text → pest pairs → typed AST.

use pest::Parser;
use pest_derive::Parser;

use crate::ast::*;
use crate::error::SqrtParseError;

#[derive(Parser)]
#[grammar = "sqrt.pest"]
struct SqrtPestParser;

/// Parse SQRT source code into a typed AST.
pub fn parse(input: &str) -> Result<SqrtProgram, SqrtParseError> {
    let pairs = SqrtPestParser::parse(Rule::program, input).map_err(|e| {
        SqrtParseError::from_pest_error(input, e)
    })?;

    let program_pair = pairs.into_iter().next().unwrap();
    parse_program(program_pair)
}

/// Validate SQRT syntax without returning an AST.
pub fn validate(input: &str) -> bool {
    parse(input).is_ok()
}

// ============================================================
// Top-Level
// ============================================================

fn parse_program(pair: pest::iterators::Pair<Rule>) -> Result<SqrtProgram, SqrtParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::program);
    let mut declarations = Vec::new();
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::declaration => {
                declarations.push(parse_declaration(inner)?);
            }
            Rule::EOI => {}
            _ => {}
        }
    }
    Ok(SqrtProgram { declarations })
}

fn parse_declaration(pair: pest::iterators::Pair<Rule>) -> Result<Declaration, SqrtParseError> {
    let span = pair_to_span(&pair);
    let mut doc_comment = None;
    let mut kind = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::doc_comments => {
                doc_comment = parse_doc_comments(inner);
            }
            Rule::let_decl => {
                kind = Some(DeclarationKind::Let(parse_let_decl(inner)?));
            }
            Rule::tool_decl => {
                kind = Some(DeclarationKind::Tool(parse_tool_decl(inner)?));
            }
            Rule::tool_shorthand => {
                kind = Some(DeclarationKind::ToolShorthand(parse_tool_shorthand(inner)?));
            }
            _ => {}
        }
    }

    Ok(Declaration {
        doc_comment,
        kind: kind.ok_or_else(|| SqrtParseError::internal("Empty declaration"))?,
        span: Some(span),
    })
}

fn parse_doc_comments(pair: pest::iterators::Pair<Rule>) -> Option<String> {
    let comments: Vec<&str> = pair
        .into_inner()
        .filter(|p| p.as_rule() == Rule::DOC_COMMENT)
        .map(|p| {
            let text = p.as_str();
            // Strip leading "///" and optional single space
            text.strip_prefix("///")
                .map(|s| s.strip_prefix(' ').unwrap_or(s))
                .unwrap_or(text)
        })
        .collect();
    if comments.is_empty() {
        None
    } else {
        Some(comments.join("\n"))
    }
}

// ============================================================
// Let Declarations
// ============================================================

fn parse_let_decl(pair: pest::iterators::Pair<Rule>) -> Result<LetDecl, SqrtParseError> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let expr_pair = inner.next().unwrap();
    let value = parse_expression(expr_pair)?;
    Ok(LetDecl { name, value })
}

fn parse_expression(pair: pest::iterators::Pair<Rule>) -> Result<Expression, SqrtParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::expression);
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::predicate | Rule::predicate_and | Rule::predicate_not | Rule::predicate_atom => {
            Ok(Expression::Predicate(parse_predicate(inner)?))
        }
        Rule::set_expression | Rule::set_minus | Rule::set_intersect | Rule::set_union
        | Rule::set_element_op | Rule::set_atom => {
            Ok(Expression::SetExpr(parse_set_expression(inner)?))
        }
        Rule::type_domain => Ok(Expression::TypeDomain(parse_type_domain(inner)?)),
        Rule::comparison | Rule::value_comparison | Rule::set_comparison => {
            Ok(Expression::Predicate(Predicate::Comparison(
                parse_comparison(inner)?,
            )))
        }
        other => Err(SqrtParseError::internal(&format!(
            "Unexpected rule in expression: {other:?}"
        ))),
    }
}

// ============================================================
// Tool Declarations
// ============================================================

fn parse_tool_decl(pair: pest::iterators::Pair<Rule>) -> Result<ToolDecl, SqrtParseError> {
    let mut id = None;
    let mut priority = None;
    let mut checks = Vec::new();
    let mut result_block = None;
    let mut session_before = None;
    let mut session_after = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::tool_id => {
                id = Some(parse_tool_id(inner));
            }
            Rule::tool_member => {
                let mut doc_comment = None;
                for member_inner in inner.into_inner() {
                    match member_inner.as_rule() {
                        Rule::doc_comments => {
                            doc_comment = parse_doc_comments(member_inner);
                        }
                        Rule::priority_decl => {
                            let int_pair = member_inner.into_inner().next().unwrap();
                            priority = Some(int_pair.as_str().parse::<i64>().unwrap());
                        }
                        Rule::check_rule => {
                            let mut rule = parse_check_rule(member_inner)?;
                            rule.doc_comment = doc_comment.take();
                            checks.push(rule);
                        }
                        Rule::result_block => {
                            result_block = Some(parse_result_block(member_inner)?);
                        }
                        Rule::session_block => {
                            let (timing, stmts) = parse_session_block(member_inner)?;
                            match timing {
                                SessionTiming::Before => session_before = Some(stmts),
                                SessionTiming::After => session_after = Some(stmts),
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(ToolDecl {
        id: id.ok_or_else(|| SqrtParseError::internal("Tool declaration missing ID"))?,
        priority,
        checks,
        result_block,
        session_before,
        session_after,
    })
}

fn parse_tool_id(pair: pest::iterators::Pair<Rule>) -> ToolId {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::REGEX_STRING => ToolId::Regex(extract_regex_string_content(inner.as_str())),
        Rule::STRING => ToolId::Exact(extract_string_content(inner.as_str())),
        _ => unreachable!("tool_id must be STRING or REGEX_STRING"),
    }
}

// ============================================================
// Tool Shorthand
// ============================================================

fn parse_tool_shorthand(
    pair: pest::iterators::Pair<Rule>,
) -> Result<ToolShorthandDecl, SqrtParseError> {
    let mut id = None;
    let mut priority = None;
    let mut target = UpdateTarget::Result; // default
    let mut update = None;
    let mut condition = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::tool_id => {
                id = Some(parse_tool_id(inner));
            }
            Rule::shorthand_priority => {
                let int_pair = inner.into_inner().next().unwrap();
                priority = Some(int_pair.as_str().parse::<i64>().unwrap());
            }
            Rule::shorthand_body => {
                for body_inner in inner.into_inner() {
                    match body_inner.as_rule() {
                        Rule::shorthand_target => {
                            target = parse_shorthand_target(body_inner);
                        }
                        Rule::shorthand_update => {
                            update = Some(parse_shorthand_update(body_inner)?);
                        }
                        Rule::shorthand_condition => {
                            let pred_pair = body_inner.into_inner().next().unwrap();
                            condition = Some(parse_predicate(pred_pair)?);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(ToolShorthandDecl {
        id: id.ok_or_else(|| SqrtParseError::internal("Shorthand missing tool ID"))?,
        priority,
        target,
        update: update.ok_or_else(|| SqrtParseError::internal("Shorthand missing update"))?,
        condition,
    })
}

fn parse_shorthand_target(pair: pest::iterators::Pair<Rule>) -> UpdateTarget {
    let text = pair.as_str().trim();
    if text.starts_with("session") && text.contains("before") {
        UpdateTarget::SessionBefore
    } else if text.starts_with("session") && text.contains("after") {
        UpdateTarget::SessionAfter
    } else if text.starts_with("session") {
        // "session" alone defaults to session after
        UpdateTarget::SessionAfter
    } else {
        UpdateTarget::Result
    }
}

fn parse_shorthand_update(
    pair: pest::iterators::Pair<Rule>,
) -> Result<MetadataUpdate, SqrtParseError> {
    let mut field = None;
    let mut op = None;
    let mut value = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::META_FIELD => {
                field = Some(parse_meta_field(inner.as_str()));
            }
            Rule::augmented_assign_op => {
                op = Some(parse_augmented_assign_op(inner.as_str()));
            }
            Rule::set_expression | Rule::set_minus | Rule::set_intersect | Rule::set_union
            | Rule::set_element_op | Rule::set_atom => {
                value = Some(parse_set_expression(inner)?);
            }
            _ => {}
        }
    }

    Ok(MetadataUpdate {
        target: MetadataTarget::Contextual,
        field: field.ok_or_else(|| SqrtParseError::internal("Shorthand update missing field"))?,
        op: op.unwrap_or(MetaUpdateOp::Assign),
        value: value
            .ok_or_else(|| SqrtParseError::internal("Shorthand update missing value"))?,
    })
}

// ============================================================
// Check Rules
// ============================================================

fn parse_check_rule(pair: pest::iterators::Pair<Rule>) -> Result<CheckRule, SqrtParseError> {
    let mut enforcement = None;
    let mut outcome = None;
    let mut condition = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::enforcement => {
                enforcement = Some(match inner.as_str().trim() {
                    "must" | "hard" => Enforcement::Must,
                    "should" | "soft" => Enforcement::Should,
                    other => {
                        return Err(SqrtParseError::internal(&format!(
                            "Unknown enforcement: {other}"
                        )))
                    }
                });
            }
            Rule::outcome => {
                outcome = Some(match inner.as_str().trim() {
                    "allow" => Outcome::Allow,
                    "deny" => Outcome::Deny,
                    other => {
                        return Err(SqrtParseError::internal(&format!(
                            "Unknown outcome: {other}"
                        )))
                    }
                });
            }
            Rule::condition_clause => {
                condition = Some(parse_condition_clause(inner)?);
            }
            _ => {}
        }
    }

    Ok(CheckRule {
        enforcement: enforcement
            .ok_or_else(|| SqrtParseError::internal("Check rule missing enforcement"))?,
        outcome: outcome
            .ok_or_else(|| SqrtParseError::internal("Check rule missing outcome"))?,
        condition: condition
            .ok_or_else(|| SqrtParseError::internal("Check rule missing condition"))?,
        doc_comment: None,
    })
}

fn parse_condition_clause(
    pair: pest::iterators::Pair<Rule>,
) -> Result<Condition, SqrtParseError> {
    let text = pair.as_str().trim();
    if text == "always" {
        return Ok(Condition::Always);
    }
    // "when" + predicate
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::predicate | Rule::predicate_and | Rule::predicate_not
            | Rule::predicate_atom => {
                return Ok(Condition::When(parse_predicate(inner)?));
            }
            _ => {}
        }
    }
    Ok(Condition::Always)
}

// ============================================================
// Result Block
// ============================================================

fn parse_result_block(
    pair: pest::iterators::Pair<Rule>,
) -> Result<Vec<MetadataStmt>, SqrtParseError> {
    let mut stmts = Vec::new();
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::result_stmt {
            stmts.push(parse_result_stmt(inner)?);
        }
    }
    Ok(stmts)
}

fn parse_result_stmt(
    pair: pest::iterators::Pair<Rule>,
) -> Result<MetadataStmt, SqrtParseError> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::doc_comments => {}
            Rule::result_update => {
                return Ok(MetadataStmt::Update(parse_metadata_update(inner)?));
            }
            Rule::result_conditional => {
                return parse_result_conditional(inner);
            }
            _ => {}
        }
    }
    Err(SqrtParseError::internal("Empty result statement"))
}

fn parse_result_conditional(
    pair: pest::iterators::Pair<Rule>,
) -> Result<MetadataStmt, SqrtParseError> {
    let mut condition = None;
    let mut updates = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::predicate | Rule::predicate_and | Rule::predicate_not
            | Rule::predicate_atom => {
                condition = Some(parse_predicate(inner)?);
            }
            Rule::result_update_inner => {
                for update_inner in inner.into_inner() {
                    if update_inner.as_rule() == Rule::result_update {
                        updates.push(parse_metadata_update(update_inner)?);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(MetadataStmt::Conditional {
        condition: condition
            .ok_or_else(|| SqrtParseError::internal("Conditional missing predicate"))?,
        updates,
    })
}

// ============================================================
// Session Block
// ============================================================

enum SessionTiming {
    Before,
    After,
}

fn parse_session_block(
    pair: pest::iterators::Pair<Rule>,
) -> Result<(SessionTiming, Vec<MetadataStmt>), SqrtParseError> {
    let mut timing = SessionTiming::After;
    let mut stmts = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::session_timing => {
                timing = match inner.as_str().trim() {
                    "before" => SessionTiming::Before,
                    "after" => SessionTiming::After,
                    _ => SessionTiming::After,
                };
            }
            Rule::session_stmt => {
                stmts.push(parse_session_stmt(inner)?);
            }
            _ => {}
        }
    }

    Ok((timing, stmts))
}

fn parse_session_stmt(
    pair: pest::iterators::Pair<Rule>,
) -> Result<MetadataStmt, SqrtParseError> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::doc_comments => {}
            Rule::session_update => {
                return Ok(MetadataStmt::Update(parse_metadata_update(inner)?));
            }
            Rule::session_conditional => {
                return parse_session_conditional(inner);
            }
            _ => {}
        }
    }
    Err(SqrtParseError::internal("Empty session statement"))
}

fn parse_session_conditional(
    pair: pest::iterators::Pair<Rule>,
) -> Result<MetadataStmt, SqrtParseError> {
    let mut condition = None;
    let mut updates = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::predicate | Rule::predicate_and | Rule::predicate_not
            | Rule::predicate_atom => {
                condition = Some(parse_predicate(inner)?);
            }
            Rule::session_update_inner => {
                for update_inner in inner.into_inner() {
                    if update_inner.as_rule() == Rule::session_update {
                        updates.push(parse_metadata_update(update_inner)?);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(MetadataStmt::Conditional {
        condition: condition
            .ok_or_else(|| SqrtParseError::internal("Session conditional missing predicate"))?,
        updates,
    })
}

// ============================================================
// Metadata Updates (shared by result/session/shorthand)
// ============================================================

fn parse_metadata_update(
    pair: pest::iterators::Pair<Rule>,
) -> Result<MetadataUpdate, SqrtParseError> {
    let mut target = None;
    let mut op = MetaUpdateOp::Assign;
    let mut value = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::update_target => {
                target = Some(parse_update_target(inner)?);
            }
            Rule::augmented_assign_op => {
                op = parse_augmented_assign_op(inner.as_str());
            }
            Rule::set_expression | Rule::set_minus | Rule::set_intersect | Rule::set_union
            | Rule::set_element_op | Rule::set_atom => {
                value = Some(parse_set_expression(inner)?);
            }
            _ => {}
        }
    }

    let (meta_target, field) =
        target.ok_or_else(|| SqrtParseError::internal("Update missing target"))?;

    Ok(MetadataUpdate {
        target: meta_target,
        field,
        op,
        value: value.ok_or_else(|| SqrtParseError::internal("Update missing value"))?,
    })
}

fn parse_update_target(
    pair: pest::iterators::Pair<Rule>,
) -> Result<(MetadataTarget, MetaFieldKind), SqrtParseError> {
    let text = pair.as_str().trim();

    // Check for @result.FIELD
    if text.starts_with("@result.") {
        let field_str = text.strip_prefix("@result.").unwrap();
        return Ok((MetadataTarget::Result, parse_meta_field(field_str)));
    }
    // Check for @session.FIELD
    if text.starts_with("@session.") {
        let field_str = text.strip_prefix("@session.").unwrap();
        return Ok((MetadataTarget::Session, parse_meta_field(field_str)));
    }
    // Check for @FIELD (contextual)
    if text.starts_with('@') {
        let field_str = text.strip_prefix('@').unwrap();
        return Ok((MetadataTarget::Contextual, parse_meta_field(field_str)));
    }
    // Check for IDENTIFIER.FIELD
    if let Some(dot_pos) = text.rfind('.') {
        let arg_name = &text[..dot_pos];
        let field_str = &text[dot_pos + 1..];
        return Ok((
            MetadataTarget::Arg(arg_name.to_string()),
            parse_meta_field(field_str),
        ));
    }

    Err(SqrtParseError::internal(&format!(
        "Cannot parse update target: {text}"
    )))
}

fn parse_meta_field(s: &str) -> MetaFieldKind {
    match s.trim() {
        "tags" => MetaFieldKind::Tags,
        "producers" => MetaFieldKind::Producers,
        "consumers" => MetaFieldKind::Consumers,
        _ => MetaFieldKind::Tags, // Should not happen with valid grammar
    }
}

fn parse_augmented_assign_op(s: &str) -> MetaUpdateOp {
    match s.trim() {
        "|=" => MetaUpdateOp::UnionAssign,
        "&=" => MetaUpdateOp::IntersectAssign,
        "-=" => MetaUpdateOp::MinusAssign,
        "^=" => MetaUpdateOp::XorAssign,
        _ => MetaUpdateOp::Assign,
    }
}

// ============================================================
// Predicates
// ============================================================

fn parse_predicate(pair: pest::iterators::Pair<Rule>) -> Result<Predicate, SqrtParseError> {
    match pair.as_rule() {
        Rule::predicate => {
            // predicate = { predicate_and ~ ("or" ~ predicate_and)* }
            let mut inner = pair.into_inner();
            let first = parse_predicate(inner.next().unwrap())?;
            
            inner.try_fold(first, |acc, p| {
                Ok(Predicate::Or(Box::new(acc), Box::new(parse_predicate(p)?)))
            })
        }
        Rule::predicate_and => {
            // predicate_and = { predicate_not ~ ("and" ~ predicate_not)* }
            let mut inner = pair.into_inner();
            let first = parse_predicate(inner.next().unwrap())?;

            inner.try_fold(first, |acc, p| {
                Ok(Predicate::And(Box::new(acc), Box::new(parse_predicate(p)?)))
            })
        }
        Rule::predicate_not => {
            // predicate_not = { "not" ~ predicate_not | predicate_atom }
            //
            // In pest PEG, the "not" keyword is a literal string that gets
            // silently consumed — it never appears as a child pair. So
            // `into_inner()` always yields exactly 1 child regardless of
            // which branch was taken. To distinguish the two cases we
            // compare the start position of the parent `predicate_not` pair
            // with the start position of its single child. If the parent
            // starts before the child (because it consumed "not" + whitespace),
            // the negation branch was taken.
            let parent_start = pair.as_span().start();
            let child = pair.into_inner().next().unwrap();
            let child_start = child.as_span().start();

            if child_start > parent_start {
                // The "not" keyword was consumed before the child
                Ok(Predicate::Not(Box::new(parse_predicate(child)?)))
            } else {
                // Direct passthrough to predicate_atom
                parse_predicate(child)
            }
        }
        Rule::predicate_atom => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::comparison => Ok(Predicate::Comparison(parse_comparison(inner)?)),
                Rule::IDENTIFIER => Ok(Predicate::Ref(inner.as_str().to_string())),
                Rule::predicate | Rule::predicate_and | Rule::predicate_not
                | Rule::predicate_atom => parse_predicate(inner),
                _ => Err(SqrtParseError::internal(&format!(
                    "Unexpected predicate atom rule: {:?}",
                    inner.as_rule()
                ))),
            }
        }
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected predicate rule: {:?}",
            pair.as_rule()
        ))),
    }
}

// ============================================================
// Comparisons
// ============================================================

fn parse_comparison(pair: pest::iterators::Pair<Rule>) -> Result<Comparison, SqrtParseError> {
    let inner = match pair.as_rule() {
        Rule::comparison => pair.into_inner().next().unwrap(),
        Rule::value_comparison | Rule::set_comparison => pair,
        _ => {
            return Err(SqrtParseError::internal(&format!(
                "Unexpected comparison rule: {:?}",
                pair.as_rule()
            )))
        }
    };

    match inner.as_rule() {
        Rule::value_comparison => parse_value_comparison(inner),
        Rule::set_comparison => parse_set_comparison(inner),
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected comparison inner: {:?}",
            inner.as_rule()
        ))),
    }
}

fn parse_value_comparison(
    pair: pest::iterators::Pair<Rule>,
) -> Result<Comparison, SqrtParseError> {
    let text = pair.as_str();
    let inner_pairs: Vec<_> = pair.into_inner().collect();

    if text.contains(" in ") {
        // value_operand ~ "in" ~ set_expression
        let operand = parse_value_operand(inner_pairs[0].clone())?;
        let set = parse_set_expression(inner_pairs[1].clone())?;
        Ok(Comparison::ValueIn { operand, set })
    } else {
        // value_operand ~ "==" ~ value_operand
        let left = parse_value_operand(inner_pairs[0].clone())?;
        let right = parse_value_operand(inner_pairs[1].clone())?;
        Ok(Comparison::ValueEquals { left, right })
    }
}

fn parse_set_comparison(
    pair: pest::iterators::Pair<Rule>,
) -> Result<Comparison, SqrtParseError> {
    let text = pair.as_str();
    let inner_pairs: Vec<_> = pair.into_inner().collect();

    if text.contains(" overlaps ") {
        let left = parse_set_operand(inner_pairs[0].clone())?;
        let right = parse_set_expression(inner_pairs[1].clone())?;
        Ok(Comparison::SetOverlaps { left, right })
    } else if text.contains(" subset ") {
        let left = parse_set_operand(inner_pairs[0].clone())?;
        let right = parse_set_expression(inner_pairs[1].clone())?;
        Ok(Comparison::SetSubsetOf { left, right })
    } else if text.contains(" superset ") {
        let left = parse_set_operand(inner_pairs[0].clone())?;
        let right = parse_set_expression(inner_pairs[1].clone())?;
        Ok(Comparison::SetSupersetOf { left, right })
    } else if text.contains(" is empty") {
        let left = parse_set_operand(inner_pairs[0].clone())?;
        Ok(Comparison::SetIsEmpty(left))
    } else if text.contains(" is universal") {
        let left = parse_set_operand(inner_pairs[0].clone())?;
        Ok(Comparison::SetIsUniversal(left))
    } else if text.contains("==") {
        let left = parse_set_operand(inner_pairs[0].clone())?;
        let right = parse_set_expression(inner_pairs[1].clone())?;
        Ok(Comparison::SetEquals { left, right })
    } else {
        Err(SqrtParseError::internal(&format!(
            "Cannot determine set comparison type: {text}"
        )))
    }
}

// ============================================================
// Set Expressions
// ============================================================

fn parse_set_expression(pair: pest::iterators::Pair<Rule>) -> Result<SetExpr, SqrtParseError> {
    match pair.as_rule() {
        Rule::set_expression => {
            // set_expression = { set_minus ~ (set_xor_op ~ set_minus)* }
            parse_binary_set_op(pair, |l, r| SetExpr::Xor(Box::new(l), Box::new(r)))
        }
        Rule::set_minus => {
            // set_minus = { set_intersect ~ (set_minus_op ~ set_intersect)* }
            parse_binary_set_op(pair, |l, r| SetExpr::Minus(Box::new(l), Box::new(r)))
        }
        Rule::set_intersect => {
            // set_intersect = { set_union ~ (set_intersect_op ~ set_union)* }
            parse_binary_set_op(pair, |l, r| SetExpr::Intersect(Box::new(l), Box::new(r)))
        }
        Rule::set_union => {
            // set_union = { set_element_op ~ (set_union_op ~ set_element_op)* }
            parse_binary_set_op(pair, |l, r| SetExpr::Union(Box::new(l), Box::new(r)))
        }
        Rule::set_element_op => {
            // set_element_op = { set_atom ~ (("with" | "without") ~ element)* }
            let mut inner = pair.into_inner();
            let first = parse_set_expression(inner.next().unwrap())?;

            let mut result = first;
            // Remaining pairs come in keyword/element pairs
            while let Some(next) = inner.next() {
                let text = next.as_str().trim();
                match next.as_rule() {
                    Rule::element => {
                        // The preceding keyword was "with" or "without"
                        // but pest may not give us the keyword as a separate token.
                        // We handle this differently — look at the text.
                        // Actually in pest, "with"/"without" are literal strings consumed
                        // silently. The element is what remains.
                        // Since pest PEG consumes keywords, let me handle via pairs.
                        let elem = parse_element(next)?;
                        // Default to "with" — we need to check the actual keyword
                        result = SetExpr::With(Box::new(result), elem);
                    }
                    _ => {
                        // Could be the keyword pair itself
                        if text == "with" {
                            if let Some(elem_pair) = inner.next() {
                                let elem = parse_element(elem_pair)?;
                                result = SetExpr::With(Box::new(result), elem);
                            }
                        } else if text == "without" {
                            if let Some(elem_pair) = inner.next() {
                                let elem = parse_element(elem_pair)?;
                                result = SetExpr::Without(Box::new(result), elem);
                            }
                        }
                    }
                }
            }
            Ok(result)
        }
        Rule::set_atom => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::set_literal => parse_set_literal(inner),
                Rule::set_operand => {
                    let operand = parse_set_operand(inner)?;
                    Ok(SetExpr::Operand(operand))
                }
                Rule::IDENTIFIER => Ok(SetExpr::Ref(inner.as_str().to_string())),
                Rule::set_expression | Rule::set_minus | Rule::set_intersect
                | Rule::set_union | Rule::set_element_op | Rule::set_atom => {
                    parse_set_expression(inner)
                }
                _ => Err(SqrtParseError::internal(&format!(
                    "Unexpected set atom: {:?}",
                    inner.as_rule()
                ))),
            }
        }
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected set expression rule: {:?}",
            pair.as_rule()
        ))),
    }
}

/// Parse a binary set operation with left-associative folding.
/// The PEG pattern is: `operand ~ (op ~ operand)*`
fn parse_binary_set_op(
    pair: pest::iterators::Pair<Rule>,
    combine: fn(SetExpr, SetExpr) -> SetExpr,
) -> Result<SetExpr, SqrtParseError> {
    let mut inner = pair.into_inner();
    let first = parse_set_expression(inner.next().unwrap())?;

    let mut result = first;
    while let Some(next) = inner.next() {
        // Skip operator pairs (set_xor_op, set_minus_op, etc.)
        match next.as_rule() {
            Rule::set_xor_op | Rule::set_minus_op | Rule::set_intersect_op
            | Rule::set_union_op => {
                // Consume operator, then parse operand
                if let Some(operand_pair) = inner.next() {
                    let right = parse_set_expression(operand_pair)?;
                    result = combine(result, right);
                }
            }
            _ => {
                // Directly an operand (shouldn't happen but handle gracefully)
                let right = parse_set_expression(next)?;
                result = combine(result, right);
            }
        }
    }

    Ok(result)
}

// ============================================================
// Set Literals
// ============================================================

fn parse_set_literal(pair: pest::iterators::Pair<Rule>) -> Result<SetExpr, SqrtParseError> {
    let inner_pairs: Vec<_> = pair.into_inner().collect();
    if inner_pairs.is_empty() {
        // Empty set: { }
        return Ok(SetExpr::Literal(Vec::new()));
    }

    // Non-empty set: { element_list }
    let element_list = &inner_pairs[0];
    let mut elements = Vec::new();
    for elem_pair in element_list.clone().into_inner() {
        if elem_pair.as_rule() == Rule::element {
            elements.push(parse_element(elem_pair)?);
        }
    }
    Ok(SetExpr::Literal(elements))
}

fn parse_element(pair: pest::iterators::Pair<Rule>) -> Result<SetElement, SqrtParseError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::string_element => parse_string_element(inner),
        Rule::type_domain => Ok(SetElement::TypeDomain(parse_type_domain(inner)?)),
        Rule::number => Ok(SetElement::Number(parse_number(inner))),
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected element rule: {:?}",
            inner.as_rule()
        ))),
    }
}

fn parse_string_element(pair: pest::iterators::Pair<Rule>) -> Result<SetElement, SqrtParseError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::STRING => Ok(SetElement::String(extract_string_content(inner.as_str()))),
        Rule::REGEX_STRING => Ok(SetElement::Regex(extract_regex_string_content(
            inner.as_str(),
        ))),
        Rule::WILDCARD_STRING => Ok(SetElement::Wildcard(extract_wildcard_string_content(
            inner.as_str(),
        ))),
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected string element: {:?}",
            inner.as_rule()
        ))),
    }
}

// ============================================================
// Set Operands
// ============================================================

fn parse_set_operand(pair: pest::iterators::Pair<Rule>) -> Result<SetOperand, SqrtParseError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::arg_meta_access => {
            let text = inner.as_str().trim();
            let dot_pos = text.rfind('.').unwrap();
            let arg_name = text[..dot_pos].to_string();
            let field = parse_meta_field(&text[dot_pos + 1..]);
            Ok(SetOperand::ArgField { arg_name, field })
        }
        Rule::result_meta_access => {
            let text = inner.as_str().trim();
            let field_str = text.strip_prefix("@result.").unwrap();
            Ok(SetOperand::ResultField(parse_meta_field(field_str)))
        }
        Rule::session_meta_access => {
            let text = inner.as_str().trim();
            let field_str = text.strip_prefix("@session.").unwrap();
            Ok(SetOperand::SessionField(parse_meta_field(field_str)))
        }
        Rule::context_meta_access => {
            let text = inner.as_str().trim();
            let field_str = text.strip_prefix('@').unwrap();
            Ok(SetOperand::ContextField(parse_meta_field(field_str)))
        }
        Rule::args_meta_access => {
            let mut field = MetaFieldKind::Tags;
            let mut agg = AggregationOp::Union; // default
            for sub in inner.into_inner() {
                match sub.as_rule() {
                    Rule::META_FIELD => field = parse_meta_field(sub.as_str()),
                    Rule::agg_suffix => {
                        let suffix_text = sub.as_str().trim();
                        if suffix_text.contains("intersect") {
                            agg = AggregationOp::Intersect;
                        }
                    }
                    _ => {}
                }
            }
            Ok(SetOperand::ArgsField { field, agg })
        }
        Rule::aggregation => {
            let mut op = AggregationOp::Union;
            let mut field = MetaFieldKind::Tags;
            for sub in inner.into_inner() {
                match sub.as_rule() {
                    Rule::agg_op => {
                        op = if sub.as_str().trim() == "intersect" {
                            AggregationOp::Intersect
                        } else {
                            AggregationOp::Union
                        };
                    }
                    Rule::META_FIELD => field = parse_meta_field(sub.as_str()),
                    _ => {}
                }
            }
            Ok(SetOperand::Aggregation { op, field })
        }
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected set operand: {:?}",
            inner.as_rule()
        ))),
    }
}

// ============================================================
// Value Operands
// ============================================================

fn parse_value_operand(
    pair: pest::iterators::Pair<Rule>,
) -> Result<ValueOperand, SqrtParseError> {
    let inner = match pair.as_rule() {
        Rule::value_operand => pair.into_inner().next().unwrap(),
        _ => pair,
    };

    match inner.as_rule() {
        Rule::arg_value_access => {
            let text = inner.as_str().trim();
            let arg_name = text.strip_suffix(".value").unwrap().to_string();
            Ok(ValueOperand::ArgValue(arg_name))
        }
        Rule::result_value_access => Ok(ValueOperand::ResultValue),
        Rule::session_value_access => Ok(ValueOperand::SessionValue),
        Rule::literal => Ok(ValueOperand::Literal(parse_literal(inner)?)),
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected value operand: {:?}",
            inner.as_rule()
        ))),
    }
}

fn parse_literal(pair: pest::iterators::Pair<Rule>) -> Result<LiteralValue, SqrtParseError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::STRING => Ok(LiteralValue::String(extract_string_content(inner.as_str()))),
        Rule::DATETIME_STRING => Ok(LiteralValue::Datetime(extract_datetime_string_content(
            inner.as_str(),
        ))),
        Rule::BOOL => Ok(LiteralValue::Bool(inner.as_str() == "true")),
        Rule::number => Ok(LiteralValue::Number(parse_number(inner))),
        Rule::FLOAT => Ok(LiteralValue::Number(NumberValue::Float(
            inner.as_str().parse().unwrap(),
        ))),
        Rule::INT => Ok(LiteralValue::Number(NumberValue::Int(
            inner.as_str().parse().unwrap(),
        ))),
        Rule::INF => Ok(LiteralValue::Number(parse_inf(inner.as_str()))),
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected literal: {:?}",
            inner.as_rule()
        ))),
    }
}

// ============================================================
// Type Domains
// ============================================================

fn parse_type_domain(pair: pest::iterators::Pair<Rule>) -> Result<TypeDomain, SqrtParseError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::bool_domain => {
            let bool_pair = inner.into_inner().next().unwrap();
            Ok(TypeDomain::Bool(bool_pair.as_str() == "true"))
        }
        Rule::int_domain => {
            let range_pair = inner.into_inner().next().unwrap();
            Ok(TypeDomain::Int(parse_range_spec(range_pair)?))
        }
        Rule::float_domain => {
            let range_pair = inner.into_inner().next().unwrap();
            Ok(TypeDomain::Float(parse_range_spec(range_pair)?))
        }
        Rule::str_domain => {
            let mut pattern = None;
            let mut length = None;
            for sub in inner.into_inner() {
                match sub.as_rule() {
                    Rule::str_pattern => pattern = Some(parse_str_pattern(sub)?),
                    Rule::length_spec => {
                        let range_pair = sub.into_inner().next().unwrap();
                        length = Some(parse_range_spec(range_pair)?);
                    }
                    _ => {}
                }
            }
            Ok(TypeDomain::Str {
                pattern: pattern
                    .ok_or_else(|| SqrtParseError::internal("str domain missing pattern"))?,
                length,
            })
        }
        Rule::datetime_domain => {
            let spec_pair = inner.into_inner().next().unwrap();
            Ok(TypeDomain::Datetime(parse_datetime_spec(spec_pair)?))
        }
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected type domain: {:?}",
            inner.as_rule()
        ))),
    }
}

fn parse_range_spec(
    pair: pest::iterators::Pair<Rule>,
) -> Result<RangeSpec<NumberValue>, SqrtParseError> {
    let inner_pairs: Vec<_> = pair.into_inner().collect();

    match inner_pairs.len() {
        1 => {
            // Exact value or single-sided range
            let p = &inner_pairs[0];
            match p.as_rule() {
                Rule::number | Rule::INT | Rule::FLOAT | Rule::INF => {
                    Ok(RangeSpec::Exact(parse_number(p.clone())))
                }
                _ => Err(SqrtParseError::internal(&format!(
                    "Unexpected range_spec single: {:?}",
                    p.as_rule()
                ))),
            }
        }
        2 => {
            let (a, b) = (&inner_pairs[0], &inner_pairs[1]);
            // Could be: number RANGE_OP, or RANGE_OP number
            match (a.as_rule(), b.as_rule()) {
                (Rule::number, Rule::RANGE_INCLUSIVE) => {
                    Ok(RangeSpec::From(parse_number(a.clone())))
                }
                (Rule::number, Rule::RANGE_EXCLUSIVE_LEFT) => {
                    Ok(RangeSpec::FromExclusive(parse_number(a.clone())))
                }
                (Rule::RANGE_INCLUSIVE, Rule::number) => {
                    Ok(RangeSpec::To(parse_number(b.clone())))
                }
                (Rule::RANGE_EXCLUSIVE_RIGHT, Rule::number) => {
                    Ok(RangeSpec::ToExclusive(parse_number(b.clone())))
                }
                _ => Err(SqrtParseError::internal(&format!(
                    "Unexpected range_spec pair: {:?}, {:?}",
                    a.as_rule(),
                    b.as_rule()
                ))),
            }
        }
        3 => {
            let (a, op, b) = (&inner_pairs[0], &inner_pairs[1], &inner_pairs[2]);
            let min = parse_number(a.clone());
            let max = parse_number(b.clone());
            match op.as_rule() {
                Rule::RANGE_INCLUSIVE => Ok(RangeSpec::Inclusive { min, max }),
                Rule::RANGE_EXCLUSIVE_BOTH => Ok(RangeSpec::ExclusiveBoth { min, max }),
                Rule::RANGE_EXCLUSIVE_LEFT => Ok(RangeSpec::ExclusiveLeft { min, max }),
                Rule::RANGE_EXCLUSIVE_RIGHT => Ok(RangeSpec::ExclusiveRight { min, max }),
                _ => Err(SqrtParseError::internal(&format!(
                    "Unexpected range operator: {:?}",
                    op.as_rule()
                ))),
            }
        }
        n => Err(SqrtParseError::internal(&format!(
            "Unexpected range_spec with {n} parts"
        ))),
    }
}

fn parse_str_pattern(
    pair: pest::iterators::Pair<Rule>,
) -> Result<StringPattern, SqrtParseError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::STRING => Ok(StringPattern::Exact(extract_string_content(inner.as_str()))),
        Rule::REGEX_STRING => Ok(StringPattern::Matching(extract_regex_string_content(
            inner.as_str(),
        ))),
        Rule::WILDCARD_STRING => Ok(StringPattern::Like(extract_wildcard_string_content(
            inner.as_str(),
        ))),
        _ => Err(SqrtParseError::internal(&format!(
            "Unexpected str pattern: {:?}",
            inner.as_rule()
        ))),
    }
}

fn parse_datetime_spec(
    pair: pest::iterators::Pair<Rule>,
) -> Result<DatetimeSpec, SqrtParseError> {
    let inner_pairs: Vec<_> = pair.into_inner().collect();

    match inner_pairs.len() {
        1 => {
            let p = &inner_pairs[0];
            match p.as_rule() {
                Rule::DATETIME_STRING => Ok(DatetimeSpec::Exact(
                    extract_datetime_string_content(p.as_str()),
                )),
                Rule::STRING => Ok(DatetimeSpec::String(extract_string_content(p.as_str()))),
                Rule::number => Ok(DatetimeSpec::Epoch(parse_number(p.clone()))),
                _ => Err(SqrtParseError::internal("Unexpected datetime spec")),
            }
        }
        2 => {
            let (a, b) = (&inner_pairs[0], &inner_pairs[1]);
            match (a.as_rule(), b.as_rule()) {
                (Rule::DATETIME_STRING, Rule::RANGE_INCLUSIVE) => Ok(DatetimeSpec::Range(
                    RangeSpec::From(extract_datetime_string_content(a.as_str())),
                )),
                (Rule::DATETIME_STRING, Rule::RANGE_EXCLUSIVE_LEFT) => Ok(DatetimeSpec::Range(
                    RangeSpec::FromExclusive(extract_datetime_string_content(a.as_str())),
                )),
                (Rule::RANGE_INCLUSIVE, Rule::DATETIME_STRING) => Ok(DatetimeSpec::Range(
                    RangeSpec::To(extract_datetime_string_content(b.as_str())),
                )),
                (Rule::RANGE_EXCLUSIVE_RIGHT, Rule::DATETIME_STRING) => Ok(DatetimeSpec::Range(
                    RangeSpec::ToExclusive(extract_datetime_string_content(b.as_str())),
                )),
                _ => Err(SqrtParseError::internal("Unexpected datetime spec pair")),
            }
        }
        3 => {
            let (a, op, b) = (&inner_pairs[0], &inner_pairs[1], &inner_pairs[2]);
            let min = extract_datetime_string_content(a.as_str());
            let max = extract_datetime_string_content(b.as_str());
            match op.as_rule() {
                Rule::RANGE_INCLUSIVE => Ok(DatetimeSpec::Range(RangeSpec::Inclusive {
                    min,
                    max,
                })),
                Rule::RANGE_EXCLUSIVE_BOTH => Ok(DatetimeSpec::Range(RangeSpec::ExclusiveBoth {
                    min,
                    max,
                })),
                Rule::RANGE_EXCLUSIVE_LEFT => Ok(DatetimeSpec::Range(RangeSpec::ExclusiveLeft {
                    min,
                    max,
                })),
                Rule::RANGE_EXCLUSIVE_RIGHT => {
                    Ok(DatetimeSpec::Range(RangeSpec::ExclusiveRight { min, max }))
                }
                _ => Err(SqrtParseError::internal("Unexpected datetime range op")),
            }
        }
        _ => Err(SqrtParseError::internal("Unexpected datetime spec length")),
    }
}

// ============================================================
// Numbers
// ============================================================

fn parse_number(pair: pest::iterators::Pair<Rule>) -> NumberValue {
    match pair.as_rule() {
        Rule::number => {
            let inner = pair.into_inner().next().unwrap();
            parse_number(inner)
        }
        Rule::FLOAT => NumberValue::Float(pair.as_str().parse().unwrap()),
        Rule::INT => NumberValue::Int(pair.as_str().parse().unwrap()),
        Rule::INF => parse_inf(pair.as_str()),
        _ => NumberValue::Int(0), // Should not happen
    }
}

fn parse_inf(s: &str) -> NumberValue {
    match s.trim() {
        "inf" | "+inf" => NumberValue::PosInf,
        "-inf" => NumberValue::NegInf,
        _ => NumberValue::PosInf,
    }
}

// ============================================================
// String Content Extraction
// ============================================================

/// Extract content from `"..."` (removes surrounding quotes).
fn extract_string_content(s: &str) -> String {
    let inner = &s[1..s.len() - 1]; // Remove " and "
    unescape_string(inner)
}

/// Extract content from `r"..."` (removes `r"` prefix and `"` suffix).
fn extract_regex_string_content(s: &str) -> String {
    let inner = &s[2..s.len() - 1]; // Remove r" and "
    unescape_string(inner)
}

/// Extract content from `w"..."` (removes `w"` prefix and `"` suffix).
fn extract_wildcard_string_content(s: &str) -> String {
    let inner = &s[2..s.len() - 1]; // Remove w" and "
    unescape_string(inner)
}

/// Extract content from `d"..."` (removes `d"` prefix and `"` suffix).
fn extract_datetime_string_content(s: &str) -> String {
    let inner = &s[2..s.len() - 1]; // Remove d" and "
    unescape_string(inner)
}

/// Process escape sequences in a string.
fn unescape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

// ============================================================
// Helpers
// ============================================================

fn pair_to_span(pair: &pest::iterators::Pair<Rule>) -> Span {
    let pest_span = pair.as_span();
    let (start_line, start_col) = pest_span.start_pos().line_col();
    let (end_line, end_col) = pest_span.end_pos().line_col();
    Span {
        start_line,
        start_col,
        end_line,
        end_col,
    }
}
