#[cfg(test)]
mod tests {
    use crate::ast::*;
    use crate::parse;

    // ============================================================
    // Helper: parse and unwrap
    // ============================================================

    fn parse_ok(input: &str) -> SqrtProgram {
        match parse(input) {
            Ok(prog) => prog,
            Err(e) => panic!("Parse error on input:\n{}\n\nError: {}", input, e),
        }
    }

    fn parse_err(input: &str) {
        assert!(
            parse(input).is_err(),
            "Expected parse error on input:\n{}",
            input
        );
    }

    // ============================================================
    // Empty Program
    // ============================================================

    #[test]
    fn test_empty_program() {
        let prog = parse_ok("");
        assert!(prog.declarations.is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        let prog = parse_ok("   \n\n  \t  ");
        assert!(prog.declarations.is_empty());
    }

    #[test]
    fn test_comments_only() {
        let prog = parse_ok("// this is a comment\n/* multi\nline */\n");
        assert!(prog.declarations.is_empty());
    }

    // ============================================================
    // Let Declarations
    // ============================================================

    #[test]
    fn test_let_set_literal() {
        let prog = parse_ok(r#"let sensitive = {"internal_use", "confidential"};"#);
        assert_eq!(prog.declarations.len(), 1);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::Let(LetDecl { name, value }) => {
                assert_eq!(name, "sensitive");
                match value {
                    Expression::SetExpr(SetExpr::Literal(elems)) => {
                        assert_eq!(elems.len(), 2);
                        assert_eq!(elems[0], SetElement::String("internal_use".to_string()));
                        assert_eq!(elems[1], SetElement::String("confidential".to_string()));
                    }
                    other => panic!("Expected set literal, got {:?}", other),
                }
            }
            other => panic!("Expected let declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_let_empty_set() {
        let prog = parse_ok("let empty_tags = {};");
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => {
                    assert!(elems.is_empty());
                }
                other => panic!("Expected empty set, got {:?}", other),
            },
            other => panic!("Expected let declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_let_regex_set() {
        let prog = parse_ok(r#"let trusted = {str matching r".*@trustedcorp\.com"};"#);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::Let(LetDecl { name, value }) => {
                assert_eq!(name, "trusted");
                match value {
                    Expression::SetExpr(SetExpr::Literal(elems)) => {
                        assert_eq!(elems.len(), 1);
                        match &elems[0] {
                            SetElement::TypeDomain(TypeDomain::Str { pattern, length }) => {
                                assert_eq!(
                                    *pattern,
                                    StringPattern::Matching(
                                        r".*@trustedcorp\.com".to_string()
                                    )
                                );
                                assert!(length.is_none());
                            }
                            other => panic!("Expected str type domain, got {:?}", other),
                        }
                    }
                    other => panic!("Expected set literal, got {:?}", other),
                }
            }
            other => panic!("Expected let declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_let_predicate() {
        let prog = parse_ok(
            r#"let is_sensitive = body.tags overlaps {"internal_use", "confidential"};"#,
        );
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::Let(LetDecl { name, value }) => {
                assert_eq!(name, "is_sensitive");
                match value {
                    Expression::Predicate(Predicate::Comparison(Comparison::SetOverlaps {
                        left,
                        right,
                    })) => {
                        assert_eq!(
                            *left,
                            SetOperand::ArgField {
                                arg_name: "body".to_string(),
                                field: MetaFieldKind::Tags,
                            }
                        );
                        match right {
                            SetExpr::Literal(elems) => assert_eq!(elems.len(), 2),
                            other => panic!("Expected set literal, got {:?}", other),
                        }
                    }
                    other => panic!("Expected set overlaps comparison, got {:?}", other),
                }
            }
            other => panic!("Expected let declaration, got {:?}", other),
        }
    }

    // ============================================================
    // Tool Shorthand
    // ============================================================

    #[test]
    fn test_tool_shorthand_simple() {
        let prog = parse_ok(r#"tool "get_document" -> @tags |= {"retrieved"};"#);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::ToolShorthand(sh) => {
                assert_eq!(sh.id, ToolId::Exact("get_document".to_string()));
                assert!(sh.priority.is_none());
                assert_eq!(sh.target, UpdateTarget::Result);
                assert_eq!(sh.update.field, MetaFieldKind::Tags);
                assert_eq!(sh.update.op, MetaUpdateOp::UnionAssign);
                assert!(sh.condition.is_none());
            }
            other => panic!("Expected tool shorthand, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_shorthand_with_priority() {
        let prog = parse_ok(r#"tool "my_tool" [10] -> @tags |= {"high_pri"};"#);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::ToolShorthand(sh) => {
                assert_eq!(sh.priority, Some(10));
            }
            other => panic!("Expected tool shorthand, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_shorthand_session_target() {
        let prog = parse_ok(r#"tool "my_tool" -> session @tags |= {"tagged"};"#);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::ToolShorthand(sh) => {
                assert_eq!(sh.target, UpdateTarget::SessionAfter);
            }
            other => panic!("Expected tool shorthand, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_shorthand_session_before() {
        let prog = parse_ok(r#"tool "my_tool" -> session before @tags |= {"tagged"};"#);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::ToolShorthand(sh) => {
                assert_eq!(sh.target, UpdateTarget::SessionBefore);
            }
            other => panic!("Expected tool shorthand, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_shorthand_with_condition() {
        let prog = parse_ok(
            r#"tool "my_tool" -> @tags |= {"tagged"} when @result.tags overlaps {"important"};"#,
        );
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::ToolShorthand(sh) => {
                assert!(sh.condition.is_some());
            }
            other => panic!("Expected tool shorthand, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_shorthand_regex_id() {
        let prog = parse_ok(r#"tool r"get_.*" -> @tags |= {"data_retrieval"};"#);
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::ToolShorthand(sh) => {
                assert_eq!(sh.id, ToolId::Regex("get_.*".to_string()));
            }
            other => panic!("Expected tool shorthand, got {:?}", other),
        }
    }

    // ============================================================
    // Tool Declarations (Full Form)
    // ============================================================

    #[test]
    fn test_tool_decl_check_rules() {
        let prog = parse_ok(
            r#"
            tool "send_email" {
                must deny when body.tags overlaps {"confidential"};
                should allow always;
            }
        "#,
        );
        let decl = &prog.declarations[0];
        match &decl.kind {
            DeclarationKind::Tool(tool) => {
                assert_eq!(tool.id, ToolId::Exact("send_email".to_string()));
                assert_eq!(tool.checks.len(), 2);

                assert_eq!(tool.checks[0].enforcement, Enforcement::Must);
                assert_eq!(tool.checks[0].outcome, Outcome::Deny);
                assert!(matches!(tool.checks[0].condition, Condition::When(_)));

                assert_eq!(tool.checks[1].enforcement, Enforcement::Should);
                assert_eq!(tool.checks[1].outcome, Outcome::Allow);
                assert_eq!(tool.checks[1].condition, Condition::Always);
            }
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_decl_hard_soft_aliases() {
        let prog = parse_ok(
            r#"
            tool "test" {
                hard deny always;
                soft allow always;
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                assert_eq!(tool.checks[0].enforcement, Enforcement::Must);
                assert_eq!(tool.checks[1].enforcement, Enforcement::Should);
            }
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_decl_with_result_block() {
        let prog = parse_ok(
            r#"
            tool "get_document" {
                result {
                    @tags |= {"confidential"};
                    @producers |= {"internal_db"};
                    @consumers &= {"admin"};
                }
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                let result_block = tool.result_block.as_ref().unwrap();
                assert_eq!(result_block.len(), 3);

                match &result_block[0] {
                    MetadataStmt::Update(u) => {
                        assert_eq!(u.field, MetaFieldKind::Tags);
                        assert_eq!(u.op, MetaUpdateOp::UnionAssign);
                    }
                    other => panic!("Expected update, got {:?}", other),
                }
                match &result_block[1] {
                    MetadataStmt::Update(u) => {
                        assert_eq!(u.field, MetaFieldKind::Producers);
                        assert_eq!(u.op, MetaUpdateOp::UnionAssign);
                    }
                    other => panic!("Expected update, got {:?}", other),
                }
                match &result_block[2] {
                    MetadataStmt::Update(u) => {
                        assert_eq!(u.field, MetaFieldKind::Consumers);
                        assert_eq!(u.op, MetaUpdateOp::IntersectAssign);
                    }
                    other => panic!("Expected update, got {:?}", other),
                }
            }
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_decl_with_session_blocks() {
        let prog = parse_ok(
            r#"
            tool "sensitive_op" {
                session before {
                    @tags |= {"accessing_sensitive"};
                }
                session after {
                    @tags |= {"completed_access"};
                }
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                assert!(tool.session_before.is_some());
                assert!(tool.session_after.is_some());
                assert_eq!(tool.session_before.as_ref().unwrap().len(), 1);
                assert_eq!(tool.session_after.as_ref().unwrap().len(), 1);
            }
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_tool_decl_with_priority() {
        let prog = parse_ok(
            r#"
            tool "important" {
                priority 10;
                must allow always;
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                assert_eq!(tool.priority, Some(10));
            }
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    // ============================================================
    // Predicates
    // ============================================================

    #[test]
    fn test_predicate_and() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when body.tags overlaps {"a"} and to.tags overlaps {"b"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::And(_, _)) => {}
                other => panic!("Expected And predicate, got {:?}", other),
            },
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_predicate_or() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when body.tags overlaps {"a"} or body.tags overlaps {"b"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Or(_, _)) => {}
                other => panic!("Expected Or predicate, got {:?}", other),
            },
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_predicate_not() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when not body.tags overlaps {"safe"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Not(_)) => {}
                other => panic!("Expected Not predicate, got {:?}", other),
            },
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_predicate_ref() {
        let prog = parse_ok(
            r#"
            let is_safe = body.tags overlaps {"safe"};
            tool "test" {
                must allow when is_safe;
            }
        "#,
        );
        match &prog.declarations[1].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Ref(name)) => {
                    assert_eq!(name, "is_safe");
                }
                other => panic!("Expected predicate ref, got {:?}", other),
            },
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    #[test]
    fn test_predicate_parenthesized() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when (body.tags overlaps {"a"}) and (not to.tags is empty);
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::And(_, _)) => {}
                other => panic!("Expected And predicate, got {:?}", other),
            },
            other => panic!("Expected tool declaration, got {:?}", other),
        }
    }

    // ============================================================
    // Set Comparisons
    // ============================================================

    #[test]
    fn test_set_subset_of() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must allow when body.tags subset of {"safe", "public"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetSubsetOf { .. })) => {}
                other => panic!("Expected SetSubsetOf, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_set_is_empty() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when body.tags is empty;
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetIsEmpty(_))) => {}
                other => panic!("Expected SetIsEmpty, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_set_is_universal() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must allow when body.consumers is universal;
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetIsUniversal(_))) => {}
                other => panic!("Expected SetIsUniversal, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    // ============================================================
    // Value Comparisons
    // ============================================================

    #[test]
    fn test_value_in_set() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must allow when to.value in {str matching r".*@trustedcorp\.com"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::ValueIn {
                    operand,
                    ..
                })) => {
                    assert_eq!(*operand, ValueOperand::ArgValue("to".to_string()));
                }
                other => panic!("Expected ValueIn, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_value_equals() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when recipient.value == "admin@example.com";
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::ValueEquals {
                    left,
                    right,
                })) => {
                    assert_eq!(*left, ValueOperand::ArgValue("recipient".to_string()));
                    match right {
                        ValueOperand::Literal(LiteralValue::String(s)) => {
                            assert_eq!(s, "admin@example.com");
                        }
                        other => panic!("Expected string literal, got {:?}", other),
                    }
                }
                other => panic!("Expected ValueEquals, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    // ============================================================
    // Set Operations
    // ============================================================

    #[test]
    fn test_set_union() {
        let prog = parse_ok(r#"let combined = {"a"} | {"b"};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Union(_, _)) => {}
                other => panic!("Expected set union, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_set_intersect() {
        let prog = parse_ok(r#"let common = {"a", "b"} & {"b", "c"};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Intersect(_, _)) => {}
                other => panic!("Expected set intersect, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_set_minus() {
        let prog = parse_ok(r#"let diff = {"a", "b"} - {"b"};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Minus(_, _)) => {}
                other => panic!("Expected set minus, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_set_keyword_ops() {
        let prog = parse_ok(r#"let combined = {"a"} union {"b"};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Union(_, _)) => {}
                other => panic!("Expected set union (keyword), got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    // ============================================================
    // Type Domains
    // ============================================================

    #[test]
    fn test_type_domain_bool() {
        let prog = parse_ok(r#"let check = {bool true};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => {
                    assert_eq!(elems[0], SetElement::TypeDomain(TypeDomain::Bool(true)));
                }
                other => panic!("Expected set with bool, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_type_domain_int_range() {
        let prog = parse_ok(r#"let age_range = {int 1..100};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => match &elems[0] {
                    SetElement::TypeDomain(TypeDomain::Int(RangeSpec::Inclusive { min, max })) => {
                        assert_eq!(*min, NumberValue::Int(1));
                        assert_eq!(*max, NumberValue::Int(100));
                    }
                    other => panic!("Expected int inclusive range, got {:?}", other),
                },
                other => panic!("Expected set literal, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_type_domain_int_exclusive() {
        let prog = parse_ok(r#"let half_open = {int 0<..<100};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => match &elems[0] {
                    SetElement::TypeDomain(TypeDomain::Int(RangeSpec::ExclusiveBoth {
                        min,
                        max,
                    })) => {
                        assert_eq!(*min, NumberValue::Int(0));
                        assert_eq!(*max, NumberValue::Int(100));
                    }
                    other => panic!("Expected int exclusive both range, got {:?}", other),
                },
                other => panic!("Expected set literal, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_type_domain_str_with_length() {
        let prog = parse_ok(r#"let bounded = {str matching r".*" length 1..100};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => match &elems[0] {
                    SetElement::TypeDomain(TypeDomain::Str { pattern, length }) => {
                        assert_eq!(*pattern, StringPattern::Matching(".*".to_string()));
                        assert!(length.is_some());
                    }
                    other => panic!("Expected str with length, got {:?}", other),
                },
                other => panic!("Expected set literal, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_type_domain_str_wildcard() {
        let prog = parse_ok(r#"let files = {str like w"*.txt"};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => match &elems[0] {
                    SetElement::TypeDomain(TypeDomain::Str { pattern, .. }) => {
                        assert_eq!(*pattern, StringPattern::Like("*.txt".to_string()));
                    }
                    other => panic!("Expected str wildcard, got {:?}", other),
                },
                other => panic!("Expected set literal, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    // ============================================================
    // Meta Field Access Patterns
    // ============================================================

    #[test]
    fn test_args_meta_access() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when @args.tags overlaps {"confidential"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetOverlaps {
                    left,
                    ..
                })) => {
                    assert_eq!(
                        *left,
                        SetOperand::ArgsField {
                            field: MetaFieldKind::Tags,
                            agg: AggregationOp::Union,
                        }
                    );
                }
                other => panic!("Expected overlaps with @args.tags, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_session_meta_access() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when @session.tags overlaps {"blocked"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetOverlaps {
                    left,
                    ..
                })) => {
                    assert_eq!(
                        *left,
                        SetOperand::SessionField(MetaFieldKind::Tags)
                    );
                }
                other => panic!("Expected overlaps with @session.tags, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    // ============================================================
    // Doc Comments
    // ============================================================

    #[test]
    fn test_doc_comments() {
        let prog = parse_ok(
            r#"
            /// Prevents sensitive data leaks
            /// across untrusted boundaries
            tool "send_email" {
                must deny always;
            }
        "#,
        );
        let decl = &prog.declarations[0];
        assert!(decl.doc_comment.is_some());
        let comment = decl.doc_comment.as_ref().unwrap();
        assert!(comment.contains("Prevents sensitive data leaks"));
        assert!(comment.contains("across untrusted boundaries"));
    }

    // ============================================================
    // Complex Real-World Examples from Docs
    // ============================================================

    #[test]
    fn test_data_leak_prevention_example() {
        let prog = parse_ok(
            r#"
            let sensitive_docs = {"internal_use", "confidential"};

            tool "get_internal_document" -> @tags |= sensitive_docs;

            tool "send_email" {
                hard deny when (body.tags overlaps sensitive_docs) and
                    (not to.value in {str matching r".*@trustedcorp\.com"});
            }
        "#,
        );
        assert_eq!(prog.declarations.len(), 3);
        assert!(matches!(
            prog.declarations[0].kind,
            DeclarationKind::Let(_)
        ));
        assert!(matches!(
            prog.declarations[1].kind,
            DeclarationKind::ToolShorthand(_)
        ));
        assert!(matches!(
            prog.declarations[2].kind,
            DeclarationKind::Tool(_)
        ));
    }

    #[test]
    fn test_pii_protection_example() {
        let prog = parse_ok(
            r#"
            tool r"get_.*_records" -> @tags |= {"pii"};

            tool r"send_to_external_.*" {
                must deny when @args.tags overlaps {"pii"};
            }
        "#,
        );
        assert_eq!(prog.declarations.len(), 2);
    }

    #[test]
    fn test_refund_workflow_example() {
        let prog = parse_ok(
            r#"
            tool "request_refund_approval" {
                session after {
                    @tags |= {"refund_pending"};
                }
            }

            tool "issue_refund" {
                hard deny when not (@session.tags overlaps {"refund_approved"});
            }
        "#,
        );
        assert_eq!(prog.declarations.len(), 2);
    }

    #[test]
    fn test_full_complex_tool() {
        let prog = parse_ok(
            r#"
            /// Full example with all features
            tool "complex_tool" {
                priority 5;

                hard deny when @args.tags overlaps {"blocked"};
                should allow when body.tags subset of {"safe", "public"};
                soft deny always;

                result {
                    @tags |= {"processed"};
                    @producers |= {"complex_tool_v2"};
                    @consumers &= {"authorized_users"};
                }

                session before {
                    @tags |= {"in_progress"};
                }

                session after {
                    @tags |= {"completed"};
                }
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                assert_eq!(tool.priority, Some(5));
                assert_eq!(tool.checks.len(), 3);
                assert!(tool.result_block.is_some());
                assert_eq!(tool.result_block.as_ref().unwrap().len(), 3);
                assert!(tool.session_before.is_some());
                assert!(tool.session_after.is_some());
            }
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    // ============================================================
    // Additional Edge Cases
    // ============================================================

    #[test]
    fn test_predicate_double_not() {
        // `not not X` should produce Not(Not(X))
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when not not body.tags is empty;
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Not(inner)) => match inner.as_ref() {
                    Predicate::Not(inner2) => match inner2.as_ref() {
                        Predicate::Comparison(Comparison::SetIsEmpty(_)) => {}
                        other => panic!("Expected SetIsEmpty inside double not, got {:?}", other),
                    },
                    other => panic!("Expected inner Not, got {:?}", other),
                },
                other => panic!("Expected outer Not, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_predicate_not_combined_with_and() {
        // `not A and B` should parse as `(not A) and B` since not binds tighter
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when not body.tags is empty and @session.tags overlaps {"active"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::And(left, _right)) => match left.as_ref() {
                    Predicate::Not(_) => {}
                    other => panic!("Expected left side to be Not, got {:?}", other),
                },
                other => panic!("Expected And at top level, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_result_conditional() {
        let prog = parse_ok(
            r#"
            tool "my_tool" {
                result {
                    when body.tags overlaps {"sensitive"} {
                        @tags |= {"needs_review"};
                        @consumers &= {"admin"};
                    }
                }
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                let result_block = tool.result_block.as_ref().unwrap();
                assert_eq!(result_block.len(), 1);
                match &result_block[0] {
                    MetadataStmt::Conditional {
                        condition,
                        updates,
                    } => {
                        assert!(matches!(condition, Predicate::Comparison(_)));
                        assert_eq!(updates.len(), 2);
                    }
                    other => panic!("Expected conditional, got {:?}", other),
                }
            }
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_set_superset_of() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must allow when body.tags superset of {"safe"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetSupersetOf { .. })) => {}
                other => panic!("Expected SetSupersetOf, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_set_equals() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when body.tags == {"exactly_this"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetEquals { .. })) => {}
                other => panic!("Expected SetEquals, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_aggregation_syntax() {
        let prog = parse_ok(
            r#"
            tool "test" {
                must deny when union of tags from args overlaps {"confidential"};
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => match &tool.checks[0].condition {
                Condition::When(Predicate::Comparison(Comparison::SetOverlaps {
                    left,
                    ..
                })) => {
                    assert_eq!(
                        *left,
                        SetOperand::Aggregation {
                            op: AggregationOp::Union,
                            field: MetaFieldKind::Tags,
                        }
                    );
                }
                other => panic!("Expected overlaps with aggregation, got {:?}", other),
            },
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_escaped_strings() {
        let prog = parse_ok(r#"let paths = {"path\\to\\file", "line\nnext"};"#);
        match &prog.declarations[0].kind {
            DeclarationKind::Let(LetDecl { value, .. }) => match value {
                Expression::SetExpr(SetExpr::Literal(elems)) => {
                    assert_eq!(elems[0], SetElement::String("path\\to\\file".to_string()));
                    assert_eq!(elems[1], SetElement::String("line\nnext".to_string()));
                }
                other => panic!("Expected set literal, got {:?}", other),
            },
            other => panic!("Expected let, got {:?}", other),
        }
    }

    #[test]
    fn test_multiple_declarations() {
        let prog = parse_ok(
            r#"
            let a = {"x"};
            let b = {"y"};
            tool "t1" -> @tags |= a;
            tool "t2" -> @tags |= b;
            tool "t3" {
                must deny always;
            }
        "#,
        );
        assert_eq!(prog.declarations.len(), 5);
        assert!(matches!(
            prog.declarations[0].kind,
            DeclarationKind::Let(_)
        ));
        assert!(matches!(
            prog.declarations[1].kind,
            DeclarationKind::Let(_)
        ));
        assert!(matches!(
            prog.declarations[2].kind,
            DeclarationKind::ToolShorthand(_)
        ));
        assert!(matches!(
            prog.declarations[3].kind,
            DeclarationKind::ToolShorthand(_)
        ));
        assert!(matches!(
            prog.declarations[4].kind,
            DeclarationKind::Tool(_)
        ));
    }

    #[test]
    fn test_update_target_arg_field() {
        let prog = parse_ok(
            r#"
            tool "test" {
                result {
                    body.tags |= {"annotated"};
                }
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                let result_block = tool.result_block.as_ref().unwrap();
                match &result_block[0] {
                    MetadataStmt::Update(u) => {
                        assert_eq!(u.target, MetadataTarget::Arg("body".to_string()));
                        assert_eq!(u.field, MetaFieldKind::Tags);
                    }
                    other => panic!("Expected update, got {:?}", other),
                }
            }
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    #[test]
    fn test_all_augmented_assign_ops() {
        let prog = parse_ok(
            r#"
            tool "test" {
                result {
                    @tags |= {"a"};
                    @tags &= {"b"};
                    @tags -= {"c"};
                    @tags ^= {"d"};
                    @tags = {"e"};
                }
            }
        "#,
        );
        match &prog.declarations[0].kind {
            DeclarationKind::Tool(tool) => {
                let result_block = tool.result_block.as_ref().unwrap();
                assert_eq!(result_block.len(), 5);
                let ops: Vec<MetaUpdateOp> = result_block
                    .iter()
                    .map(|s| match s {
                        MetadataStmt::Update(u) => u.op,
                        _ => panic!("Expected update"),
                    })
                    .collect();
                assert_eq!(
                    ops,
                    vec![
                        MetaUpdateOp::UnionAssign,
                        MetaUpdateOp::IntersectAssign,
                        MetaUpdateOp::MinusAssign,
                        MetaUpdateOp::XorAssign,
                        MetaUpdateOp::Assign,
                    ]
                );
            }
            other => panic!("Expected tool, got {:?}", other),
        }
    }

    // ============================================================
    // Error Cases
    // ============================================================

    #[test]
    fn test_missing_semicolon() {
        parse_err(r#"let x = {"a"}"#);
    }

    #[test]
    fn test_unclosed_brace() {
        parse_err(r#"tool "test" { must allow always;"#);
    }

    #[test]
    fn test_invalid_enforcement() {
        parse_err(
            r#"
            tool "test" {
                maybe allow always;
            }
        "#,
        );
    }

    // ============================================================
    // Serialization Roundtrip
    // ============================================================

    #[test]
    fn test_ast_serialization_roundtrip() {
        let prog = parse_ok(
            r#"
            let tags = {"a", "b"};
            tool "my_tool" -> @tags |= tags;
        "#,
        );
        let json = serde_json::to_string(&prog).unwrap();
        let deserialized: SqrtProgram = serde_json::from_str(&json).unwrap();
        assert_eq!(prog, deserialized);
    }
}
