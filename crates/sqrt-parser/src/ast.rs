//! SQRT Abstract Syntax Tree types.
//!
//! These types represent the parsed structure of an SQRT policy program.
//! The parser converts pest parse pairs into this typed AST.

use serde::{Deserialize, Serialize};

/// Source location information for error reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

/// A complete SQRT program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqrtProgram {
    pub declarations: Vec<Declaration>,
}

/// Top-level declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Declaration {
    pub doc_comment: Option<String>,
    pub kind: DeclarationKind,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeclarationKind {
    Let(LetDecl),
    Tool(ToolDecl),
    ToolShorthand(ToolShorthandDecl),
}

// ============================================================
// Let Declarations
// ============================================================

/// `let name = expression;`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LetDecl {
    pub name: String,
    pub value: Expression,
}

/// The value assigned by a `let` declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expression {
    Predicate(Predicate),
    SetExpr(SetExpr),
    TypeDomain(TypeDomain),
}

// ============================================================
// Tool Declarations (Full Form)
// ============================================================

/// `tool "name" { ... }`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDecl {
    pub id: ToolId,
    pub priority: Option<i64>,
    pub checks: Vec<CheckRule>,
    pub result_block: Option<Vec<MetadataStmt>>,
    pub session_before: Option<Vec<MetadataStmt>>,
    pub session_after: Option<Vec<MetadataStmt>>,
}

/// Tool identifier — exact string or regex pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolId {
    Exact(String),
    Regex(String),
}

// ============================================================
// Tool Shorthand
// ============================================================

/// `tool "name" [priority] -> [target] @field op value [when cond];`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolShorthandDecl {
    pub id: ToolId,
    pub priority: Option<i64>,
    pub target: UpdateTarget,
    pub update: MetadataUpdate,
    pub condition: Option<Predicate>,
}

// ============================================================
// Check Rules
// ============================================================

/// `must deny when condition;` or `should allow always;`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckRule {
    pub enforcement: Enforcement,
    pub outcome: Outcome,
    pub condition: Condition,
    pub doc_comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Enforcement {
    /// `must` / `hard` — cannot be overridden
    Must,
    /// `should` / `soft` — can be overridden by higher-priority rules
    Should,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Condition {
    Always,
    When(Predicate),
}

// ============================================================
// Metadata Updates (used in result/session blocks and shorthand)
// ============================================================

/// A single metadata update statement, possibly conditional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetadataStmt {
    /// `@tags |= {"new"};`
    Update(MetadataUpdate),
    /// `when condition { ... }`
    Conditional {
        condition: Predicate,
        updates: Vec<MetadataUpdate>,
    },
}

/// A metadata update operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetadataUpdate {
    pub target: MetadataTarget,
    pub field: MetaFieldKind,
    pub op: MetaUpdateOp,
    pub value: SetExpr,
}

/// Where the metadata update applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataTarget {
    /// `@tags` — context-dependent (result or session based on block)
    Contextual,
    /// `@result.tags`
    Result,
    /// `@session.tags`
    Session,
    /// `arg_name.tags`
    Arg(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaFieldKind {
    Tags,
    Producers,
    Consumers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaUpdateOp {
    /// `=`
    Assign,
    /// `|=`
    UnionAssign,
    /// `&=`
    IntersectAssign,
    /// `-=`
    MinusAssign,
    /// `^=`
    XorAssign,
}

/// Shorthand target — where the shorthand update applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateTarget {
    Result,
    Session,
    SessionBefore,
    SessionAfter,
}

// ============================================================
// Predicates (Boolean Expressions)
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Predicate {
    /// `a or b`
    Or(Box<Predicate>, Box<Predicate>),
    /// `a and b`
    And(Box<Predicate>, Box<Predicate>),
    /// `not a`
    Not(Box<Predicate>),
    /// Reference to a `let`-declared predicate
    Ref(String),
    /// A comparison (value or set)
    Comparison(Comparison),
}

// ============================================================
// Comparisons
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Comparison {
    // Value comparisons
    /// `arg.value in {"a", "b"}`
    ValueIn {
        operand: ValueOperand,
        set: SetExpr,
    },
    /// `arg.value == "literal"`
    ValueEquals {
        left: ValueOperand,
        right: ValueOperand,
    },

    // Set comparisons
    /// `A overlaps B`
    SetOverlaps {
        left: SetOperand,
        right: SetExpr,
    },
    /// `A subset of B`
    SetSubsetOf {
        left: SetOperand,
        right: SetExpr,
    },
    /// `A superset of B`
    SetSupersetOf {
        left: SetOperand,
        right: SetExpr,
    },
    /// `A == B`
    SetEquals {
        left: SetOperand,
        right: SetExpr,
    },
    /// `A is empty`
    SetIsEmpty(SetOperand),
    /// `A is universal`
    SetIsUniversal(SetOperand),
}

// ============================================================
// Set Expressions
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SetExpr {
    /// `{"a", "b"}` or `{}`
    Literal(Vec<SetElement>),

    /// Metadata field access (e.g., `arg.tags`, `@result.producers`)
    Operand(SetOperand),

    /// Reference to a `let`-declared set
    Ref(String),

    /// Binary set operations
    Union(Box<SetExpr>, Box<SetExpr>),
    Intersect(Box<SetExpr>, Box<SetExpr>),
    Minus(Box<SetExpr>, Box<SetExpr>),
    Xor(Box<SetExpr>, Box<SetExpr>),

    /// Element operations
    With(Box<SetExpr>, SetElement),
    Without(Box<SetExpr>, SetElement),
}

/// An element within a set literal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SetElement {
    /// `"exact string"`
    String(String),
    /// `r"regex pattern"`
    Regex(String),
    /// `w"wildcard*pattern"`
    Wildcard(String),
    /// A type domain constraint (e.g., `int 1..100`)
    TypeDomain(TypeDomain),
    /// A numeric value
    Number(NumberValue),
}

// ============================================================
// Set Operands (Metadata Accessors)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetOperand {
    /// `arg_name.tags`
    ArgField { arg_name: String, field: MetaFieldKind },
    /// `@result.tags`
    ResultField(MetaFieldKind),
    /// `@session.tags`
    SessionField(MetaFieldKind),
    /// `@tags` (context-dependent)
    ContextField(MetaFieldKind),
    /// `@args.tags` or `@args.tags.union` or `@args.tags.intersect`
    ArgsField { field: MetaFieldKind, agg: AggregationOp },
    /// `union of tags from args`
    Aggregation { op: AggregationOp, field: MetaFieldKind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationOp {
    Union,
    Intersect,
}

// ============================================================
// Value Operands
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValueOperand {
    /// `arg_name.value`
    ArgValue(String),
    /// `@result.value`
    ResultValue,
    /// `@session.value`
    SessionValue,
    /// A literal value
    Literal(LiteralValue),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LiteralValue {
    String(String),
    Datetime(String),
    Number(NumberValue),
    Bool(bool),
}

// ============================================================
// Type Domains (Value Constraints)
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypeDomain {
    Bool(bool),
    Int(RangeSpec<NumberValue>),
    Float(RangeSpec<NumberValue>),
    Str {
        pattern: StringPattern,
        length: Option<RangeSpec<NumberValue>>,
    },
    Datetime(DatetimeSpec),
}

/// Range specification — used for int, float, and string length domains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RangeSpec<T> {
    /// Exact value: `42`
    Exact(T),
    /// `a..b` (both inclusive)
    Inclusive { min: T, max: T },
    /// `a<..<b` (both exclusive)
    ExclusiveBoth { min: T, max: T },
    /// `a<..b` (min exclusive, max inclusive)
    ExclusiveLeft { min: T, max: T },
    /// `a..<b` (min inclusive, max exclusive)
    ExclusiveRight { min: T, max: T },
    /// `..b` (up to, inclusive)
    To(T),
    /// `..<b` (up to, exclusive)
    ToExclusive(T),
    /// `a..` (from, inclusive)
    From(T),
    /// `a<..` (from, exclusive)
    FromExclusive(T),
}

/// String matching pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringPattern {
    /// `"exact"` — exact string match
    Exact(String),
    /// `matching r"pattern"` — regex match
    Matching(String),
    /// `like w"glob*"` — wildcard/glob match
    Like(String),
}

/// Datetime specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DatetimeSpec {
    /// Exact datetime: `d"2023-10-01T00:00:00Z"`
    Exact(String),
    /// Datetime from a plain string
    String(String),
    /// Epoch timestamp
    Epoch(NumberValue),
    /// Range of datetimes (reuse RangeSpec with String)
    Range(RangeSpec<String>),
}

// ============================================================
// Number Values
// ============================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NumberValue {
    Int(i64),
    Float(f64),
    PosInf,
    NegInf,
}
