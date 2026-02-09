//! Metadata update resolution and application.
//!
//! Resolves `MetadataStmt` AST nodes into concrete `ResolvedUpdate` values
//! by evaluating set expressions and conditions. Also provides the function
//! to apply resolved updates to a `Metadata` instance.

use security_compass_meta::Metadata;
use sqrt_parser::{MetaFieldKind, MetaUpdateOp, MetadataStmt};

use crate::context::EvalContext;
use crate::error::EvalError;
use crate::predicate_eval::eval_predicate;
use crate::set_eval::eval_set_expr;
use crate::types::ResolvedUpdate;

/// Resolve a list of metadata statements into concrete updates.
///
/// Each `MetadataStmt` is either an unconditional update or a conditional
/// block (`when pred { updates }`). Conditional blocks are evaluated:
/// if the predicate is true, their inner updates are included.
///
/// Returns a flat list of `ResolvedUpdate` values ready to be applied.
pub(crate) fn resolve_metadata_stmts(
    stmts: &[MetadataStmt],
    ctx: &EvalContext<'_>,
) -> Result<Vec<ResolvedUpdate>, EvalError> {
    let mut resolved = Vec::new();

    for stmt in stmts {
        match stmt {
            MetadataStmt::Update(update) => {
                let field_value = eval_set_expr(&update.value, ctx)?;
                resolved.push(ResolvedUpdate {
                    field: update.field,
                    op: update.op,
                    string_set: field_value.as_string_set().clone(),
                    consumer_set: field_value.as_consumer_set(),
                });
            }

            MetadataStmt::Conditional { condition, updates } => {
                if eval_predicate(condition, ctx)? {
                    for update in updates {
                        let field_value = eval_set_expr(&update.value, ctx)?;
                        resolved.push(ResolvedUpdate {
                            field: update.field,
                            op: update.op,
                            string_set: field_value.as_string_set().clone(),
                            consumer_set: field_value.as_consumer_set(),
                        });
                    }
                }
            }
        }
    }

    Ok(resolved)
}

/// Apply a resolved metadata update to a `Metadata` instance.
///
/// Dispatches on field kind × operation, using the appropriate augmented
/// assignment methods from `security-compass-meta`.
pub fn apply_update(meta: &mut Metadata, update: &ResolvedUpdate) {
    match (&update.field, &update.op) {
        // ---- Tags ----
        (MetaFieldKind::Tags, MetaUpdateOp::Assign) => {
            meta.tags = update.string_set.clone();
        }
        (MetaFieldKind::Tags, MetaUpdateOp::UnionAssign) => {
            meta.tags_union_assign(&update.string_set);
        }
        (MetaFieldKind::Tags, MetaUpdateOp::IntersectAssign) => {
            meta.tags_intersect_assign(&update.string_set);
        }
        (MetaFieldKind::Tags, MetaUpdateOp::MinusAssign) => {
            meta.tags_difference_assign(&update.string_set);
        }
        (MetaFieldKind::Tags, MetaUpdateOp::XorAssign) => {
            meta.tags_xor_assign(&update.string_set);
        }

        // ---- Producers ----
        (MetaFieldKind::Producers, MetaUpdateOp::Assign) => {
            meta.producers = update.string_set.clone();
        }
        (MetaFieldKind::Producers, MetaUpdateOp::UnionAssign) => {
            meta.producers_union_assign(&update.string_set);
        }
        (MetaFieldKind::Producers, MetaUpdateOp::IntersectAssign) => {
            meta.producers_intersect_assign(&update.string_set);
        }
        (MetaFieldKind::Producers, MetaUpdateOp::MinusAssign) => {
            meta.producers_difference_assign(&update.string_set);
        }
        (MetaFieldKind::Producers, MetaUpdateOp::XorAssign) => {
            meta.producers_xor_assign(&update.string_set);
        }

        // ---- Consumers ----
        (MetaFieldKind::Consumers, MetaUpdateOp::Assign) => {
            meta.consumers = update.consumer_set.clone();
        }
        (MetaFieldKind::Consumers, MetaUpdateOp::UnionAssign) => {
            meta.consumers_union_assign(&update.consumer_set);
        }
        (MetaFieldKind::Consumers, MetaUpdateOp::IntersectAssign) => {
            meta.consumers_intersect_assign(&update.consumer_set);
        }
        (MetaFieldKind::Consumers, MetaUpdateOp::MinusAssign) => {
            meta.consumers_difference_assign(&update.consumer_set);
        }
        (MetaFieldKind::Consumers, MetaUpdateOp::XorAssign) => {
            meta.consumers_xor_assign(&update.consumer_set);
        }
    }
}

/// Apply a list of resolved updates to a metadata instance in order.
pub fn apply_updates(meta: &mut Metadata, updates: &[ResolvedUpdate]) {
    for update in updates {
        apply_update(meta, update);
    }
}
