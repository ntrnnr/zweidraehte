//! Preparation and execution use the same concrete evidence reads.
use crate::commissioning::error::Diagnostic;
use crate::commissioning::procedure::LoadControlCause;
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::TransferContext;
use crate::commissioning::runtime::commissioner::CommissioningObserver;
use crate::commissioning::runtime::prepared::{BoundRead, ReadExpectation};

/// Capture once, then require the same bytes or absence before mutation.
/// Only an explicit resource-not-found response proves absence.
pub(in crate::commissioning) async fn read_bound_evidence(
    session: &mut ExecutionSession<'_>,
    reads: &mut [BoundRead],
    observer: &impl CommissioningObserver,
) -> std::result::Result<(), Diagnostic> {
    if reads.is_empty() {
        return Ok(());
    }
    let cancelled = || {
        if observer.cancelled() {
            Err(Diagnostic::new("commissioning was cancelled during evidence validation"))
        } else {
            Ok(())
        }
    };
    cancelled()?;
    session.connect().await?;
    let result = async {
        for read in reads {
            cancelled()?;
            let value = match session.read(&read.service.target, read.service.extent, TransferContext::Public).await {
                Ok(value) => Some(value),
                Err(error)
                    if error.load_control_cause == Some(LoadControlCause::ResourceNotFound)
                        && matches!(
                            read.expected,
                            ReadExpectation::Capture { optional: true } | ReadExpectation::Exact(None)
                        ) =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
            cancelled()?;
            if value.as_ref().is_some_and(|value| value.len() != read.service.extent.byte_length as usize) {
                return Err(Diagnostic::new(format!("evidence resource {} returned an invalid width", read.resource)));
            }
            if let ReadExpectation::Exact(expected) = &read.expected
                && value != *expected
            {
                return Err(Diagnostic::new(format!(
                    "evidence resource {} changed from its required value or presence; prepare commissioning again",
                    read.resource
                )));
            }
            read.expected = ReadExpectation::Exact(value);
        }
        Ok(())
    }
    .await;
    session.finish(result).await
}
