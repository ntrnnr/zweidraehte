//! Resolve reference security cursors before final control filtering.
//!
//! Native insertion pointers retain integer positions. Inserting the unload
//! does not relocate a separately captured reload pointer. Resolve both source
//! positions while omitted controls still exist, then map them to output steps.

use super::{LifecycleAnchor, ProcedureLowerer};
use crate::commissioning::compiler::features::ProcedureCompilationPhase;
use zweidraehte_ets_files::schema::LoadControl;

#[cfg(test)]
mod tests;

impl ProcedureLowerer<'_> {
    pub(super) fn security_cursor_anchors(&self) -> (Vec<LifecycleAnchor>, bool) {
        use ProcedureCompilationPhase::{NativeSecurityLoad, NativeSecurityUnload};

        let source = &self.selected_boundaries;
        if source.is_empty() {
            return (Vec::new(), false);
        }

        // Each fallback has its own priority. A later disconnect does not
        // replace an earlier restart, and reset codes other than one do not
        // provide this insertion boundary.
        let before_reload = source
            .iter()
            .position(|boundary| matches!(boundary.control, LoadControl::LdCtrlLoadCompleted(_)))
            .or_else(|| source.iter().rposition(|boundary| matches!(boundary.control, LoadControl::LdCtrlRestart(_))))
            .or_else(|| {
                source.iter().rposition(|boundary| {
                    matches!(boundary.control,
                LoadControl::LdCtrlMasterReset(reset) if reset.erase_code == 1)
                })
            })
            .or_else(|| {
                source.iter().rposition(|boundary| matches!(boundary.control, LoadControl::LdCtrlDisconnect(_)))
            })
            .unwrap_or(source.len());
        let last_unload = source.iter().rposition(|boundary| matches!(boundary.control, LoadControl::LdCtrlUnload(_)));
        let unload_cursor = last_unload.map_or(before_reload, |index| index + 1);

        // A strictly earlier insertion consumes one slot before the captured
        // integer. Equal offsets instead put reload before the inserted unload.
        // With no authored unload the native pointers alias, so its Advance
        // keeps unload before reload at the original source boundary.
        let reload_cursor = before_reload - usize::from(last_unload.is_some() && unload_cursor < before_reload);
        let block_precedes_unload = last_unload.is_some() && before_reload <= unload_cursor;
        let anchor = |index: usize, phase| {
            if let Some(boundary) = source.get(index) {
                LifecycleAnchor {
                    phase,
                    position: boundary.position,
                    path: boundary.path.clone(),
                    session: boundary.session.clone(),
                }
            } else {
                LifecycleAnchor {
                    phase,
                    position: self.parsed.program.steps.len(),
                    path: self.parsed.root.clone(),
                    session: self.sessions.last().cloned(),
                }
            }
        };

        (
            vec![anchor(unload_cursor, NativeSecurityUnload), anchor(reload_cursor, NativeSecurityLoad)],
            block_precedes_unload,
        )
    }
}
