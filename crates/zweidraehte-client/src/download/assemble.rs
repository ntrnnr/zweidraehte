//! Assembling a runnable procedure out of the mask and product layers.
//!
//! ETS composes a download procedure differently per management model,
//! and the two shapes are genuinely different rather than variations
//! on a theme:
//!
//! - **System 7 / BIM M112** — the master data carries *only* an
//!   `Unload` template. The Load procedure is wholly product-supplied
//!   (`LoadProcedureStyle="ProductProcedure"`), because its absolute
//!   segment addresses only exist in the product database. Assembly is
//!   therefore: take the product's procedure as-is.
//! - **System B** — the master data carries complete Load templates
//!   with `LdCtrlMerge` splice points, and the product contributes
//!   fragments tagged with matching `MergeId`s
//!   (`LoadProcedureStyle="MergedProcedure"`). Assembly splices the
//!   fragments into the template.
//!
//! Merge resolution happens here, at assembly time — never at run
//! time. The interpreter refuses `LdCtrlMerge` outright, so an
//! unresolved splice point is a loud failure rather than a silently
//! skipped step.

use zweidraehte_knxprod::schema::LoadControl;

use super::ir::{Instruction, controls_to_instructions};
use super::mask::MaskData;
use super::product::ProductData;
use crate::error::{Error, Result};

/// Which procedure to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureKind {
    /// Everything: tables, application, parameters.
    LoadAll,
    /// Tear the device's configuration down.
    UnloadAll,
}

impl ProcedureKind {
    fn master_data_key(self) -> (&'static str, &'static str) {
        match self {
            Self::LoadAll => ("Load", "all"),
            Self::UnloadAll => ("Unload", "all"),
        }
    }
}

/// Build the instruction stream for `kind` from the two upper layers.
pub fn assemble(mask: &MaskData<'_>, product: &ProductData, kind: ProcedureKind) -> Result<Vec<Instruction>> {
    let controls = assemble_controls(mask, product, kind)?;
    controls_to_instructions(&controls, product.task_identity)
}

/// The same, stopping at the resolved control stream — useful for
/// tests and diagnostics that want to see the assembly result before
/// it is lowered to IR.
pub fn assemble_controls(mask: &MaskData<'_>, product: &ProductData, kind: ProcedureKind) -> Result<Vec<LoadControl>> {
    let (procedure_type, sub_type) = kind.master_data_key();

    // A product procedure replaces the mask's Load template outright.
    // (Unload always comes from the mask: tearing down needs no
    // product knowledge.)
    if kind == ProcedureKind::LoadAll
        && product.load_procedure_style == crate::download::product::LoadProcedureStyle::Product
        && let Some(controls) = product.product_procedure()
    {
        return Ok(controls.to_vec());
    }

    let template = mask.procedure(procedure_type, sub_type).ok_or_else(|| {
        Error::DownloadAssembly(format!(
            "mask {} defines no {procedure_type}/{sub_type} procedure, and the product supplies none either",
            mask.version()
        ))
    })?;

    splice_merges(&template.controls, product)
}

/// Replace every `LdCtrlMerge` with the product fragment carrying that
/// `MergeId`.
///
/// A merge point with no matching fragment is *not* an error: the mask
/// template offers splice points for optional product content (a
/// product with no parameter segment contributes no fragment for the
/// parameter merge), and ETS simply emits nothing there. A fragment
/// with no matching splice point, on the other hand, means the product
/// and the mask disagree — worth reporting, but only after the whole
/// template has been walked.
fn splice_merges(template: &[LoadControl], product: &ProductData) -> Result<Vec<LoadControl>> {
    let mut out = Vec::with_capacity(template.len());
    let mut spliced = Vec::new();

    for control in template {
        match control {
            LoadControl::LdCtrlMerge(merge) => {
                if let Some(fragment) = product.merge_fragment(merge.merge_id) {
                    // Fragments are flat streams; nested merges are
                    // not a thing in the published templates.
                    for inner in fragment {
                        if let LoadControl::LdCtrlMerge(nested) = inner {
                            return Err(Error::DownloadAssembly(format!(
                                "product fragment for merge {} contains a nested merge {}",
                                merge.merge_id, nested.merge_id
                            )));
                        }
                        out.push(inner.clone());
                    }
                    spliced.push(merge.merge_id);
                }
            }
            other => out.push(other.clone()),
        }
    }

    let orphaned: Vec<u8> =
        product.load_procedures.iter().filter_map(|p| p.merge_id).filter(|id| !spliced.contains(id)).collect();
    if !orphaned.is_empty() {
        return Err(Error::DownloadAssembly(format!(
            "product declares merge fragments {orphaned:?} that the mask template has no splice point for"
        )));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_knxprod::MasterData;
    use zweidraehte_knxprod::schema::{LdCtrlMerge, LdCtrlRestart, LoadProcedure};
    use zweidraehte_proto::device::MaskVersion;
    use zweidraehte_proto::messages::apdu::load_control::LoadEvent;

    use crate::download::mask::MaskDb;

    fn system7_product() -> ProductData {
        ProductData::from_mtxml_str(crate::download::product::tests::SYSTEM7_MTXML).expect("fixture parses")
    }

    #[test]
    fn system7_load_comes_from_the_product() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let product = system7_product();

        let instructions = assemble(&mask, &product, ProcedureKind::LoadAll).expect("assembles");

        // The mask has no Load template at all — everything here came
        // from the product file.
        assert!(mask.procedure("Load", "all").is_none());
        assert_eq!(instructions.first(), Some(&Instruction::Connect));
        assert!(instructions.iter().any(|i| matches!(i, Instruction::CompareProperty { prop_id: 78, .. })));
        assert!(instructions.iter().any(|i| matches!(i, Instruction::AbsSegment { .. })));
        assert_eq!(instructions.last(), Some(&Instruction::Disconnect));
    }

    #[test]
    fn system7_unload_comes_from_the_mask() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let product = system7_product();

        let instructions = assemble(&mask, &product, ProcedureKind::UnloadAll).expect("assembles");
        assert_eq!(instructions, vec![
            Instruction::Connect,
            Instruction::LsmEvent { lsm: 1, event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: 2, event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: 3, event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: 4, event: LoadEvent::Unload },
            Instruction::Disconnect,
        ]);
    }

    /// A mask template whose merge points get product fragments
    /// spliced in — the System B shape, in miniature.
    const MERGED_MASK: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="1">
    <MaskVersions>
      <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlMerge MergeId="1" />
              <LdCtrlUnload LsmIdx="3" />
              <LdCtrlMerge MergeId="4" />
              <LdCtrlRestart />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

    fn merged_mask_db() -> MaskDb {
        MaskDb::from_str(MERGED_MASK).expect("fixture")
    }

    fn product_with_fragments(fragments: Vec<LoadProcedure>) -> ProductData {
        ProductData {
            load_procedure_style: crate::download::product::LoadProcedureStyle::Merged,
            load_procedures: fragments,
            ..Default::default()
        }
    }

    #[test]
    fn merge_points_take_product_fragments() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(vec![LoadProcedure {
            merge_id: Some(1),
            controls: vec![LoadControl::LdCtrlRestart(LdCtrlRestart {})],
        }]);

        let controls = assemble_controls(&mask, &product, ProcedureKind::LoadAll).expect("assembles");

        // Merge 1 became the fragment's Restart; merge 4 had no
        // fragment and vanished.
        assert_eq!(controls.len(), 4);
        assert!(matches!(controls[0], LoadControl::LdCtrlConnect(_)));
        assert!(matches!(controls[1], LoadControl::LdCtrlRestart(_)), "fragment spliced in");
        assert!(matches!(controls[2], LoadControl::LdCtrlUnload(_)));
        assert!(matches!(controls[3], LoadControl::LdCtrlRestart(_)));
        assert!(
            !controls.iter().any(|c| matches!(c, LoadControl::LdCtrlMerge(_))),
            "no merge point may survive assembly"
        );
    }

    #[test]
    fn a_fragment_the_template_cannot_place_is_an_error() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        // MergeId 7 has no splice point in this template.
        let product = product_with_fragments(vec![LoadProcedure {
            merge_id: Some(7),
            controls: vec![LoadControl::LdCtrlRestart(LdCtrlRestart {})],
        }]);

        assert!(matches!(assemble_controls(&mask, &product, ProcedureKind::LoadAll), Err(Error::DownloadAssembly(_))));
    }

    #[test]
    fn nested_merges_are_rejected() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(vec![LoadProcedure {
            merge_id: Some(1),
            controls: vec![LoadControl::LdCtrlMerge(LdCtrlMerge { merge_id: 4 })],
        }]);

        assert!(matches!(assemble_controls(&mask, &product, ProcedureKind::LoadAll), Err(Error::DownloadAssembly(_))));
    }

    #[test]
    fn a_missing_template_names_the_mask() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        // A product that supplies no procedure of its own leaves the
        // System 7 Load with nowhere to come from.
        let product = ProductData::default();

        let err = assemble_controls(&mask, &product, ProcedureKind::LoadAll).expect_err("no source");
        assert!(matches!(err, Error::DownloadAssembly(ref m) if m.contains("Load/all")));
    }

    /// Guard for the `MasterData` import used by the fixtures above.
    #[test]
    fn fixtures_are_well_formed_master_data() {
        let _: MasterData = MERGED_MASK.parse().expect("merged fixture");
    }
}
