//! Assembling a runnable procedure out of the mask and product layers.
//!
//! ETS composes a download procedure differently per management model,
//! and the two shapes are genuinely different rather than variations
//! on a theme:
//!
//! - **System 7** — the master data carries *only* an
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

/// Semantic part of an already-deployed application that needs updating.
///
/// This is deliberately independent of mask procedure names. The selector
/// below maps it onto the smallest remote procedure the actual device mask
/// offers and uses [`DownloadScope::Full`] when no safe partial procedure is
/// available.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DownloadScope {
    #[default]
    Full,
    Parameters,
    GroupCommunication,
    ParametersAndGroupCommunication,
}

impl DownloadScope {
    pub fn includes_group_communication(self) -> bool {
        matches!(self, Self::Full | Self::GroupCommunication | Self::ParametersAndGroupCommunication)
    }
}

/// Which procedure to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureKind {
    /// Program one application and its tables/parameters.
    ///
    /// System B calls this mask procedure `Load/ap1`. Masks without that
    /// specialised procedure expose their ordinary application download as
    /// `Load/all`, which is the compatible fallback.
    LoadApplication,
    /// Everything, including Application Program 2 where the product
    /// supplies one.
    LoadAll,
    /// Rewrite application parameters without replacing group tables.
    LoadParameters,
    /// Rewrite address, association, Group Object, and security tables.
    LoadGroupCommunication,
    /// Rewrite both parameter and group-communication configuration.
    LoadParametersAndGroupCommunication,
    /// Tear the device's configuration down.
    UnloadAll,
}

impl ProcedureKind {
    fn master_data_key(self) -> (&'static str, &'static str) {
        match self {
            Self::LoadApplication => ("Load", "ap1"),
            Self::LoadAll => ("Load", "all"),
            Self::LoadParameters => ("Load", "par"),
            Self::LoadGroupCommunication => ("Load", "grp"),
            Self::LoadParametersAndGroupCommunication => ("Load", "par,grp"),
            Self::UnloadAll => ("Unload", "all"),
        }
    }

    pub fn scope(self) -> DownloadScope {
        match self {
            Self::LoadApplication | Self::LoadAll | Self::UnloadAll => DownloadScope::Full,
            Self::LoadParameters => DownloadScope::Parameters,
            Self::LoadGroupCommunication => DownloadScope::GroupCommunication,
            Self::LoadParametersAndGroupCommunication => DownloadScope::ParametersAndGroupCommunication,
        }
    }

    fn is_full_load(self) -> bool {
        matches!(self, Self::LoadApplication | Self::LoadAll)
    }

    fn fragment_selector(self) -> &'static str {
        match self {
            Self::LoadParameters | Self::LoadParametersAndGroupCommunication => "par",
            Self::LoadGroupCommunication => "grp",
            Self::LoadApplication | Self::LoadAll | Self::UnloadAll => "full",
        }
    }
}

/// Select the smallest remote procedure which covers `requested`.
///
/// The choice is capability-based, not family-based. For example BCU2 only
/// offers `par,grp`, so either kind of change uses that safe superset, while
/// System B can keep the two scopes separate. Product-owned procedures (the
/// current System 7 form) have no partial entry point and therefore retain
/// the full application flow.
pub fn procedure_kind_for_scope(mask: &MaskData<'_>, product: &ProductData, requested: DownloadScope) -> ProcedureKind {
    let available = |kind: ProcedureKind| {
        let (procedure_type, sub_type) = kind.master_data_key();
        mask.procedure(procedure_type, sub_type).is_some_and(|procedure| procedure.allows_remote())
    };
    let partial = match requested {
        DownloadScope::Parameters => {
            [Some(ProcedureKind::LoadParameters), Some(ProcedureKind::LoadParametersAndGroupCommunication)]
        }
        DownloadScope::GroupCommunication => {
            [Some(ProcedureKind::LoadGroupCommunication), Some(ProcedureKind::LoadParametersAndGroupCommunication)]
        }
        DownloadScope::ParametersAndGroupCommunication => {
            [Some(ProcedureKind::LoadParametersAndGroupCommunication), None]
        }
        DownloadScope::Full => [None, None],
    };
    if let Some(kind) = partial.into_iter().flatten().find(|kind| available(*kind)) {
        return kind;
    }

    if product.load_procedure_style == crate::download::product::LoadProcedureStyle::Merged
        && product.load_procedures.iter().any(|procedure| matches!(procedure.merge_id, Some(3 | 5)))
    {
        ProcedureKind::LoadAll
    } else {
        ProcedureKind::LoadApplication
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
    if kind.is_full_load()
        && product.load_procedure_style == crate::download::product::LoadProcedureStyle::Product
        && let Some(controls) = product.product_procedure()
    {
        return Ok(controls.to_vec());
    }

    let template = mask
        .procedure(procedure_type, sub_type)
        .or_else(|| (kind == ProcedureKind::LoadApplication).then(|| mask.procedure("Load", "all")).flatten())
        .ok_or_else(|| {
            Error::DownloadAssembly(format!(
                "mask {} defines no {procedure_type}/{sub_type} procedure, and the product supplies none either",
                mask.version()
            ))
        })?;

    splice_merges(&template.controls, product, kind.fragment_selector(), kind.is_full_load())
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
fn splice_merges(
    template: &[LoadControl],
    product: &ProductData,
    applies_to: &str,
    require_all_fragments: bool,
) -> Result<Vec<LoadControl>> {
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
                        if control_applies_to(inner, applies_to) {
                            out.push(inner.clone());
                        }
                    }
                    spliced.push(merge.merge_id);
                }
            }
            other => out.push(other.clone()),
        }
    }

    let orphaned: Vec<u8> =
        product.load_procedures.iter().filter_map(|p| p.merge_id).filter(|id| !spliced.contains(id)).collect();
    // A complete procedure must account for every product fragment. Partial
    // mask procedures intentionally omit unrelated merge points (for example
    // `Load/grp` does not carry the application parameter segment), so those
    // fragments are not evidence of incompatible product data.
    if require_all_fragments && !orphaned.is_empty() {
        return Err(Error::DownloadAssembly(format!(
            "product declares merge fragments {orphaned:?} that the mask template has no splice point for"
        )));
    }

    Ok(out)
}

/// Whether a product-fragment control belongs to the selected download path.
/// Controls without `AppliesTo` are common to every path.
fn control_applies_to(control: &LoadControl, selected: &str) -> bool {
    let applies_to = match control {
        LoadControl::LdCtrlRelSegment(control) => control.applies_to.as_deref(),
        LoadControl::LdCtrlWriteRelMem(control) => control.applies_to.as_deref(),
        _ => None,
    };
    applies_to.is_none_or(|values| values.split(',').any(|value| value.trim().eq_ignore_ascii_case(selected)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_knxprod::MasterData;
    use zweidraehte_knxprod::schema::{LdCtrlMerge, LdCtrlRelSegment, LdCtrlRestart, LdCtrlWriteRelMem, LoadProcedure};
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
            Instruction::LsmEvent { lsm: 1.into(), event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: 2.into(), event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: 3.into(), event: LoadEvent::Unload },
            Instruction::LsmEvent { lsm: 4.into(), event: LoadEvent::Unload },
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
              <LdCtrlUnload LsmIdx="5" />
              <LdCtrlLoad LsmIdx="5" />
              <LdCtrlMerge MergeId="4" />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Load" ProcedureSubType="ap1" Access="remote">
              <LdCtrlConnect />
              <LdCtrlUnload LsmIdx="5" />
              <LdCtrlUnload LsmIdx="4" />
              <LdCtrlMerge MergeId="4" />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Load" ProcedureSubType="par" Access="remote">
              <LdCtrlConnect />
              <LdCtrlMerge MergeId="4" />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Load" ProcedureSubType="grp" Access="remote">
              <LdCtrlConnect />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Load" ProcedureSubType="par,grp" Access="remote">
              <LdCtrlConnect />
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
        assert_eq!(controls.len(), 5);
        assert!(matches!(controls[0], LoadControl::LdCtrlConnect(_)));
        assert!(matches!(controls[1], LoadControl::LdCtrlRestart(_)), "fragment spliced in");
        assert!(matches!(controls[2], LoadControl::LdCtrlUnload(_)));
        assert!(matches!(controls[3], LoadControl::LdCtrlLoad(_)));
        assert!(matches!(controls[4], LoadControl::LdCtrlRestart(_)));
        assert!(
            !controls.iter().any(|c| matches!(c, LoadControl::LdCtrlMerge(_))),
            "no merge point may survive assembly"
        );
    }

    #[test]
    fn application_programming_prefers_ap1_without_loading_ap2() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(Vec::new());

        let controls = assemble_controls(&mask, &product, ProcedureKind::LoadApplication).expect("assembles");

        assert!(
            controls
                .iter()
                .any(|control| { matches!(control, LoadControl::LdCtrlUnload(unload) if unload.lsm_idx == Some(4)) })
        );
        assert!(
            controls
                .iter()
                .any(|control| { matches!(control, LoadControl::LdCtrlUnload(unload) if unload.lsm_idx == Some(5)) })
        );
        assert!(
            !controls
                .iter()
                .any(|control| { matches!(control, LoadControl::LdCtrlLoad(load) if load.lsm_idx == Some(5)) })
        );

        let all = assemble_controls(&mask, &product, ProcedureKind::LoadAll).expect("assembles complete procedure");
        assert!(all.iter().any(|control| matches!(control, LoadControl::LdCtrlLoad(load) if load.lsm_idx == Some(5))));
    }

    #[test]
    fn complete_download_selects_only_full_fragment_controls() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(vec![LoadProcedure {
            merge_id: Some(4),
            controls: vec![
                LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                    applies_to: Some("full".into()),
                    lsm_idx: Some(4),
                    size: 2040,
                    mode: 1,
                    fill: 0,
                    ..Default::default()
                }),
                LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                    applies_to: Some("par".into()),
                    lsm_idx: Some(4),
                    size: 2040,
                    mode: 0,
                    fill: 0,
                    ..Default::default()
                }),
                LoadControl::LdCtrlWriteRelMem(LdCtrlWriteRelMem {
                    applies_to: Some("full,par".into()),
                    obj_idx: Some(4),
                    size: 2040,
                    verify: true,
                    ..Default::default()
                }),
            ],
        }]);

        let controls = assemble_controls(&mask, &product, ProcedureKind::LoadApplication).expect("assembles");
        let allocations = controls
            .iter()
            .filter_map(|control| match control {
                LoadControl::LdCtrlRelSegment(segment) if segment.lsm_idx == Some(4) => Some(segment.mode),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(allocations, [1], "only the full allocation branch remains");
        assert_eq!(
            controls.iter().filter(|control| matches!(control, LoadControl::LdCtrlWriteRelMem(_))).count(),
            1,
            "controls shared by full and partial downloads remain"
        );
    }

    #[test]
    fn scope_selection_uses_the_smallest_available_remote_procedure() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(Vec::new());

        assert_eq!(procedure_kind_for_scope(&mask, &product, DownloadScope::Parameters), ProcedureKind::LoadParameters);
        assert_eq!(
            procedure_kind_for_scope(&mask, &product, DownloadScope::GroupCommunication),
            ProcedureKind::LoadGroupCommunication
        );
        assert_eq!(
            procedure_kind_for_scope(&mask, &product, DownloadScope::ParametersAndGroupCommunication),
            ProcedureKind::LoadParametersAndGroupCommunication
        );
    }

    #[test]
    fn partial_scope_widens_to_the_available_safe_superset() {
        let xml = MERGED_MASK
            .replace("ProcedureSubType=\"par\" Access=\"remote\"", "ProcedureSubType=\"par\" Access=\"local2\"")
            .replace("ProcedureSubType=\"grp\" Access=\"remote\"", "ProcedureSubType=\"grp\" Access=\"local2\"");
        let db = MaskDb::from_str(&xml).expect("fixture");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(Vec::new());

        assert_eq!(
            procedure_kind_for_scope(&mask, &product, DownloadScope::Parameters),
            ProcedureKind::LoadParametersAndGroupCommunication
        );
        assert_eq!(
            procedure_kind_for_scope(&mask, &product, DownloadScope::GroupCommunication),
            ProcedureKind::LoadParametersAndGroupCommunication
        );
    }

    #[test]
    fn parameter_download_selects_the_partial_product_fragment() {
        let db = merged_mask_db();
        let mask = db.mask(MaskVersion::SystemBTp1).expect("07B0");
        let product = product_with_fragments(vec![LoadProcedure {
            merge_id: Some(4),
            controls: vec![
                LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                    applies_to: Some("full".into()),
                    lsm_idx: Some(4),
                    size: 16,
                    mode: 1,
                    ..Default::default()
                }),
                LoadControl::LdCtrlRelSegment(LdCtrlRelSegment {
                    applies_to: Some("par".into()),
                    lsm_idx: Some(4),
                    size: 16,
                    mode: 0,
                    ..Default::default()
                }),
            ],
        }]);

        let controls = assemble_controls(&mask, &product, ProcedureKind::LoadParameters).expect("assembles");
        assert!(
            controls
                .iter()
                .any(|control| matches!(control, LoadControl::LdCtrlRelSegment(segment) if segment.mode == 0))
        );
        assert!(
            !controls
                .iter()
                .any(|control| matches!(control, LoadControl::LdCtrlRelSegment(segment) if segment.mode == 1))
        );
    }

    #[test]
    fn product_owned_procedure_falls_back_to_full() {
        let db = MaskDb::from_str(crate::download::mask::fixtures::MV_0705).expect("fixture");
        let mask = db.mask(MaskVersion::System7Tp1).expect("0705");
        let product = system7_product();

        assert_eq!(
            procedure_kind_for_scope(&mask, &product, DownloadScope::Parameters),
            ProcedureKind::LoadApplication
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
