//! Published source selection does not widen explicit download applicability.

use crate::commissioning::catalog::profile::{ProcedureId, ResolvedProfile};
use crate::commissioning::error::CompileError;
use crate::commissioning::input::ProgramSections;
use zweidraehte_ets_files::schema::master_data::Procedure;

const CONFIGURATION: u32 = 0x000c_0008;
const APPLICATION_1: u32 = 0xbf;
const INELIGIBLE: i32 = -32;

fn source_mask(subtype: Option<&str>) -> (u32, &'static str) {
    match subtype {
        Some("ap1") => (APPLICATION_1, "ap1"),
        Some("par") => (1, "par"),
        Some("grp") => (2, "grp"),
        Some("par,grp") => (3, "par,grp"),
        Some("cfg") => (CONFIGURATION, "cfg"),
        // Missing and unfamiliar source labels use the complete source class;
        // preserve their original spelling in the selected ProcedureId.
        _ => (0xff, "all"),
    }
}

fn request_mask(sections: ProgramSections) -> u32 {
    let mut mask = 0;
    for (section, bit) in [
        (ProgramSections::PARAMETERS, 1),
        (ProgramSections::GROUP_COMMUNICATION, 2),
        (ProgramSections::CONFIGURATION, 8),
        (ProgramSections::APPLICATION_PROGRAM_1, 128),
        (ProgramSections::APPLICATION_PROGRAM_2, 64),
    ] {
        if sections.contains(section) {
            mask |= bit;
        }
    }
    mask
}

fn score(request: u32, source: u32) -> i32 {
    if request == source {
        return 32;
    }
    // Application configuration and network-only configuration sources cannot
    // substitute for each other. Mixed application/configuration requests can
    // still use an overlapping application source.
    if (request & CONFIGURATION != 0 && request & !CONFIGURATION == 0 && source & !CONFIGURATION != 0)
        || (source & CONFIGURATION != 0 && source & !CONFIGURATION == 0 && request & !CONFIGURATION != 0)
    {
        return INELIGIBLE;
    }
    let mut rank = (source & request).count_ones() as i32 - (source & !request).count_ones() as i32;
    for bit in [1, 2] {
        if request & bit != 0 && source & bit == 0 {
            rank -= 16;
        }
    }
    rank
}

pub(super) fn select_partial_source(
    profile: &ResolvedProfile,
    sections: ProgramSections,
) -> Result<Option<((ProcedureId, &Procedure), &'static str)>, CompileError> {
    // The selected hardware relation is AP1-only; AP2 requests have already
    // been rejected by the caller before entering source selection.
    let request = request_mask(sections) & !64;
    let mut best = None;
    let mut best_rank = INELIGIBLE;
    for (source_index, procedure) in profile.source().procedures.iter().flat_map(|group| &group.procedures).enumerate()
    {
        if !procedure.allows_remote() || !procedure.is_load() {
            continue;
        }
        let (mask, subtype) = source_mask(procedure.procedure_sub_type.as_deref());
        if mask & request == 0 {
            continue;
        }
        // The public section model can request primary application code
        // independently. A parameter/group-only source cannot fulfill that
        // request, even when it overlaps another selected section.
        if sections.contains(ProgramSections::APPLICATION_PROGRAM_1) && mask & 128 == 0 {
            continue;
        }
        let rank = score(request, mask);
        // Keep the first source on ties; an exact source ends the search.
        if rank > best_rank {
            best = Some((
                (
                    ProcedureId {
                        procedure_type: procedure.procedure_type.clone(),
                        subtype: procedure.procedure_sub_type.clone(),
                        management_style: profile.management_style(),
                        source_index,
                    },
                    procedure,
                ),
                subtype,
            ));
            best_rank = rank;
        }
        if mask == request {
            break;
        }
    }
    // Application-only configuration has no authored program unless its
    // source is exact. Features may contribute their own configuration work.
    if request & 0xff == 8 && best_rank < 32 {
        return Ok(None);
    }
    best.map(Some).ok_or_else(|| {
        CompileError::missing_procedure(format!(
            "profile {} variant {} has no eligible remote Load procedure for partial sections {sections:?}",
            profile.mask().full_id,
            profile.variant().source_index,
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ranks_cover_exact_overlap_missing_sections_and_configuration_gates() {
        for (request, source, expected) in [
            (1, 1, 32),
            (2, 2, 32),
            (3, 3, 32),
            (1, 3, 0),
            (2, 3, 0),
            (11, 3, 2),
            (1, 0xff, -6),
            (3, 0xff, -4),
            (11, 0xff, -2),
            (1, APPLICATION_1, -5),
            (11, APPLICATION_1, -1),
            (3, 1, -15),
            (3, 2, -15),
            (8, 0xff, INELIGIBLE),
            (8, CONFIGURATION, -1),
            (9, CONFIGURATION, INELIGIBLE),
        ] {
            assert_eq!(score(request, source), expected, "request={request}, source={source}");
        }
    }
}
