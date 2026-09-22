use super::*;
use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::catalog::rules::resolved_download_stamp_resources;
use crate::commissioning::error::CompileError;
use crate::commissioning::procedure::StampDescriptor;
use crate::commissioning::procedure::operands::StandardMemoryService;

fn stamps(profile: &ResolvedProfile) -> Result<Vec<StampDescriptor>, CompileError> {
    resolved_download_stamp_resources(profile, StandardMemoryService::Classic)
}

#[test]
fn nonzero_download_stamp_requires_a_runtime_stamp_resource() {
    let xml = RESOURCE_SELECTION
        .replace("<Resources>", "<Features><Feature Name=\"DownloadStamp\" Value=\"1\" /></Features><Resources>");
    let profile = resolve_resource_selection(&xml).expect("profile selection");
    let error = stamps(&profile).expect_err("stamp support without a stamp resource must fail");

    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert!(
        error.message.contains("MV-0012")
            && error.message.contains("remote access")
            && error.message.contains("no runtime-readable Stamp_SystemB resource")
    );
}

#[test]
fn zero_download_stamp_does_not_require_a_stamp_resource() {
    let xml = RESOURCE_SELECTION
        .replace("<Resources>", "<Features><Feature Name=\"DownloadStamp\" Value=\"0\" /></Features><Resources>");

    let profile = resolve_resource_selection(&xml).expect("profile selection");
    assert!(stamps(&profile).expect("disabled stamp support needs no stamp resource").is_empty());
}

#[test]
fn unknown_stamp_flavours_fail_before_profile_execution() {
    let xml = RESOURCE_SELECTION
        .replace("<Resources>", "<Features><Feature Name=\"DownloadStamp\" Value=\"1\" /></Features><Resources>")
        .replace("<ResourceType Length=\"1\" />", "<ResourceType Length=\"1\" Flavour=\"Stamp_Future\" />");
    let profile = resolve_resource_selection(&xml).expect("profile selection does not bind unused codecs");
    let error = profile
        .resource("Chosen")
        .expect("selection")
        .expect("chosen resource")
        .flavour()
        .expect_err("unknown stamp codec must fail when consumed");

    assert_eq!(error.kind, CompileErrorKind::Unsupported);
    assert!(error.message.contains("Stamp_Future"));
}
