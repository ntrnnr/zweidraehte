/// One closed token from the load-control `AppliesTo` vocabulary.
///
/// Project schemas through project-23 publish the original `full`/`par`/`grp`
/// spellings. Product procedures in the field also use the application and
/// configuration section spellings accepted by ETS. Keeping this parser next
/// to procedure evaluation prevents catalog preflight from recognizing a
/// different language than the executable compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commissioning) enum AppliesToScope {
    Full,
    ApplicationProgram1,
    ApplicationProgram2,
    Parameters,
    GroupCommunication,
    Configuration,
    All,
    Automatic,
}

pub(in crate::commissioning) fn parse_applies_to_token(token: &str) -> Option<AppliesToScope> {
    match token.trim().to_ascii_lowercase().as_str() {
        "full" => Some(AppliesToScope::Full),
        "ap1" => Some(AppliesToScope::ApplicationProgram1),
        "ap2" => Some(AppliesToScope::ApplicationProgram2),
        "par" => Some(AppliesToScope::Parameters),
        "grp" => Some(AppliesToScope::GroupCommunication),
        "cfg" | "config" => Some(AppliesToScope::Configuration),
        "all" => Some(AppliesToScope::All),
        "auto" => Some(AppliesToScope::Automatic),
        _ => None,
    }
}
