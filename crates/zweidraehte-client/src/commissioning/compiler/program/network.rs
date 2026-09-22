//! Prepared network choices; execution follows one ordinary sequential flow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkProgram {
    pub(crate) assign_domain: bool,
    pub(crate) assign_address: bool,
    pub(crate) clear_programming_mode: bool,
    pub(crate) enable_data_security: bool,
    pub(crate) bootstrap_tool_key: bool,
    pub(crate) restart: bool,
    pub(crate) advance_sending_sequence: bool,
    pub(crate) programming_button_cleanup: bool,
}
