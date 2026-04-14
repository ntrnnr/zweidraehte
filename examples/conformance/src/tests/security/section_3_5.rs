//! Section 3.5 — S-A_Data PDU for routing (placeholder).
//!
//! The reference XML (`KnxConformanceTestTemplate-DataSecurity.xml`) declares
//! this suite as "[to be completed]" with no telegrams. Kept as a placeholder
//! so the coverage index matches the reference.

use crate::{TestCase, TestSuite};
use super::variables::create_security_variables;
use crate::tests::helpers::*;

pub fn create_section_3_5_suite() -> TestSuite {
    let variables = create_security_variables();

    TestSuite::new("3.5 S-A_Data PDU for routing", variables)
        .secure()
        .with_cases(vec![
            TestCase::new("3.5 [to be completed]").with_steps(vec![
                comment("Placeholder: suite is marked '[to be completed]' in the reference XML."),
            ]),
        ])
}
