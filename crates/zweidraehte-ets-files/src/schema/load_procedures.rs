//! Lossless XML syntax for KNX load procedures.
//!
//! Product MTXML and Master Data use the same load-control language. This
//! module models the project-20 through project-23 union and deliberately
//! preserves optional values rather than applying XSD defaults while parsing.
//! Absence can carry information during profile resolution: in particular,
//! `Occurrence="0"` is not the same input as an omitted `Occurrence`.
//!
//! Symbolic values remain strings here. A newer symbolic value can therefore
//! be diagnosed later with its mask and procedure context. Element names are
//! different: the load-control vocabulary is closed, so an unknown control is
//! a parse error rather than silently discarded.

use serde::{Deserialize, Serialize};

// ============================================================================
// Procedures and the recursive control vocabulary
// ============================================================================

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadProcedures {
    #[serde(rename = "LoadProcedure", default, skip_serializing_if = "Vec::is_empty")]
    pub procedures: Vec<LoadProcedure>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadProcedure {
    #[serde(rename = "@MergeId", skip_serializing_if = "Option::is_none")]
    pub merge_id: Option<u8>,

    #[serde(rename = "$value", default, skip_serializing_if = "Vec::is_empty")]
    pub controls: Vec<LoadControl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadControl {
    LdCtrlUnload(LdCtrlUnload),
    LdCtrlLoad(LdCtrlLoad),
    LdCtrlMaxLength(LdCtrlMaxLength),
    LdCtrlClearCachedObjectTypes(LdCtrlClearCachedObjectTypes),
    LdCtrlLoadCompleted(LdCtrlLoadCompleted),
    LdCtrlAbsSegment(LdCtrlAbsSegment),
    LdCtrlRelSegment(LdCtrlRelSegment),
    LdCtrlTaskSegment(LdCtrlTaskSegment),
    LdCtrlTaskPtr(LdCtrlTaskPtr),
    LdCtrlTaskCtrl1(LdCtrlTaskCtrl1),
    LdCtrlTaskCtrl2(LdCtrlTaskCtrl2),
    LdCtrlWriteProp(LdCtrlWriteProp),
    LdCtrlCompareProp(LdCtrlCompareProp),
    LdCtrlLoadImageProp(LdCtrlLoadImageProp),
    LdCtrlInvokeFunctionProp(LdCtrlInvokeFunctionProp),
    LdCtrlReadFunctionProp(LdCtrlReadFunctionProp),
    LdCtrlWriteMem(LdCtrlWriteMem),
    LdCtrlCompareMem(LdCtrlCompareMem),
    LdCtrlLoadImageMem(LdCtrlLoadImageMem),
    LdCtrlWriteRelMem(LdCtrlWriteRelMem),
    LdCtrlCompareRelMem(LdCtrlCompareRelMem),
    LdCtrlLoadImageRelMem(LdCtrlLoadImageRelMem),
    LdCtrlConnect(LdCtrlConnect),
    LdCtrlDisconnect(LdCtrlDisconnect),
    LdCtrlRestart(LdCtrlRestart),
    LdCtrlMasterReset(LdCtrlMasterReset),
    LdCtrlDelay(LdCtrlDelay),
    LdCtrlSetControlVariable(LdCtrlSetControlVariable),
    LdCtrlMapError(LdCtrlMapError),
    LdCtrlProgressText(LdCtrlProgressText),
    LdCtrlDeclarePropDesc(LdCtrlDeclarePropDesc),
    LdCtrlClearLCFilterTable(LdCtrlClearLCFilterTable),
    LdCtrlMerge(LdCtrlMerge),

    #[serde(rename = "choose")]
    Choose(LdCtrlChoose),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdCtrlChoose {
    #[serde(rename = "@ParamRefId")]
    pub param_ref_id: String,

    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "when", default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<LdCtrlWhen>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdCtrlWhen {
    #[serde(rename = "@test", skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,

    #[serde(rename = "@default", skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,

    #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
    pub internal_description: Option<String>,

    #[serde(rename = "$value", default, skip_serializing_if = "Vec::is_empty")]
    pub controls: Vec<LoadControl>,
}

// ============================================================================
// Common load-control syntax
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnError {
    #[serde(rename = "@Cause")]
    pub cause: String,

    #[serde(rename = "@Ignore", skip_serializing_if = "Option::is_none")]
    pub ignore: Option<bool>,

    #[serde(rename = "@MessageRef", skip_serializing_if = "Option::is_none")]
    pub message_ref: Option<String>,
}

// The XSD uses inheritance. Direct fields keep XML attributes before child
// `OnError` elements and preserve the existing ergonomic field access.
macro_rules! define_load_control {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$field_meta:meta])* $field:ident: $field_ty:ty,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[serde(rename = "@AppliesTo", skip_serializing_if = "Option::is_none")]
            pub applies_to: Option<String>,

            #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
            pub internal_description: Option<String>,

            $($(#[$field_meta])* pub $field: $field_ty,)*

            #[serde(rename = "OnError", default, skip_serializing_if = "Vec::is_empty")]
            pub on_errors: Vec<OnError>,
        }
    };
}

macro_rules! define_compare_control {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$field_meta:meta])* $field:ident: $field_ty:ty,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[serde(rename = "@AppliesTo", skip_serializing_if = "Option::is_none")]
            pub applies_to: Option<String>,

            #[serde(rename = "@InternalDescription", skip_serializing_if = "Option::is_none")]
            pub internal_description: Option<String>,

            #[serde(rename = "@AllowCachedValue", skip_serializing_if = "Option::is_none")]
            pub allow_cached_value: Option<bool>,

            #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
            pub inline_data: Option<String>,

            #[serde(rename = "@Mask", skip_serializing_if = "Option::is_none")]
            pub mask: Option<String>,

            #[serde(rename = "@Range", skip_serializing_if = "Option::is_none")]
            pub range: Option<String>,

            #[serde(rename = "@Invert", skip_serializing_if = "Option::is_none")]
            pub invert: Option<bool>,

            #[serde(rename = "@RetryInterval", skip_serializing_if = "Option::is_none")]
            pub retry_interval: Option<u16>,

            #[serde(rename = "@TimeOut", skip_serializing_if = "Option::is_none")]
            pub time_out: Option<u16>,

            $($(#[$field_meta])* pub $field: $field_ty,)*

            #[serde(rename = "OnError", default, skip_serializing_if = "Vec::is_empty")]
            pub on_errors: Vec<OnError>,
        }
    };
}

// Object selector validity depends on the resolved programming profile. The
// syntax layer therefore preserves all optional selector components verbatim.

// ============================================================================
// Load-state and segment controls
// ============================================================================

define_load_control! {
    LdCtrlUnload {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
    }
}

define_load_control! {
    LdCtrlLoad {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
    }
}

define_load_control! {
    LdCtrlMaxLength {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Size")]
        size: u32,
    }
}

define_load_control! { LdCtrlClearCachedObjectTypes {} }

define_load_control! {
    LdCtrlLoadCompleted {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
    }
}

define_load_control! {
    LdCtrlAbsSegment {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@SegType")]
        seg_type: u8,
        #[serde(rename = "@Address")]
        address: u16,
        #[serde(rename = "@Size")]
        size: u16,
        #[serde(rename = "@Access")]
        access: u8,
        #[serde(rename = "@MemType")]
        mem_type: u8,
        #[serde(rename = "@SegFlags")]
        seg_flags: u8,
    }
}

define_load_control! {
    LdCtrlRelSegment {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Size")]
        size: u32,
        #[serde(rename = "@Mode")]
        mode: u8,
        #[serde(rename = "@Fill")]
        fill: u8,
    }
}

define_load_control! {
    LdCtrlTaskSegment {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Address")]
        address: u16,
    }
}

define_load_control! {
    LdCtrlTaskPtr {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@InitPtr")]
        init_ptr: u16,
        #[serde(rename = "@SavePtr")]
        save_ptr: u16,
        #[serde(rename = "@SerialPtr")]
        serial_ptr: u16,
    }
}

define_load_control! {
    LdCtrlTaskCtrl1 {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Address")]
        address: u16,
        #[serde(rename = "@Count")]
        count: u8,
    }
}

define_load_control! {
    LdCtrlTaskCtrl2 {
        #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
        lsm_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Callback")]
        callback: u16,
        #[serde(rename = "@Address")]
        address: u16,
        #[serde(rename = "@Seg0")]
        seg0: u16,
        #[serde(rename = "@Seg1")]
        seg1: u16,
    }
}

// ============================================================================
// Property controls
// ============================================================================

define_load_control! {
    LdCtrlWriteProp {
        /// Module argument supplying the object-index base, resolved before lowering.
        #[serde(rename = "@BaseObjIdx", skip_serializing_if = "Option::is_none")]
        base_obj_idx: Option<String>,
        /// Module argument supplying the occurrence base.
        #[serde(rename = "@BaseOccurrence", skip_serializing_if = "Option::is_none")]
        base_occurrence: Option<String>,
        /// Module argument supplying the first-element base.
        #[serde(rename = "@BaseStartElement", skip_serializing_if = "Option::is_none")]
        base_start_element: Option<String>,
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@PropId")]
        prop_id: u16,
        #[serde(rename = "@StartElement", skip_serializing_if = "Option::is_none")]
        start_element: Option<u16>,
        #[serde(rename = "@Count", skip_serializing_if = "Option::is_none")]
        count: Option<u16>,
        #[serde(rename = "@Verify")]
        verify: bool,
        #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
        inline_data: Option<String>,
        #[serde(rename = "@Trim", skip_serializing_if = "Option::is_none")]
        trim: Option<bool>,
    }
}

define_compare_control! {
    LdCtrlCompareProp {
        /// Module argument supplying the object-index base, resolved before lowering.
        #[serde(rename = "@BaseObjIdx", skip_serializing_if = "Option::is_none")]
        base_obj_idx: Option<String>,
        /// Module argument supplying the occurrence base.
        #[serde(rename = "@BaseOccurrence", skip_serializing_if = "Option::is_none")]
        base_occurrence: Option<String>,
        /// Module argument supplying the first-element base.
        #[serde(rename = "@BaseStartElement", skip_serializing_if = "Option::is_none")]
        base_start_element: Option<String>,
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@PropId")]
        prop_id: u16,
        #[serde(rename = "@StartElement", skip_serializing_if = "Option::is_none")]
        start_element: Option<u16>,
        #[serde(rename = "@Count", skip_serializing_if = "Option::is_none")]
        count: Option<u16>,
    }
}

define_load_control! {
    LdCtrlLoadImageProp {
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@PropId")]
        prop_id: u16,
        #[serde(rename = "@StartElement", skip_serializing_if = "Option::is_none")]
        start_element: Option<u16>,
        #[serde(rename = "@Count", skip_serializing_if = "Option::is_none")]
        count: Option<u16>,
    }
}

define_load_control! {
    LdCtrlInvokeFunctionProp {
        /// Module argument supplying the object-index base, resolved before lowering.
        #[serde(rename = "@BaseObjIdx", skip_serializing_if = "Option::is_none")]
        base_obj_idx: Option<String>,
        /// Module argument supplying the occurrence base.
        #[serde(rename = "@BaseOccurrence", skip_serializing_if = "Option::is_none")]
        base_occurrence: Option<String>,
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@PropId")]
        prop_id: u16,
        #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
        inline_data: Option<String>,
    }
}

define_load_control! {
    LdCtrlReadFunctionProp {
        /// Module argument supplying the object-index base, resolved before lowering.
        #[serde(rename = "@BaseObjIdx", skip_serializing_if = "Option::is_none")]
        base_obj_idx: Option<String>,
        /// Module argument supplying the occurrence base.
        #[serde(rename = "@BaseOccurrence", skip_serializing_if = "Option::is_none")]
        base_occurrence: Option<String>,
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@PropId")]
        prop_id: u16,
    }
}

define_load_control! {
    LdCtrlDeclarePropDesc {
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@PropId")]
        prop_id: u16,
        #[serde(rename = "@PropType")]
        prop_type: String,
        #[serde(rename = "@MaxElements")]
        max_elements: u16,
        #[serde(rename = "@ReadAccess")]
        read_access: u8,
        #[serde(rename = "@WriteAccess")]
        write_access: u8,
        #[serde(rename = "@Writable")]
        writable: bool,
    }
}

// ============================================================================
// Absolute and relative memory controls
// ============================================================================

define_load_control! {
    LdCtrlWriteMem {
        #[serde(rename = "@AddressSpace", skip_serializing_if = "Option::is_none")]
        address_space: Option<String>,
        #[serde(rename = "@Address")]
        address: u32,
        #[serde(rename = "@Size")]
        size: u32,
        #[serde(rename = "@Verify")]
        verify: bool,
        #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
        inline_data: Option<String>,
    }
}

define_compare_control! {
    LdCtrlCompareMem {
        #[serde(rename = "@AddressSpace", skip_serializing_if = "Option::is_none")]
        address_space: Option<String>,
        #[serde(rename = "@Address")]
        address: u32,
        #[serde(rename = "@Size")]
        size: u32,
    }
}

define_load_control! {
    LdCtrlLoadImageMem {
        #[serde(rename = "@AddressSpace", skip_serializing_if = "Option::is_none")]
        address_space: Option<String>,
        #[serde(rename = "@Address")]
        address: u32,
        #[serde(rename = "@Size")]
        size: u32,
    }
}

define_load_control! {
    LdCtrlWriteRelMem {
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Offset")]
        offset: u32,
        #[serde(rename = "@Size")]
        size: u32,
        #[serde(rename = "@Verify")]
        verify: bool,
        #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
        inline_data: Option<String>,
    }
}

define_compare_control! {
    LdCtrlCompareRelMem {
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Offset")]
        offset: u32,
        #[serde(rename = "@Size")]
        size: u32,
    }
}

define_load_control! {
    LdCtrlLoadImageRelMem {
        #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
        obj_idx: Option<u8>,
        #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
        obj_type: Option<u16>,
        #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
        occurrence: Option<u16>,
        #[serde(rename = "@Offset")]
        offset: u32,
        #[serde(rename = "@Size")]
        size: u32,
    }
}

// ============================================================================
// Session, tool-state, and orchestration controls
// ============================================================================

define_load_control! { LdCtrlConnect {} }
define_load_control! { LdCtrlDisconnect {} }
define_load_control! { LdCtrlRestart {} }

define_load_control! {
    LdCtrlMasterReset {
        #[serde(rename = "@EraseCode")]
        erase_code: u8,
        #[serde(rename = "@ChannelNumber")]
        channel_number: u8,
    }
}

define_load_control! {
    LdCtrlDelay {
        #[serde(rename = "@MilliSeconds")]
        milli_seconds: u16,
    }
}

define_load_control! {
    LdCtrlSetControlVariable {
        #[serde(rename = "@Name")]
        name: String,
        #[serde(rename = "@Value")]
        value: bool,
    }
}

define_load_control! {
    LdCtrlMapError {
        #[serde(rename = "@LdCtrlFilter", skip_serializing_if = "Option::is_none")]
        ld_ctrl_filter: Option<u8>,
        #[serde(rename = "@OriginalError")]
        original_error: u32,
        #[serde(rename = "@MappedError")]
        mapped_error: u32,
    }
}

define_load_control! {
    LdCtrlProgressText {
        #[serde(rename = "@TextId", skip_serializing_if = "Option::is_none")]
        text_id: Option<u32>,
        #[serde(rename = "@MessageRef", skip_serializing_if = "Option::is_none")]
        message_ref: Option<String>,
    }
}

define_load_control! {
    LdCtrlClearLCFilterTable {
        #[serde(rename = "@UseFunctionProp", skip_serializing_if = "Option::is_none")]
        use_function_prop: Option<bool>,
    }
}

define_load_control! {
    LdCtrlMerge {
        #[serde(rename = "@MergeId")]
        merge_id: u8,
    }
}

#[cfg(test)]
mod tests {
    use quick_xml::{de::from_str, se::to_string};

    use super::*;

    #[test]
    fn parses_and_roundtrips_the_complete_control_shapes() {
        let xml = r#"
            <LoadProcedures>
              <LoadProcedure MergeId="9">
                <LdCtrlMaxLength ObjType="9" Size="1048576"
                    AppliesTo="full,par" InternalDescription="allocation">
                  <OnError Cause="ResourceNotFound" Ignore="true" MessageRef="M-00FA_M-1" />
                  <OnError Cause="FutureCause" Ignore="false" />
                </LdCtrlMaxLength>
                <LdCtrlClearCachedObjectTypes />
                <LdCtrlCompareRelMem ObjType="6" Occurrence="0" Offset="70000"
                    Size="90000" AllowCachedValue="true" InlineData="A50F"
                    Mask="F00F" Range="[0,65535]u" Invert="true"
                    RetryInterval="125" TimeOut="500" />
                <LdCtrlLoadImageRelMem ObjIdx="4" Offset="65536" Size="131072" />
                <LdCtrlInvokeFunctionProp ObjType="11" Occurrence="3"
                    PropId="300" InlineData="010203" />
                <LdCtrlReadFunctionProp ObjIdx="7" PropId="301" />
                <LdCtrlProgressText TextId="70000" MessageRef="M-00FA_M-2" />
                <LdCtrlDeclarePropDesc ObjType="12" Occurrence="1" PropId="302"
                    PropType="PDT_FUTURE" MaxElements="65535" ReadAccess="15"
                    WriteAccess="14" Writable="true" />
                <choose ParamRefId="M-00FA_P-1" InternalDescription="outer choice">
                  <when test="=1" InternalDescription="selected">
                    <LdCtrlWriteMem AddressSpace="FutureSpace" Address="1048575"
                        Size="4" Verify="true" InlineData="DEADBEEF" />
                    <choose ParamRefId="M-00FA_P-2">
                      <when default="true">
                        <LdCtrlSetControlVariable Name="FutureVariable" Value="false" />
                      </when>
                    </choose>
                  </when>
                  <when default="false">
                    <LdCtrlMasterReset EraseCode="7" ChannelNumber="0" />
                  </when>
                </choose>
              </LoadProcedure>
            </LoadProcedures>
        "#;

        let procedures: LoadProcedures = from_str(xml).expect("complete procedure parses");
        let procedure = &procedures.procedures[0];

        let LoadControl::LdCtrlMaxLength(max_length) = &procedure.controls[0] else {
            panic!("expected maximum-length control");
        };
        assert_eq!(max_length.size, 1_048_576);
        assert_eq!(max_length.occurrence, None);
        assert_eq!(max_length.on_errors.len(), 2);
        assert_eq!(max_length.on_errors[0].ignore, Some(true));
        assert_eq!(max_length.on_errors[1].cause, "FutureCause");

        let LoadControl::LdCtrlCompareRelMem(compare) = &procedure.controls[2] else {
            panic!("expected relative-memory comparison");
        };
        assert_eq!(compare.occurrence, Some(0));
        assert_eq!(compare.offset, 70_000);
        assert_eq!(compare.mask.as_deref(), Some("F00F"));
        assert_eq!(compare.range.as_deref(), Some("[0,65535]u"));

        let LoadControl::LdCtrlDeclarePropDesc(descriptor) = &procedure.controls[7] else {
            panic!("expected property descriptor");
        };
        assert_eq!(descriptor.prop_type, "PDT_FUTURE");

        let LoadControl::Choose(outer) = &procedure.controls[8] else {
            panic!("expected conditional control");
        };
        assert_eq!(outer.when.len(), 2);
        assert!(matches!(outer.when[0].controls[1], LoadControl::Choose(_)));

        let serialized = to_string(&procedures).expect("complete procedure serializes");
        let reparsed: LoadProcedures = from_str(&serialized).expect("serialized procedure reparses");
        assert_eq!(reparsed, procedures);
    }

    #[test]
    fn preserves_absent_zero_and_positive_occurrences() {
        let xml = r#"
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlLoad ObjType="9" />
                <LdCtrlLoad ObjType="9" Occurrence="0" />
                <LdCtrlLoad ObjType="9" Occurrence="2" />
              </LoadProcedure>
            </LoadProcedures>
        "#;

        let procedures: LoadProcedures = from_str(xml).expect("selectors parse");
        let controls = &procedures.procedures[0].controls;

        let occurrences: Vec<Option<u16>> = controls
            .iter()
            .map(|control| match control {
                LoadControl::LdCtrlLoad(load) => load.occurrence,
                other => panic!("expected load control, got {other:?}"),
            })
            .collect();

        assert_eq!(occurrences, vec![None, Some(0), Some(2)]);
    }

    #[test]
    fn rejects_unknown_control_elements() {
        let xml = r#"
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlInvented Address="1" />
              </LoadProcedure>
            </LoadProcedures>
        "#;

        let error = from_str::<LoadProcedures>(xml).expect_err("unknown control must fail");
        assert!(error.to_string().contains("LdCtrlInvented"));
    }
}
