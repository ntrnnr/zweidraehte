//! Resolve values operands against the image and target metadata.

use super::*;
use crate::commissioning::error::CompileError;

use crate::commissioning::compiler::selection::syntax::{decode_optional_hex, parse_range};
use crate::commissioning::image::ImageLocation;
use crate::commissioning::procedure::{Comparison, ComparisonPadding, ControlPath, OperationData};

impl ProcedureLowerer<'_> {
    pub(super) fn comparison(
        &self,
        inline: Option<Vec<u8>>,
        mask: Option<&str>,
        range: Option<&str>,
        image_location: Option<ImageLocation>,
        length: u32,
        padding: ComparisonPadding,
        path: &ControlPath,
    ) -> Result<Comparison, CompileError> {
        if let Some(range) = range {
            if inline.is_some() || mask.is_some() {
                return Err(CompileError::at(path, "range comparison cannot also declare InlineData or Mask"));
            }

            return parse_range(range).map_err(|message| CompileError::at(path, message));
        }

        let data = match inline {
            Some(data) => OperationData::Inline(data),
            None => {
                let location =
                    image_location.ok_or_else(|| CompileError::at(path, "comparison has no inline or image data"))?;
                OperationData::Buffer { location, length, fallback: None }
            }
        };

        let expected_length = operation_data_length(&data);
        let mask = decode_optional_hex(mask, path)?;
        if let Some(mask) = mask.as_ref()
            && mask.len() != expected_length as usize
        {
            return Err(CompileError::at(
                path,
                format!("comparison mask has {} bytes, expected {expected_length}", mask.len()),
            ));
        }

        Ok(match data {
            OperationData::Buffer { location, length, fallback: None } => {
                Comparison::ImageExact { location, length, mask }
            }
            data => Comparison::Exact { data, mask, padding },
        })
    }

    pub(super) fn progress_text(
        &self,
        text_id: Option<u32>,
        message_reference: Option<&str>,
        path: &ControlPath,
    ) -> Result<String, CompileError> {
        let by_reference = message_reference
            .map(|reference| {
                self.context.progress_messages_by_reference.get(reference).cloned().ok_or_else(|| {
                    CompileError::at(path, format!("progress message reference {reference:?} is unresolved"))
                })
            })
            .transpose()?;
        let by_id = text_id
            .map(|id| {
                self.context
                    .progress_messages_by_id
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| CompileError::at(path, format!("progress text ID {id} is unresolved")))
            })
            .transpose()?;

        match (by_reference, by_id) {
            (Some(reference), Some(id)) if reference != id => {
                Err(CompileError::at(path, "progress MessageRef and TextId resolve to different text"))
            }
            (Some(text), _) | (_, Some(text)) => Ok(text),
            (None, None) => Err(CompileError::at(path, "progress control has neither MessageRef nor TextId")),
        }
    }
}
