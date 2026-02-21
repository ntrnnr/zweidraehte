//! ETS page layout for the 2-button light switch.
//!
//! Two channels:
//! - "Button 1" — always visible; in 1-function mode shows rocker_direction
//! - "Button 2" — only visible in 2-function mode
//!
//! Only available with the `knxprod` feature.
//!
//! In 1-function mode, Button 1's config drives both physical buttons as a
//! rocker pair (top = one direction, bottom = opposite). Button 2's channel
//! is hidden and its objects are unused.
//!
//! Comm object refs live in each channel's Function block. The `selector_param`
//! on the comm object definitions controls which refs are active per mode.
//!
//! Status objects are conditionally visible: they only appear when the mode
//! actually needs feedback (Switch+Toggle or Dimmer). Switch On/Off, Blind,
//! and Scene modes are stateless and don't show the status object.
//!
//! Each channel also has an "Object description" virtual parameter
//! (`btn1_description` / `btn2_description`) that lets the user enter a
//! custom label in ETS. This label is substituted into the comm object
//! display text via `{{param:default}}` text templates.

use knxprod::definition::page_layout::{EtsPageLayout, PageStructure};
use knxprod::ets_pages;

use super::LightSwitchDevice;
use super::params::{ButtonConfigDiscriminant, ButtonsMode, SwitchAction};

impl EtsPageLayout for LightSwitchDevice {
    fn page_layout() -> PageStructure {
        ets_pages! {
            device {
                block "general" => "General" {
                    param debounce_time
                    param long_press_time
                    param buttons_mode
                }
            }

            // Button 1 — always visible.
            // In 1-function mode, also shows rocker_direction.
            channel "button1" => "Button 1" (1) {
                block "btn1_function" => "Button 1 {{btn1_description:}}" {
                    param btn1_description
                    selector button1_config
                    obj btn1_primary
                    obj btn1_secondary

                    // Status feedback is only needed for Toggle and Dimmer
                    // modes. Switch On/Off is stateless (no feedback needed).
                    when button1_config {
                        [ButtonConfigDiscriminant::Switch] => {
                            when @button1_config_Switch_action {
                                [SwitchAction::Toggle] => {
                                    obj btn1_status
                                }
                            }
                        }
                        [ButtonConfigDiscriminant::Dimmer] => {
                            obj btn1_status
                        }
                    }
                }

                when @buttons_mode {
                    [ButtonsMode::OneFunction] => {
                        block "btn1_rocker" => "Rocker" {
                            param rocker_direction
                        }
                    }
                }
            }

            // Button 2 — only visible in 2-function mode.
            channel "button2" => "Button 2" (2) {
                when @buttons_mode {
                    [ButtonsMode::TwoFunction] => {
                        block "btn2_function" => "Button 2 {{btn2_description:}}" {
                            param btn2_description
                            selector button2_config
                            obj btn2_primary
                            obj btn2_secondary

                            // Same status visibility logic as button 1.
                            when button2_config {
                                [ButtonConfigDiscriminant::Switch] => {
                                    when @button2_config_Switch_action {
                                        [SwitchAction::Toggle] => {
                                            obj btn2_status
                                        }
                                    }
                                }
                                [ButtonConfigDiscriminant::Dimmer] => {
                                    obj btn2_status
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
