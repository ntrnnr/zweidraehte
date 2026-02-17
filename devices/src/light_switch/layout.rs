//! ETS page layout for the 2-button light switch.
//!
//! Defines how parameters and communication objects are presented in the
//! ETS configuration UI. Only available with the `knxprod` feature.

use knxprod::definition::page_layout::{EtsPageLayout, PageStructure};
use knxprod::ets_pages;

use super::params::ButtonConfigDiscriminant;
use super::LightSwitchDevice;

impl EtsPageLayout for LightSwitchDevice {
    fn page_layout() -> PageStructure {
        use ButtonConfigDiscriminant::*;

        ets_pages! {
            // ================================================================
            // Device-wide settings (not in any channel tab)
            // ================================================================
            device {
                block "general" => "General" {
                    param debounce_time
                    param long_press_time
                }
            }

            // ================================================================
            // Button 1 channel
            // ================================================================
            channel "button1" => "Button 1" (1) {
                block "btn1_config" => "Function" {
                    selector button1_config
                }

                when button1_config {
                    [Switch] => {
                        block "btn1_switch" => "    Switch Settings" {
                            param button1_config::Switch.operation
                            param button1_config::Switch.long_press
                            obj btn1_primary
                        }
                    }
                    [Dimmer] => {
                        block "btn1_dimmer" => "    Dimmer" {
                            obj btn1_primary
                            obj btn1_secondary
                        }
                    }
                    [Blind] => {
                        block "btn1_blind" => "    Blind" {
                            obj btn1_primary
                            obj btn1_secondary
                        }
                    }
                    [Scene] => {
                        block "btn1_scene" => "    Scene Settings" {
                            param button1_config::Scene.scene_number
                            obj btn1_primary
                        }
                    }
                }
            }

            // ================================================================
            // Button 2 channel
            // ================================================================
            channel "button2" => "Button 2" (2) {
                block "btn2_config" => "Function" {
                    selector button2_config
                }

                when button2_config {
                    [Switch] => {
                        block "btn2_switch" => "    Switch Settings" {
                            param button2_config::Switch.operation
                            param button2_config::Switch.long_press
                            obj btn2_primary
                        }
                    }
                    [Dimmer] => {
                        block "btn2_dimmer" => "    Dimmer" {
                            obj btn2_primary
                            obj btn2_secondary
                        }
                    }
                    [Blind] => {
                        block "btn2_blind" => "    Blind" {
                            obj btn2_primary
                            obj btn2_secondary
                        }
                    }
                    [Scene] => {
                        block "btn2_scene" => "    Scene Settings" {
                            param button2_config::Scene.scene_number
                            obj btn2_primary
                        }
                    }
                }
            }
        }
    }
}
