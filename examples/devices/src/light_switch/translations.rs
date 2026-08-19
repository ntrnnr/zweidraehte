//! German translations for the 2-button light switch.
//!
//! Only available with the `knxprod` feature since translations are only
//! needed for ETS product definition generation.

zweidraehte_ets_model::ets_translations! {
    pub LIGHT_SWITCH_TRANSLATIONS;

    "de-DE" {
        // ================================================================
        // Enum variant translations
        // ================================================================

        // DebounceTime — values are self-explanatory, no translation needed

        // LongPressTime — values are self-explanatory, no translation needed

        // ButtonsMode
        ButtonsMode::OneFunction => "1-Funktion",
        ButtonsMode::TwoFunction => "2-Funktion",

        // RockerDirection
        RockerDirection::Normal => "Oben = EIN / Auf / Heller",
        RockerDirection::Inverted => "Oben = AUS / Ab / Dunkler",

        // SwitchAction
        SwitchAction::Toggle => "Umschalten",
        SwitchAction::On => "Ein",
        SwitchAction::Off => "Aus",

        // ButtonConfig discriminant (union selector)
        ButtonConfigDiscriminant::Switch => "Schalten",
        ButtonConfigDiscriminant::Dimmer => "Dimmen",
        ButtonConfigDiscriminant::Blind => "Jalousie",
        ButtonConfigDiscriminant::Scene => "Szene",

        // ================================================================
        // Parameter translations
        // ================================================================
        param debounce_time => "Entprellzeit",
        param long_press_time => "Langer Tastendruck",
        param buttons_mode => "Tastenmodus",
        param rocker_direction => "Wippenrichtung",
        param btn1_description => "Objektbeschreibung",
        param btn2_description => "Objektbeschreibung",

        // Union selector parameters (auto-generated name: fieldname_selector)
        param button1_config_selector => "Funktion",
        param button2_config_selector => "Funktion",

        // Union variant inner parameters (auto-generated name: fieldname_Variant_field)
        param button1_config_Switch_action => "Schaltaktion",
        param button2_config_Switch_action => "Schaltaktion",
        param button1_config_Scene_scene_number => "Szenennummer",
        param button2_config_Scene_scene_number => "Szenennummer",

        // ================================================================
        // Block translations
        // ================================================================
        block "general" => "Allgemein",
        block "btn1_function" => "Taster 1 {{btn1_description:}}",
        block "btn1_rocker" => "Wippe",
        block "btn2_function" => "Taster 2 {{btn2_description:}}",

        // ================================================================
        // Base comm object translations (plain text, no templates)
        //
        // These translate the base ComObject element. Templates are stripped
        // because V20 TextParameterRefId substitution only applies to refs.
        // ================================================================
        obj btn1_primary { text: "Taster 1 Schalten", function: "Primärausgang" },
        obj btn1_secondary { text: "Taster 1 Dimmen/Schritt", function: "Sekundärausgang" },
        obj btn1_status { text: "Taster 1 Status", function: "Statusrückmeldung" },
        obj btn2_primary { text: "Taster 2 Schalten", function: "Primärausgang" },
        obj btn2_secondary { text: "Taster 2 Dimmen/Schritt", function: "Sekundärausgang" },
        obj btn2_status { text: "Taster 2 Status", function: "Statusrückmeldung" },

        // ================================================================
        // ComObjectRef translations (with {{param:}} → {{0}} templates)
        //
        // Each ref is identified by base object name + selector variant.
        // Text templates use {{param:}} which the generator resolves to
        // V20's {{0}} + TextParameterRefId mechanism.
        // ================================================================

        // Button 1 primary — per-mode refs
        obj_ref btn1_primary[Switch] { text: "Taster 1 {{btn1_description:}} Schalten", function: "Ein/Aus" },
        obj_ref btn1_primary[Dimmer] { text: "Taster 1 {{btn1_description:}} Schalten", function: "Umschalten" },
        obj_ref btn1_primary[Blind] { text: "Taster 1 {{btn1_description:}} Fahren", function: "Auf/Ab" },
        obj_ref btn1_primary[Scene] { text: "Taster 1 {{btn1_description:}} Szene", function: "Szenensteuerung" },

        // Button 1 status — Switch and Dimmer modes
        obj_ref btn1_status[Switch] { text: "Taster 1 {{btn1_description:}} Status", function: "Schaltstatus" },
        obj_ref btn1_status[Dimmer] { text: "Taster 1 {{btn1_description:}} Status", function: "Dimmstatus" },

        // Button 1 secondary — Dimmer and Blind modes
        obj_ref btn1_secondary[Dimmer] { text: "Taster 1 {{btn1_description:}} Dimmen", function: "Dimmsteuerung" },
        obj_ref btn1_secondary[Blind] { text: "Taster 1 {{btn1_description:}} Schritt", function: "Schritt/Stopp" },

        // Button 2 primary — per-mode refs
        obj_ref btn2_primary[Switch] { text: "Taster 2 {{btn2_description:}} Schalten", function: "Ein/Aus" },
        obj_ref btn2_primary[Dimmer] { text: "Taster 2 {{btn2_description:}} Schalten", function: "Umschalten" },
        obj_ref btn2_primary[Blind] { text: "Taster 2 {{btn2_description:}} Fahren", function: "Auf/Ab" },
        obj_ref btn2_primary[Scene] { text: "Taster 2 {{btn2_description:}} Szene", function: "Szenensteuerung" },

        // Button 2 status — Switch and Dimmer modes
        obj_ref btn2_status[Switch] { text: "Taster 2 {{btn2_description:}} Status", function: "Schaltstatus" },
        obj_ref btn2_status[Dimmer] { text: "Taster 2 {{btn2_description:}} Status", function: "Dimmstatus" },

        // Button 2 secondary — Dimmer and Blind modes
        obj_ref btn2_secondary[Dimmer] { text: "Taster 2 {{btn2_description:}} Dimmen", function: "Dimmsteuerung" },
        obj_ref btn2_secondary[Blind] { text: "Taster 2 {{btn2_description:}} Schritt", function: "Schritt/Stopp" },
    }
}
