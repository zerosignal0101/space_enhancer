#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_DOWN, VK_END, VK_HOME, VK_LEFT, VK_NEXT, VK_PRIOR, VK_RIGHT,
    VK_SHIFT, VK_UP, VK_BACK, VK_ADD, VK_LWIN, VK_SPACE,
    VK_LCONTROL, VK_RCONTROL, VK_LMENU, VK_RMENU, VK_RWIN,
    // Add these for better readability
    VK_A, VK_B, VK_C, VK_D, VK_E, VK_F, VK_G, VK_H, VK_I, VK_J, VK_K, VK_L, VK_M,
    VK_N, VK_O, VK_P, VK_Q, VK_R, VK_S, VK_T, VK_U, VK_V, VK_W, VK_X, VK_Y, VK_Z,
    VK_OEM_1, VK_OEM_2, VK_OEM_3, VK_OEM_4, VK_OEM_5, VK_OEM_6, VK_OEM_7,
    VK_OEM_COMMA, VK_OEM_PERIOD, VK_OEM_MINUS, VK_OEM_PLUS,
    GetAsyncKeyState
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, KBDLLHOOKSTRUCT, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYUP, WM_SYSKEYDOWN,
};

use log::{debug, error, info, warn}; // Import logging macros

// --- Globals for state management ---
/// Flag to prevent our simulated inputs from recursively re-triggering the hook.
static IS_SENDING_INPUT: Mutex<bool> = Mutex::new(false);

/// Defines the state machine for the Space key.
#[derive(Debug, PartialEq, Clone, Copy)]
enum SpaceState {
    NotPressed,                  // Space key is not pressed or has been released.
    PressedWaiting {
        combo_triggered_in_session: bool, // Has any combo/modifier been triggered during this Space press cycle?
    },
    ModifierActive {
        active_vk_mod: VIRTUAL_KEY, // The actual virtual modifier pressed (e.g., VK_LSHIFT or VK_CONTROL).
        activating_key_vk: VIRTUAL_KEY, // The original key code that activated the modifier (e.g., 'F' for Shift).
        combo_triggered_in_session: bool, // Has any combo been triggered during this ModifierActive session?
    },
    PassthroughActive {
        activating_modifier: VIRTUAL_KEY, // The modifier key that activated this mode (VK_CONTROL or VK_MENU).
    },
}
static SPACE_STATE: Mutex<SpaceState> = Mutex::new(SpaceState::NotPressed);

/// Key mapping definition
#[derive(Debug, Clone)]
struct TargetKey {
    vk_code: VIRTUAL_KEY,
    modifiers: &'static [VIRTUAL_KEY],
}

// Use OnceLock to initialize static HashMaps at runtime.
static KEY_MAP_PRIMARY: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_SHIFT: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_CTRL: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_CTRL_SHIFT: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_SYSTEM: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();

/// Initializes all key mappings.
fn init_key_maps() {
    KEY_MAP_PRIMARY.set(HashMap::from([
        ('i', TargetKey { vk_code: VK_UP, modifiers: &[] }),
        ('j', TargetKey { vk_code: VK_LEFT, modifiers: &[] }),
        ('k', TargetKey { vk_code: VK_DOWN, modifiers: &[] }),
        ('l', TargetKey { vk_code: VK_RIGHT, modifiers: &[] }),
        ('h', TargetKey { vk_code: VK_HOME, modifiers: &[] }),
        ('n', TargetKey { vk_code: VK_END, modifiers: &[] }),
        ('o', TargetKey { vk_code: VK_PRIOR, modifiers: &[] }), // Page Up
        ('.', TargetKey { vk_code: VK_NEXT, modifiers: &[] }),  // Page Down
        ('u', TargetKey { vk_code: VK_BACK, modifiers: &[] }), // Backspace
    ])).expect("Failed to initialize KEY_MAP_PRIMARY");

    KEY_MAP_SHIFT.set(HashMap::from([
        ('i', TargetKey { vk_code: VK_UP, modifiers: &[VK_SHIFT] }),
        ('j', TargetKey { vk_code: VK_LEFT, modifiers: &[VK_SHIFT] }),
        ('k', TargetKey { vk_code: VK_DOWN, modifiers: &[VK_SHIFT] }),
        ('l', TargetKey { vk_code: VK_RIGHT, modifiers: &[VK_SHIFT] }),
    ])).expect("Failed to initialize KEY_MAP_SHIFT");

    KEY_MAP_CTRL.set(HashMap::from([
        ('i', TargetKey { vk_code: VK_UP, modifiers: &[VK_CONTROL] }),
        ('j', TargetKey { vk_code: VK_LEFT, modifiers: &[VK_CONTROL] }),
        ('k', TargetKey { vk_code: VK_DOWN, modifiers: &[VK_CONTROL] }),
        ('l', TargetKey { vk_code: VK_RIGHT, modifiers: &[VK_CONTROL] }),
    ])).expect("Failed to initialize KEY_MAP_CTRL");

    KEY_MAP_CTRL_SHIFT.set(HashMap::from([
        ('i', TargetKey { vk_code: VK_UP, modifiers: &[VK_CONTROL, VK_SHIFT] }),
        ('j', TargetKey { vk_code: VK_LEFT, modifiers: &[VK_CONTROL, VK_SHIFT] }),
        ('k', TargetKey { vk_code: VK_DOWN, modifiers: &[VK_CONTROL, VK_SHIFT] }),
        ('l', TargetKey { vk_code: VK_RIGHT, modifiers: &[VK_CONTROL, VK_SHIFT] }),
    ])).expect("Failed to initialize KEY_MAP_CTRL_SHIFT");

    KEY_MAP_SYSTEM.set(HashMap::from([
        ('[', TargetKey { vk_code: VK_LEFT, modifiers: &[VK_CONTROL, VK_LWIN] }),
        (']', TargetKey { vk_code: VK_RIGHT, modifiers: &[VK_CONTROL, VK_LWIN] }),
    ])).expect("Failed to initialize KEY_MAP_SYSTEM");
}

// --- Helper Functions for Sending Input ---
#[derive(Debug, Clone, Copy, PartialEq)]
enum KeyAction {
    Press,
    Release,
}

/// Sends a single key event (press or release).
fn send_key_event(vk: VIRTUAL_KEY, action: KeyAction) {
    *IS_SENDING_INPUT.lock().unwrap() = true;

    let mut input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0, // Should be 0 for virtual key
                dwFlags: {
                    let mut flags = KEYEVENTF_EXTENDEDKEY;
                    if action == KeyAction::Release {
                        flags |= KEYEVENTF_KEYUP;
                    }
                    flags
                },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };

    debug!("Sending key event: VK_{:?} with action {:?}", vk, action);
    unsafe {
        SendInput(&mut [input], std::mem::size_of::<INPUT>() as i32);
    }

    *IS_SENDING_INPUT.lock().unwrap() = false;
}

/// Sends a transient key combination (press all modifiers, press target key, release target key, release all modifiers).
fn send_transient_combo(target_key: &TargetKey) {
    *IS_SENDING_INPUT.lock().unwrap() = true;
    debug!("Sending transient combo: VK_{:?}, modifiers: {:?}", target_key.vk_code, target_key.modifiers);

    for &m_vk in target_key.modifiers {
        send_key_event(m_vk, KeyAction::Press);
    }

    send_key_event(target_key.vk_code, KeyAction::Press);
    send_key_event(target_key.vk_code, KeyAction::Release);

    for &m_vk in target_key.modifiers.iter().rev() {
        send_key_event(m_vk, KeyAction::Release);
    }

    *IS_SENDING_INPUT.lock().unwrap() = false;
}

/// Converts a virtual key code to its corresponding lowercase character.
fn vk_code_to_char(vk_code: VIRTUAL_KEY) -> Option<char> {
    if vk_code.0 >= 'A' as u16 && vk_code.0 <= 'Z' as u16 {
        return Some((vk_code.0 - 'A' as u16 + 'a' as u16) as u8 as char);
    }
    match vk_code {
        VIRTUAL_KEY(0x20) => Some(' '), // Space
        VIRTUAL_KEY(0xBA) => Some(';'), // VK_OEM_1
        VIRTUAL_KEY(0xBB) => Some('='), // VK_OEM_PLUS
        VIRTUAL_KEY(0xBC) => Some(','), // VK_OEM_COMMA
        VIRTUAL_KEY(0xBD) => Some('-'), // VK_OEM_MINUS
        VIRTUAL_KEY(0xBE) => Some('.'), // VK_OEM_PERIOD
        VIRTUAL_KEY(0xBF) => Some('/'), // VK_OEM_2
        VIRTUAL_KEY(0xC0) => Some('`'), // VK_OEM_3
        VIRTUAL_KEY(0xDB) => Some('['), // VK_OEM_4
        VIRTUAL_KEY(0xDC) => Some('\\'),// VK_OEM_5
        VIRTUAL_KEY(0xDD) => Some(']'), // VK_OEM_6
        VIRTUAL_KEY(0xDE) => Some('\''),// VK_OEM_7
        _ => None,
    }
}

/// Helper function: Converts a char to VIRTUAL_KEY (for a-z and specific symbols only), used for internal matching, does not consider layout.
fn vk_code_from_char(c: char) -> Option<VIRTUAL_KEY> {
    if c >= 'a' && c <= 'z' {
        Some(VIRTUAL_KEY(c.to_ascii_uppercase() as u16))
    } else {
        match c {
            '[' => Some(VK_OEM_4),
            ']' => Some(VK_OEM_6),
            '.' => Some(VK_OEM_PERIOD),
            _ => None,
        }
    }
}

/// Releases all virtual modifiers pressed by the script.
/// active_vk_mod: The primary activator modifier (e.g., VK_SHIFT for 'f', VK_CONTROL for 'd'/'g') stored in SpaceState.
/// activating_key_vk: The key ('f'/'d'/'g') that activated the ModifierActive state.
fn release_virtual_modifiers(active_vk_mod: VIRTUAL_KEY, activating_key_vk: VIRTUAL_KEY) {
    debug!("Releasing virtual modifiers: active_vk_mod: {:?}, activating_key_vk: {:?}", active_vk_mod, activating_key_vk);

    send_key_event(active_vk_mod, KeyAction::Release);

    // Special case for 'g' which activated Ctrl+Shift
    if activating_key_vk == VK_G { // VK_G is same as VIRTUAL_KEY('G' as u16)
        send_key_event(VK_SHIFT, KeyAction::Release);
    }
}

// --- Hook Callback Function ---
extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if n_code < 0 {
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
    }

    let kbdllhookstruct = unsafe { *(lparam.0 as *const KBDLLHOOKSTRUCT) };
    let vk_code = VIRTUAL_KEY(kbdllhookstruct.vkCode as u16);
    let is_key_down = wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN;
    let is_key_up = wparam.0 as u32 == WM_KEYUP || wparam.0 as u32 == WM_SYSKEYUP;

    let debug_vk_char = vk_code_to_char(vk_code).map_or(
        format!("VK_{:X}", vk_code.0),
        |c| format!("'{}'", c)
    );
    debug!("Event: {:?} (VK_{:X}) - {:?} ({})", wparam.0, vk_code.0, if is_key_down {"DOWN"} else {"UP"}, debug_vk_char);

    // 2. If it's our simulated input, pass it through directly (to avoid infinite loops)
    if *IS_SENDING_INPUT.lock().unwrap() {
        debug!("Input being sent by script, passing through.");
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
    }

    // Get a mutable reference to the Space state for later modification.
    let mut space_state_guard = SPACE_STATE.lock().unwrap();
    let current_space_state = *space_state_guard; // Copy current state for matching.

    // --- System Hotkey (Ctrl+Space / Alt+Space / Win+Space) Passthrough Logic ---
    
    // Case A: If currently in PassthroughActive mode, all relevant key events are passed through.
    if let SpaceState::PassthroughActive { activating_modifier } = current_space_state {
        // If Space or the activating modifier is released, exit PassthroughActive state.
        if is_key_up && (vk_code == VK_SPACE || vk_code == activating_modifier) {
            info!("PassthroughActive: Key {:?} UP received. Exiting PassthroughMode.", vk_code);
            *space_state_guard = SpaceState::NotPressed;
        }
        debug!("PassthroughActive: Key VK_{:X} ({}) event. Passing through (returning LRESULT(0)).", vk_code.0, debug_vk_char);
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // In PassthroughActive mode, all keys pass through.
    }

    // Case B: Detect if Space is pressed simultaneously with Ctrl/Alt/Win (Space DOWN, Ctrl/Alt/Win ALREADY DOWN).
    if vk_code == VK_SPACE && is_key_down {
        let is_ctrl_currently_down = (unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) } as u16 & 0x8000) != 0;
        let is_alt_currently_down = (unsafe { GetAsyncKeyState(VK_MENU.0 as i32) } as u16 & 0x8000) != 0;
        let is_win_currently_down = (unsafe { GetAsyncKeyState(VK_LWIN.0 as i32) } as u16 & 0x8000) != 0;

        if is_ctrl_currently_down || is_alt_currently_down || is_win_currently_down { // Added Win key check
            info!("Space DOWN detected with system modifier (Ctrl/Alt/Win) already held. Bypassing custom Space logic to allow native system hotkey.");
            let activating_modifier = if is_ctrl_currently_down { VK_CONTROL } else if is_alt_currently_down { VK_MENU } else { VK_LWIN };
            *space_state_guard = SpaceState::PassthroughActive { activating_modifier };
            // Return LRESULT(0) directly here, allowing the Space event to pass through and not be consumed.
            return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
        }
    }

    // Case C: Detect if Ctrl/Alt/Win is pressed while Space is already active (PressedWaiting) (Space HELD, Ctrl/Alt/Win DOWN).
    if (vk_code == VK_CONTROL || vk_code == VK_MENU || vk_code == VK_LWIN) && is_key_down { // Added Win key check
        if let SpaceState::PressedWaiting { .. } = current_space_state {
            info!("System modifier (Ctrl/Alt/Win) DOWN detected while Space is held (by our script). Un-consuming Space and enabling passthrough for native system hotkey.");
            // At this point, Space has already been consumed by us, so the system hasn't received its DOWN event.
            // We need to send a virtual Space DOWN event to let the system think Space is pressed.
            send_key_event(VK_SPACE, KeyAction::Press); // Correct the system's perception of Space key's DOWN state.
            *space_state_guard = SpaceState::PassthroughActive { activating_modifier: vk_code };
            // Then let this Ctrl/Alt/Win key's DOWN event also pass through.
            return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
        }
    }

    // --- END of System Hotkey Passthrough Logic ---

    // If the above system hotkey logic did not trigger, continue processing Space itself or other combinations.

    // --- Space Key Press/Release Handling ---
    if vk_code == VK_SPACE {
        if is_key_down {
            match *space_state_guard {
                SpaceState::NotPressed => {
                    info!("Space DOWN: Entering PressedWaiting state.");
                    *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: false };
                    return LRESULT(1); // Consume the Space key's DOWN event.
                }
                _ => { // should not happen if logic is correct, but consume if it does
                    debug!("Space DOWN: Already in Space state, consume and return.");
                    return LRESULT(1);
                }
            }
        } else if is_key_up {
            // Space key is released.
            info!("Space UP: Exiting Space state.");
            match std::mem::replace(&mut *space_state_guard, SpaceState::NotPressed) {
                SpaceState::PressedWaiting { combo_triggered_in_session } => {
                    if !combo_triggered_in_session {
                        info!("Space UP: No combo triggered, sending a normal space.");
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    } else {
                        info!("Space UP: Combo triggered in PressedWaiting, no extra space.");
                    }
                }
                SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session } => {
                    info!("Space UP: Exiting ModifierActive state. Releasing virtual modifiers.");
                    release_virtual_modifiers(active_vk_mod, activating_key_vk);
                    if !combo_triggered_in_session {
                        info!("Space UP: No combo triggered in ModifierActive, sending a normal space.");
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    } else {
                        info!("Space UP: Combo triggered in ModifierActive, no extra space.");
                    }
                }
                // If Space UP is received in NotPressed or PassthroughActive state, it's unexpected, but ignore it.
                _ => { warn!("Space UP: Unexpected state, no action needed."); }
            }
            return LRESULT(1); // Consume the Space key's UP event.
        }
    }

    // --- Other Key Handling (when Space key is active) ---
    let space_state_after_space_key_check = *space_state_guard; // Re-read the latest state.

    if is_key_down {
        match space_state_after_space_key_check {
            SpaceState::PressedWaiting { combo_triggered_in_session: mut current_session_triggered_flag } => {
                debug!("Key DOWN in PressedWaiting state: VK_{:X}", vk_code.0);
                if let Some(c) = vk_code_to_char(vk_code) {
                    let mut triggered_combo_now = false;

                    // 1. Try to match system functionality
                    if let Some(target) = KEY_MAP_SYSTEM.get().unwrap().get(&c) {
                        info!("PressedWaiting: Matched system combo '{}'. Sending combo.", c);
                        send_transient_combo(target);
                        triggered_combo_now = true;
                    }
                    // 2. Try to match primary combinations
                    else if let Some(target) = KEY_MAP_PRIMARY.get().unwrap().get(&c) {
                        info!("PressedWaiting: Matched primary combo '{}'. Sending combo.", c);
                        send_transient_combo(target);
                        triggered_combo_now = true;
                    }
                    // 3. Try to match modifier activation keys
                    else {
                        match vk_code {
                            VK_F => {
                                info!("PressedWaiting: Activated Shift modifier with 'F'.");
                                send_key_event(VK_SHIFT, KeyAction::Press);
                                // Update the state in the guard.
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_SHIFT, activating_key_vk: VK_F, combo_triggered_in_session: true };
                                return LRESULT(1);
                            },
                            VK_D => {
                                info!("PressedWaiting: Activated Ctrl modifier with 'D'.");
                                send_key_event(VK_CONTROL, KeyAction::Press);
                                // Update the state in the guard.
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: VK_D, combo_triggered_in_session: true };
                                return LRESULT(1);
                            },
                            VK_G => {
                                info!("PressedWaiting: Activated Ctrl+Shift modifier with 'G'.");
                                send_key_event(VK_CONTROL, KeyAction::Press);
                                send_key_event(VK_SHIFT, KeyAction::Press);
                                // Update the state in the guard.
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: VK_G, combo_triggered_in_session: true };
                                return LRESULT(1);
                            },
                            _ => {
                                // No match found for any combination or modifier activation key, treat as invalid combo.
                                info!("PressedWaiting: Unrecognized key '{}', passing through original key.", c);
                                *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true }; // Reset for next combo.
                                return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // Pass through original key.
                            }
                        }
                    }

                    if triggered_combo_now {
                        // If any combo was triggered, update the combo_triggered_in_session flag.
                        // Directly modify the state in the guard.
                        *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true };
                        return LRESULT(1); // Consume this key.
                    }
                } else {
                    // Non-character key (like Esc, Tab, etc.) pressed, and not in mappings, treat as invalid combo.
                    info!("PressedWaiting: Non-char key VK_{:X}, passing through original key.", vk_code.0);
                    *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true };
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }
            },
            SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session: mut current_session_triggered_flag } => {
                debug!("Key DOWN in ModifierActive state: VK_{:X}, active_mod: {:?}, activating_key: {:?}", vk_code.0, active_vk_mod, activating_key_vk);
                let mut triggered_combo_now = false;

                if let Some(c) = vk_code_to_char(vk_code) {
                    let map_to_check = if active_vk_mod == VK_SHIFT {
                        KEY_MAP_SHIFT.get().unwrap()
                    } else if activating_key_vk == VK_G {
                        KEY_MAP_CTRL_SHIFT.get().unwrap()
                    } else { // active_vk_mod == VK_CONTROL
                        KEY_MAP_CTRL.get().unwrap()
                    };

                    if let Some(target_key_action) = map_to_check.get(&c) {
                        info!("ModifierActive: Matched combo '{}' with active mod. Sending target key.", c);
                        send_key_event(target_key_action.vk_code, KeyAction::Press);
                        send_key_event(target_key_action.vk_code, KeyAction::Release);
                        triggered_combo_now = true;
                    } else {
                        info!("ModifierActive: Unrecognized key '{}' with active mod. Releasing mods and passing through original key.", c);
                        release_virtual_modifiers(active_vk_mod, activating_key_vk);
                        *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true };
                        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                    }
                } else {
                    info!("ModifierActive: Non-char key VK_{:X} with active mod. Passing through original key.", vk_code.0);
                    release_virtual_modifiers(active_vk_mod, activating_key_vk);
                    *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true };
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }

                if triggered_combo_now {
                    // Update the state in the guard.
                    *space_state_guard = SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session: true };
                }
                return LRESULT(1); // Consume this key.
            },
            _ => { // NotPressed, PassthroughActive - no action needed.
                // debug!("Key DOWN (VK_{:X}) in inactive or passthrough state. Passing through.", vk_code.0);
            }
        }
    } else if is_key_up {
        // If it's the release of a modifier activation key ('f', 'd', 'g') and Space is still in ModifierActive state.
        if let SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session } = space_state_after_space_key_check { // Use the latest state.
            if vk_code == activating_key_vk {
                info!("Activating key '{:?}' UP. Releasing mods and transitioning to PressedWaiting.", vk_code);
                release_virtual_modifiers(active_vk_mod, activating_key_vk);
                // SpaceState rolls back, but combo_triggered_in_session retains its value.
                *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session }; // Update the state in the guard.
                return LRESULT(1); // Consume this key release.
            }
        }
    }

    // Default behavior: Pass the event to the next hook (if our logic hasn't consumed it).
    unsafe {
        CallNextHookEx(None, n_code, wparam, lparam)
    }
}

fn main() -> windows::core::Result<()> {
    // Initialize env_logger. Default: INFO level.
    // Set RUST_LOG=debug for detailed debug output.
    // e.g. RUST_LOG=debug cargo run
    // or RUST_LOG=info,space_enhancer=debug cargo run
    env_logger::init();

    init_key_maps();

    info!("Space Enhancer script started...");
    info!("Features:");
    info!("  - Hold Space + ijkl to continuously move the cursor.");
    info!("  - Hold Space + f + ijkl to continuously select text (Shift + Cursor Keys).");
    info!("  - Hold Space + d + ijkl to continuously move the cursor by word (Ctrl + Cursor Keys).");
    info!("  - Hold Space + g + jl to continuously select text by word (Ctrl + Shift + Cursor Keys).");
    info!("  - Hold Space + h / n / o / . / u / [ / ] for Home / End / PageUp / PageDown / Backspace / Win+Ctrl+Left / Win+Ctrl+Right");
    info!("  - If only the Space key is pressed, it will output a normal space upon release. If any combo (including modifier activation keys) is triggered while Space is held, no extra space will be output upon Space release.");
    info!("  - If an unmapped key is pressed while Space is held, it will let the original unmapped key pass through, no extra space will be output upon Space release.");
    info!("");
    info!("Please note: This script will not display a console in Release mode. In Debug mode, the console will show debug information.");
    info!("Close this window to stop the script.");

    let h_instance = unsafe { windows::Win32::System::LibraryLoader::GetModuleHandleA(None)? };

    let hook_handle = unsafe {
        SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(low_level_keyboard_proc),
            h_instance,
            0,
        )
    };

    if hook_handle.is_err() {
        error!("Failed to set keyboard hook: {:?}", hook_handle);
        return Err(hook_handle.unwrap_err());
    }

    info!("Keyboard hook set successfully.");

    let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).into() {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    unsafe {
        UnhookWindowsHookEx(hook_handle.unwrap());
    }
    info!("Keyboard hook uninstalled. Script exiting.");

    Ok(())
}
