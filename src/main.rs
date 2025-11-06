#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CONTROL, VK_MENU, VK_DOWN, VK_END, VK_HOME, VK_LEFT, VK_NEXT, VK_PRIOR, VK_RIGHT,
    VK_SHIFT, VK_UP, VK_BACK, VK_ADD, VK_LWIN, VK_SPACE,
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

use log::{debug, info, error}; // 导入日志宏

// --- Globals for state management ---
/// 标志位，防止发送我们自己的模拟输入时再次触发钩子
static IS_SENDING_INPUT: Mutex<bool> = Mutex::new(false);

/// 定义 Space 键的状态机
#[derive(Debug, PartialEq, Clone, Copy)]
enum SpaceState {
    NotPressed,                  // Space 键未按下或已释放
    PressedWaiting {
        combo_triggered_in_session: bool, // 此 Space 按下周期内是否触发过组合
    },
    ModifierActive {
        active_vk_mod: VIRTUAL_KEY, // 激活的实际修饰符，如 VK_LSHIFT 或 VK_CONTROL
        activating_key_vk: VIRTUAL_KEY, // 激活修饰符的原始键码，如 'F'
        combo_triggered_in_session: bool, // 此 Space 按下周期内是否触发过组合
    },
    PassthroughActive {
        activating_modifier: VIRTUAL_KEY, // 激活此模式的修饰键 (VK_CONTROL 或 VK_MENU)
    },
}
static SPACE_STATE: Mutex<SpaceState> = Mutex::new(SpaceState::NotPressed);

/// 键位映射
#[derive(Debug, Clone)]
struct TargetKey {
    vk_code: VIRTUAL_KEY,
    modifiers: &'static [VIRTUAL_KEY],
}

// 使用 OnceLock 在运行时初始化静态 HashMap
static KEY_MAP_PRIMARY: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_SHIFT: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_CTRL: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_CTRL_SHIFT: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();
static KEY_MAP_SYSTEM: OnceLock<HashMap<char, TargetKey>> = OnceLock::new();

/// 初始化所有键位映射
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

/// 发送单个按键事件（按下或释放）
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

/// 发送一个组合键序列（按下所有修饰符，按下目标键，释放目标键，释放所有修饰符）
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

/// 将虚拟键码转换为字符
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

/// 辅助函数：将char转换为VIRTUAL_KEY (仅对a-z和特定符号)，用于内部匹配，不考虑布局
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

/// 释放所有由脚本按下的虚拟修饰符
/// active_vk_mod: 存储在 SpaceState 中表示当前激活的主要修饰符 (e.g., VK_SHIFT for 'f', VK_CONTROL for 'd'/'g')
/// activating_key_vk: 记录哪个键 ('f'/'d'/'g') 激活了 ModifierActive 状态
fn release_virtual_modifiers_optimized(active_vk_mod: VIRTUAL_KEY, activating_key_vk: VIRTUAL_KEY) {
    debug!("Releasing virtual modifiers: active_vk_mod: {:?}, activating_key_vk: {:?}", active_vk_mod, activating_key_vk);

    send_key_event(active_vk_mod, KeyAction::Release);

    // Special case for 'g' which activated Ctrl+Shift
    if activating_key_vk == VK_G { // VK_G is same as VIRTUAL_KEY('G' as u16)
        send_key_event(VK_SHIFT, KeyAction::Release);
    }
}


// --- 钩子回调函数 ---
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

    // 2. 如果是我们的模拟输入，直接传递（避免无限循环）
    if *IS_SENDING_INPUT.lock().unwrap() {
        debug!("Input being sent by script, passing through.");
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
    }

    // 获取 Space 状态的可变引用，以便后续修改
    let mut space_state_guard = SPACE_STATE.lock().unwrap();
    let current_space_state = *space_state_guard; // 复制当前状态用于匹配

    // --- 系统热键（Ctrl+Space / Alt+Space）穿透逻辑 ---

    // 情况 A: 如果当前处于 PassthroughActive 模式，则所有相关按键都直接放行
    if let SpaceState::PassthroughActive { activating_modifier } = current_space_state {
        // 如果 Space 键或激活的修饰键被释放，根据情况退出 PassthroughActive 状态
        if is_key_up && (vk_code == VK_SPACE || vk_code == activating_modifier) {
            let is_space_still_down = (unsafe { GetAsyncKeyState(VK_SPACE.0 as i32) } as u16 & 0x8000) != 0;
            let is_mod_still_down = (unsafe { GetAsyncKeyState(activating_modifier.0 as i32) } as u16 & 0x8000) != 0;

            // 只有当 Space 和激活的修饰键都被释放时，才退出 PassthroughActive
            if !is_space_still_down && !is_mod_still_down {
                info!("PassthroughActive: All relevant keys released. Exiting PassthroughMode.");
                *space_state_guard = SpaceState::NotPressed;
            } else {
                debug!("PassthroughActive: Key {:?} UP, but other keys still down. Remaining in PassthroughMode.", vk_code);
            }
        }
        debug!("PassthroughActive: Key VK_{:X} ({}) event. Passing through (returning LRESULT(0)).", vk_code.0, debug_vk_char);
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // 在PassthroughActive模式下，所有键都通过
    }

    // 情况 B: 检测 Space 键是否与 Ctrl/Alt 同时按下 (Space DOWN, Ctrl/Alt ALREADY DOWN)
    if vk_code == VK_SPACE && is_key_down {
        let is_ctrl_currently_down = (unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) } as u16 & 0x8000) != 0;
        let is_alt_currently_down = (unsafe { GetAsyncKeyState(VK_MENU.0 as i32) } as u16 & 0x8000) != 0;

        if is_ctrl_currently_down || is_alt_currently_down {
            info!("Space DOWN detected with system modifier (Ctrl/Alt) already held. Bypassing custom Space logic to allow native system hotkey.");
            let activating_modifier = if is_ctrl_currently_down { VK_CONTROL } else { VK_MENU };
            *space_state_guard = SpaceState::PassthroughActive { activating_modifier };
            // 这里直接返回 LRESULT(0)，让 Space 事件通过，不被消耗
            return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
        }
    }

    // 情况 C: 检测 Ctrl/Alt 键是否在 Space 已经激活 (PressedWaiting) 时按下 (Space HELD, Ctrl/Alt DOWN)
    if (vk_code == VK_CONTROL || vk_code == VK_MENU) && is_key_down {
        if let SpaceState::PressedWaiting { .. } = current_space_state {
            info!("System modifier (Ctrl/Alt) DOWN detected while Space is held (by our script). Un-consuming Space and enabling passthrough for native system hotkey.");
            // 此时 Space 已经被我们消耗了，系统没有收到它的 DOWN 事件。
            // 我们需要发送一个虚拟的 Space DOWN 事件，让系统认为 Space 已经按下了。
            send_key_event(VK_SPACE, KeyAction::Press); // 修复系统对 Space 键的 DOWN 状态认知
            *space_state_guard = SpaceState::PassthroughActive { activating_modifier: vk_code };
            // 然后让这个 Ctrl/Alt 键的 DOWN 事件也通过
            return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
        }
    }

    // --- END of 系统热键穿透逻辑 ---

    // 如果以上系统热键逻辑没有触发，则继续处理 Space 本身或其他组合键

    // --- Space 键按下/抬起处理 ---
    if vk_code == VK_SPACE {
        if is_key_down {
            match *space_state_guard {
                SpaceState::NotPressed => {
                    info!("Space DOWN: Entering PressedWaiting state.");
                    *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: false };
                    return LRESULT(1); // 消耗 Space 键的按下事件
                }
                _ => { // should not happen if logic is correct, but consume if it does
                    debug!("Space DOWN: Already in Space state, consume and return.");
                    return LRESULT(1);
                }
            }
        } else if is_key_up {
            // Space 键被释放
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
                    release_virtual_modifiers_optimized(active_vk_mod, activating_key_vk);
                    if !combo_triggered_in_session {
                        info!("Space UP: No combo triggered in ModifierActive, sending a normal space.");
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    } else {
                        info!("Space UP: Combo triggered in ModifierActive, no extra space.");
                    }
                }
                // 如果在 NotPressed 或 PassthroughActive 状态下收到 Space UP，理论上不应该，但如果发生了就忽略
                _ => { debug!("Space UP: Unexpected state, no action needed."); }
            }
            return LRESULT(1); // 消耗 Space 键的释放事件
        }
    }

    // --- 其他键处理（在 Space 键处于活跃状态时）---
    let space_state_after_space_key_check = *space_state_guard; // 重新读取最新状态

    if is_key_down {
        match space_state_after_space_key_check {
            SpaceState::PressedWaiting { combo_triggered_in_session: mut current_session_triggered_flag } => {
                debug!("Key DOWN in PressedWaiting state: VK_{:X}", vk_code.0);
                if let Some(c) = vk_code_to_char(vk_code) {
                    let mut triggered_combo_now = false;

                    // 1. 尝试匹配系统功能
                    if let Some(target) = KEY_MAP_SYSTEM.get().unwrap().get(&c) {
                        info!("PressedWaiting: Matched system combo '{:?}'. Sending combo.", c);
                        send_transient_combo(target);
                        triggered_combo_now = true;
                    }
                    // 2. 尝试匹配一级组合键
                    else if let Some(target) = KEY_MAP_PRIMARY.get().unwrap().get(&c) {
                        info!("PressedWaiting: Matched primary combo '{:?}'. Sending combo.", c);
                        send_transient_combo(target);
                        triggered_combo_now = true;
                    }
                    // 3. 尝试匹配修饰符激活键
                    else {
                        match vk_code {
                            VK_F => {
                                info!("PressedWaiting: Activated Shift modifier with 'F'.");
                                send_key_event(VK_SHIFT, KeyAction::Press);
                                // 更新 guard 中的状态
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_SHIFT, activating_key_vk: VK_F, combo_triggered_in_session: true };
                                return LRESULT(1);
                            },
                            VK_D => {
                                info!("PressedWaiting: Activated Ctrl modifier with 'D'.");
                                send_key_event(VK_CONTROL, KeyAction::Press);
                                // 更新 guard 中的状态
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: VK_D, combo_triggered_in_session: true };
                                return LRESULT(1);
                            },
                            VK_G => {
                                info!("PressedWaiting: Activated Ctrl+Shift modifier with 'G'.");
                                send_key_event(VK_CONTROL, KeyAction::Press);
                                send_key_event(VK_SHIFT, KeyAction::Press);
                                // 更新 guard 中的状态
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: VK_G, combo_triggered_in_session: true };
                                return LRESULT(1);
                            },
                            _ => {
                                // 未匹配到任何组合或修饰符激活键，视为无效组合
                                info!("PressedWaiting: Unrecognized key '{:?}', passing through original key.", c);
                                send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] }); // 发送回退空格
                                *space_state_guard = SpaceState::NotPressed; // Reset for next Space press
                                return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // 传递原始键
                            }
                        }
                    }

                    if triggered_combo_now {
                        // 如果触发了任何组合，更新 combo_triggered_in_session 标志
                        // 直接修改 guard 中的状态
                        *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true };
                        return LRESULT(1); // 消耗此键
                    }
                } else {
                    // 非字符键（如 Esc, Tab 等）被按下，且未在映射中，视为无效组合
                    info!("PressedWaiting: Non-char key VK_{:X}, passing through original key after sending fallback space.", vk_code.0);
                    send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    *space_state_guard = SpaceState::NotPressed;
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
                        info!("ModifierActive: Matched combo '{:?}' with active mod. Sending target key.", c);
                        send_key_event(target_key_action.vk_code, KeyAction::Press);
                        send_key_event(target_key_action.vk_code, KeyAction::Release);
                        triggered_combo_now = true;
                    } else {
                        info!("ModifierActive: Unrecognized key '{:?}' with active mod. Releasing mods and passing original key after fallback space.", c);
                        release_virtual_modifiers_optimized(active_vk_mod, activating_key_vk);
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                        *space_state_guard = SpaceState::NotPressed;
                        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                    }
                } else {
                    info!("ModifierActive: Non-char key VK_{:X} with active mod. Releasing mods and passing original key after fallback space.", vk_code.0);
                    release_virtual_modifiers_optimized(active_vk_mod, activating_key_vk);
                    send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    *space_state_guard = SpaceState::NotPressed;
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }

                if triggered_combo_now {
                    // 更新 guard 中的状态
                    *space_state_guard = SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session: true };
                }
                return LRESULT(1); // 消耗此键
            },
            _ => { // NotPressed, PassthroughActive - 不做处理
                // debug!("Key DOWN (VK_{:X}) in inactive or passthrough state. Passing through.", vk_code.0);
            }
        }
    } else if is_key_up {
        // 如果是修饰符激活键（'f', 'd', 'g'）的释放，并且 Space 仍处于 ModifierActive 状态
        if let SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session } = space_state_after_space_key_check { // 使用最新的状态
            if vk_code == activating_key_vk {
                info!("Activating key '{:?}' UP. Releasing mods and transitioning to PressedWaiting.", vk_code);
                release_virtual_modifiers_optimized(active_vk_mod, activating_key_vk);
                // 此时 SpaceState 回退，但 combo_triggered_in_session 保持原值
                *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session }; // 更新 guard 中的状态
                return LRESULT(1); // 消耗此键的释放
            }
        }
    }

    // 默认行为：将事件传递给下一个钩子（如果我们的逻辑没有消耗它）
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

    info!("空格增强脚本已启动...");
    info!("功能说明：");
    info!("  - 按住空格 + ijkl 可连续移动光标。");
    info!("  - 按住空格 + f + ijkl 可连续选中文字 (Shift + 光标键)。");
    info!("  - 按住空格 + d + ijkl 可连续以单词移动光标 (Ctrl + 光标键)。");
    info!("  - 按住空格 + g + ijkl 可连续以单词选中文字 (Ctrl + Shift + 光标键)。");
    info!("  - 按住空格 + h / n / o / . / u / [ / ] 可执行 Home / End / PageUp / PageDown / Backspace / Win+Ctrl+Left / Win+Ctrl+Right");
    info!("  - 如果只按了空格键，松开时会输出一个普通空格。如果按住空格键期间触发了任何组合（包括修饰符激活键），松开空格键时将不会输出额外的空格。");
    info!("  - 如果在空格键按下状态下，按下了未映射的键，则会立即输出原始未映射键。");
    info!("");
    info!("请注意：本脚本在 Release 模式下不会显示控制台。在 Debug 模式下，控制台将显示调试信息。");
    info!("关闭此窗口即可停止脚本。");

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
        error!("无法设置键盘钩子: {:?}", hook_handle);
        return Err(hook_handle.unwrap_err());
    }

    info!("键盘钩子设置成功。");

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
    info!("键盘钩子已卸载。脚本退出。");

    Ok(())
}
