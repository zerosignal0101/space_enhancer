use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CONTROL, VK_DOWN, VK_END, VK_HOME, VK_LEFT, VK_NEXT, VK_PRIOR, VK_RIGHT,
    VK_SHIFT, VK_UP, VK_BACK, VK_ADD, VK_LWIN, VK_SPACE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, KBDLLHOOKSTRUCT, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYUP, WM_SYSKEYDOWN
};

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
                wScan: 0,
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

    unsafe {
        SendInput(&mut [input], std::mem::size_of::<INPUT>() as i32);
    }
  
    *IS_SENDING_INPUT.lock().unwrap() = false;
}

/// 发送一个组合键序列（按下所有修饰符，按下目标键，释放目标键，释放所有修饰符）
fn send_transient_combo(target_key: &TargetKey) {
    *IS_SENDING_INPUT.lock().unwrap() = true;

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

/// 辅助函数：将char转换为VIRTUAL_KEY (仅对a-z和特定符号)
fn vk_code_from_char(c: char) -> Option<VIRTUAL_KEY> {
    if c >= 'a' && c <= 'z' {
        Some(VIRTUAL_KEY(c.to_ascii_uppercase() as u16))
    } else {
        match c {
            '[' => Some(VIRTUAL_KEY(0xDB)),
            ']' => Some(VIRTUAL_KEY(0xDD)),
            '.' => Some(VIRTUAL_KEY(0xBE)),
            'f' => Some(VIRTUAL_KEY('F' as u16)),
            'd' => Some(VIRTUAL_KEY('D' as u16)),
            'g' => Some(VIRTUAL_KEY('G' as u16)),
            _ => None,
        }
    }
}

/// 释放所有由脚本按下的虚拟修饰符
fn release_virtual_modifiers(active_vk_mod: VIRTUAL_KEY, activating_key_vk: VIRTUAL_KEY) {
    if activating_key_vk == vk_code_from_char('g').unwrap() {
        send_key_event(VK_SHIFT, KeyAction::Release);
        send_key_event(VK_CONTROL, KeyAction::Release); // 'g' 对应 Ctrl+Shift，所以释放 Ctrl
    } else {
        send_key_event(active_vk_mod, KeyAction::Release);
    }
}


// --- 钩子回调函数 ---
extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // 1. 如果 n_code 小于 0，必须直接调用 CallNextHookEx
    if n_code < 0 {
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
    }

    // 2. 如果是我们的模拟输入，直接传递（避免无限循环）
    if *IS_SENDING_INPUT.lock().unwrap() {
        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
    }

    let kbdllhookstruct = unsafe { *(lparam.0 as *const KBDLLHOOKSTRUCT) };
    let vk_code = VIRTUAL_KEY(kbdllhookstruct.vkCode as u16);
    let is_key_down = wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN;
    let is_key_up = wparam.0 as u32 == WM_KEYUP || wparam.0 as u32 == WM_SYSKEYUP;

    // let debug_vk_char = vk_code_to_char(vk_code).map_or(
    //     format!("VK_{:X}", vk_code.0),
    //     |c| format!("'{}'", c)
    // );
    // println!("Event: {:?} - {:?} (VK:{})", wparam, vk_code, debug_vk_char); // 调试行


    // --- Space 键按下处理 ---
    if vk_code == VK_SPACE {
        let mut space_state_guard = SPACE_STATE.lock().unwrap();
        if is_key_down {
            match *space_state_guard {
                SpaceState::NotPressed => {
                    // Space 键按下，进入等待模式，尚未触发任何组合
                    *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: false };
                    return LRESULT(1); // 消耗 Space 键的按下事件
                }
                // 如果 Space 已经处于 PressedWaiting 或 ModifierActive 状态，再次按下 Space 键时也消耗
                _ => return LRESULT(1),
            }
        } else if is_key_up {
            // Space 键被释放
            match std::mem::replace(&mut *space_state_guard, SpaceState::NotPressed) {
                SpaceState::PressedWaiting { combo_triggered_in_session } => {
                    // 如果在此Space按下期间没有触发过组合，则发送一个正常空格
                    if !combo_triggered_in_session {
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    }
                }
                SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session } => {
                    // 释放之前按下的虚拟修饰符
                    release_virtual_modifiers(active_vk_mod, activating_key_vk);
                    // 如果在此Space按下期间没有触发过组合 (在ModifierActive_状态下)，则发送一个正常空格
                    if !combo_triggered_in_session {
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    }
                }
                _ => { /* NotPressed, no action needed */ }
            }
            return LRESULT(1); // 消耗 Space 键的释放事件
        }
    }

    // --- 其他键处理（在 Space 键处于活跃状态时）---
    let mut space_state_guard = SPACE_STATE.lock().unwrap(); // 获取可变引用以便修改 combo_triggered_in_session
    let current_space_state = *space_state_guard; // 复制当前状态进行匹配

    if is_key_down {
        match current_space_state {
            SpaceState::PressedWaiting { mut combo_triggered_in_session } => {
                if let Some(c) = vk_code_to_char(vk_code) {
                    let mut triggered_combo_now = false;

                    // 1. 尝试匹配系统功能
                    if let Some(target) = KEY_MAP_SYSTEM.get().unwrap().get(&c) {
                        send_transient_combo(target);
                        triggered_combo_now = true;
                    }
                    // 2. 尝试匹配一级组合键
                    else if let Some(target) = KEY_MAP_PRIMARY.get().unwrap().get(&c) {
                        send_transient_combo(target);
                        triggered_combo_now = true;
                    }
                    // 3. 尝试匹配修饰符激活键
                    else {
                        match c {
                            'f' => {
                                send_key_event(VK_SHIFT, KeyAction::Press);
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_SHIFT, activating_key_vk: vk_code, combo_triggered_in_session: true };
                                return LRESULT(1); // 消耗此键，因为状态已改变，且已处理
                            },
                            'd' => {
                                send_key_event(VK_CONTROL, KeyAction::Press);
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: vk_code, combo_triggered_in_session: true };
                                return LRESULT(1); // 消耗此键
                            },
                            'g' => {
                                send_key_event(VK_CONTROL, KeyAction::Press);
                                send_key_event(VK_SHIFT, KeyAction::Press);
                                *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: vk_code, combo_triggered_in_session: true };
                                return LRESULT(1); // 消耗此键
                            },
                            _ => {
                                // 未匹配到任何组合或修饰符激活键，视为无效组合
                                return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // 传递原始键
                            }
                        }
                    }

                    if triggered_combo_now {
                        // 如果触发了任何组合，更新 combo_triggered_in_session 标志
                        *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session: true };
                        return LRESULT(1); // 消耗此键
                    }
                } else {
                    // 非字符键（如 Esc, Tab 等）被按下，且未在映射中，视为无效组合
                    send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    *space_state_guard = SpaceState::NotPressed;
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }
            },
            SpaceState::ModifierActive { active_vk_mod, activating_key_vk, mut combo_triggered_in_session } => {
                let mut triggered_combo_now = false;
                if let Some(c) = vk_code_to_char(vk_code) {
                    let map_to_check = if active_vk_mod == VK_SHIFT {
                        KEY_MAP_SHIFT.get().unwrap()
                    } else if activating_key_vk == vk_code_from_char('g').unwrap() {
                        KEY_MAP_CTRL_SHIFT.get().unwrap()
                    } else {
                        KEY_MAP_CTRL.get().unwrap()
                    };

                    if let Some(target_key_action) = map_to_check.get(&c) {
                        // 只需发送目标键的按下和释放事件，修饰符已经由系统按住
                        send_key_event(target_key_action.vk_code, KeyAction::Press);
                        send_key_event(target_key_action.vk_code, KeyAction::Release);
                        triggered_combo_now = true;
                    } else {
                        // 修饰符活跃状态下，按下了未映射的键，视为无效组合
                        // 释放之前按下的虚拟修饰符，发送回退空格，并重置状态
                        release_virtual_modifiers(active_vk_mod, activating_key_vk);
                        send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                        *space_state_guard = SpaceState::NotPressed;
                        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                    }
                } else {
                    // 非字符键被按下，且未在映射中，视为无效组合
                    release_virtual_modifiers(active_vk_mod, activating_key_vk);
                    send_transient_combo(&TargetKey { vk_code: VK_SPACE, modifiers: &[] });
                    *space_state_guard = SpaceState::NotPressed;
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }

                if triggered_combo_now {
                    // 如果触发了任何组合，更新 combo_triggered_in_session 标志
                    *space_state_guard = SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session: true };
                }
                return LRESULT(1); // 消耗此键
            },
            SpaceState::NotPressed => {
                // Space 键未按下，不处理此事件
            }
        }
    } else if is_key_up {
        // 如果是修饰符激活键（'f', 'd', 'g'）的释放，并且 Space 仍处于 ModifierActive 状态
        if let SpaceState::ModifierActive { active_vk_mod, activating_key_vk, combo_triggered_in_session } = current_space_state {
            if vk_code == activating_key_vk {
                // 用户释放了激活键，但 Space 仍按下。转换回 PressedWaiting 状态。
                release_virtual_modifiers(active_vk_mod, activating_key_vk);
                // 此时 SpaceState 回退，但 combo_triggered_in_session 保持原值
                *space_state_guard = SpaceState::PressedWaiting { combo_triggered_in_session };
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
    init_key_maps();

    println!("空格增强脚本已启动...");
    println!("功能说明：");
    println!("  - 按住空格 + ijkl 可连续移动光标。");
    println!("  - 按住空格 + f + ijkl 可连续选中文字 (Shift + 光标键)。");
    println!("  - 按住空格 + d + ijkl 可连续以单词移动光标 (Ctrl + 光标键)。");
    println!("  - 按住空格 + g + ijkl 可连续以单词选中文字 (Ctrl + Shift + 光标键)。");
    println!("  - 按住空格 + h / n / o / . / u / [ / ] 可执行 Home / End / PageUp / PageDown / Backspace / Win+Ctrl+Left / Win+Ctrl+Right");
    println!("  - 如果只按了空格键，松开时会输出一个普通空格。如果按住空格键期间触发了任何组合（包括修饰符激活键），松开空格键时将不会输出额外的空格。");
    println!("  - 如果在空格键按下状态下，按下了未映射的键，则会立即输出原始未映射键。");
    println!("");
    println!("请注意：本脚本运行时，控制台可能不会显示键盘输入，但功能将在其他应用程序中生效。");
    println!("关闭此窗口即可停止脚本。");

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
        eprintln!("无法设置键盘钩子: {:?}", hook_handle);
        return Err(hook_handle.unwrap_err());
    }

    println!("键盘钩子设置成功。");

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
    println!("键盘钩子已卸载。脚本退出。");

    Ok(())
}
