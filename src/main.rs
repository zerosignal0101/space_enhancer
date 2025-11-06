use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use windows::Win32::Foundation::{HMODULE, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_CONTROL, VK_DOWN, VK_END, VK_HOME, VK_LEFT, VK_NEXT, VK_PRIOR, VK_RIGHT,
    VK_SHIFT, VK_UP, VK_BACK, VK_ADD, VK_LWIN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, KBDLLHOOKSTRUCT, MSLLHOOKSTRUCT, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYUP, WM_SYSKEYDOWN
};

// --- Globals for state management ---
/// 标志位，防止发送我们自己的模拟输入时再次触发钩子
static IS_SENDING_INPUT: Mutex<bool> = Mutex::new(false);

/// 定义 Space 键的状态机
#[derive(Debug, PartialEq, Clone, Copy)]
enum SpaceState {
    NotPressed,                  // Space 键未按下或已释放
    PressedWaiting,              // Space 键已按下，等待组合键或释放
    ModifierActive {             // Space + 修饰符激活键（f/d/g）已按下
        active_vk_mod: VIRTUAL_KEY, // 激活的实际修饰符，如 VK_LSHIFT
        activating_key_vk: VIRTUAL_KEY, // 激活修饰符的原始键码，如 'F'
    },
    ComboEngaged,                // Space + 组合键已按下并触发一个功能
}
static SPACE_STATE: Mutex<SpaceState> = Mutex::new(SpaceState::NotPressed);

/// 键位映射
#[derive(Debug)]
struct TargetKey {
    vk_code: VIRTUAL_KEY,
    modifiers: &'static [VIRTUAL_KEY], // 目标功能可能携带的额外修饰符
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
        ('j', TargetKey { vk_code: VK_LEFT, modifiers: &[VK_CONTROL, VK_SHIFT] }),
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
    // 临时设置 IS_SENDING_INPUT 为 true，避免钩子再次处理我们自己的事件
    *IS_SENDING_INPUT.lock().unwrap() = true;

    let mut input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: 0, // Should be 0 for virtual key codes
                dwFlags: {
                    let mut flags = KEYEVENTF_EXTENDEDKEY; // For special keys like arrow keys, etc.
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
    
    // 恢复 IS_SENDING_INPUT 标志
    *IS_SENDING_INPUT.lock().unwrap() = false;
}

/// 发送组合按键事件 (Modifier + TargetKey)
/// 注意: 这里的 modifiers 是指目标功能本身带有的修饰符，例如 Shift+方向键
/// 已经激活的 ModifierActive 状态中的修饰符，无需在此处再次按下，系统会知道它们已经按下。
fn send_combined_input(target_vk: VIRTUAL_KEY, modifiers: &[VIRTUAL_KEY]) {
    *IS_SENDING_INPUT.lock().unwrap() = true;

    // 按下所有修饰符
    for &m_vk in modifiers {
        send_key_event(m_vk, KeyAction::Press);
    }

    // 按下目标键
    send_key_event(target_vk, KeyAction::Press);
    // 释放目标键
    send_key_event(target_vk, KeyAction::Release);

    // 释放所有修饰符 (按相反的顺序释放是好习惯)
    for &m_vk in modifiers.iter().rev() {
        send_key_event(m_vk, KeyAction::Release);
    }

    *IS_SENDING_INPUT.lock().unwrap() = false;
}

/// 将虚拟键码转换为字符（主要用于调试/日志，或与char类型映射进行比较）
fn vk_code_to_char(vk_code: VIRTUAL_KEY) -> Option<char> {
    // 简单地将一些常用的字母键码转换为小写字符
    if vk_code.0 >= 'A' as u16 && vk_code.0 <= 'Z' as u16 {
        return Some((vk_code.0 - 'A' as u16 + 'a' as u16) as u8 as char);
    }
    match vk_code {
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
        _ => {
            // 对于数字或特殊符号等，直接转换可能不准确，这里简化处理
            None
        }
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

    let debug_vk_char = vk_code_to_char(vk_code).map_or(
        format!("VK_{:X}", vk_code.0),
        |c| format!("'{}'", c)
    );
    // println!("Event: {:?} - {:?} (VK:{})", wparam, vk_code, debug_vk_char);

    // --- Space 键按下处理 ---
    if vk_code == VIRTUAL_KEY(0x20) { // VK_SPACE
        let mut space_state_guard = SPACE_STATE.lock().unwrap();
        if is_key_down {
            match *space_state_guard {
                SpaceState::NotPressed => {
                    *space_state_guard = SpaceState::PressedWaiting;
                    // println!("[SPACE] -> PressedWaiting (Consumed)");
                    return LRESULT(1); // 消耗 Space 键的按下事件
                }
                // 如果 Space 已经处于 PressedWaiting 或 ComboEngaged 状态，再次按下 Space 键时也消耗
                _ => return LRESULT(1),
            }
        } else if is_key_up {
            // Space 键被释放
            match std::mem::replace(&mut *space_state_guard, SpaceState::NotPressed) {
                SpaceState::PressedWaiting => {
                    // Space 键被释放时未触发任何组合，模拟发送一个空格
                    // println!("[SPACE] -> PressedWaiting -> NotPressed (Emitting single Space)");
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Press);
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Release);
                }
                SpaceState::ModifierActive { active_vk_mod, activating_key_vk: _ } => {
                    // Space + 激活修饰符键被按下，但 Space 在没有触发最终组合时释放
                    // 释放之前按下的虚拟修饰符，并发送一个空格作为回退
                    // println!("[SPACE] -> ModifierActive -> NotPressed (Releasing {:?}, Emitting single Space)",active_vk_mod);
                    send_key_event(active_vk_mod, KeyAction::Release);
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Press);
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Release);
                }
                // ComboEngaged 或 NotPressed (不应该在 KeyUp 路径中)
                _ => {
                    // 组合已完成，Space 释放无需额外操作
                    // println!("[SPACE] -> ComboEngaged -> NotPressed (No additional action)");
                }
            }
            return LRESULT(1); // 消耗 Space 键的释放事件
        }
    }

    // --- 其他键处理（在 Space 键处于活跃状态时）---
    let current_space_state = SPACE_STATE.lock().unwrap().clone();
    if is_key_down {
        match current_space_state {
            SpaceState::PressedWaiting => {
                let mut space_state_guard = SPACE_STATE.lock().unwrap();
                // 尝试将 vk_code 转换为 char 进行映射
                if let Some(c) = vk_code_to_char(vk_code) {
                    // 1. 尝试匹配系统功能 (Space + [ 或 Space + ])
                    if let Some(target) = KEY_MAP_SYSTEM.get().unwrap().get(&c) {
                        // println!("[COMBO] Space + '{}' -> System {:?}", c, target.vk_code);
                        send_combined_input(target.vk_code, target.modifiers);
                        *space_state_guard = SpaceState::ComboEngaged;
                        return LRESULT(1);
                    }
                    // 2. 尝试匹配一级组合键
                    if let Some(target) = KEY_MAP_PRIMARY.get().unwrap().get(&c) {
                        // println!("[COMBO] Space + '{}' -> Primary Key {:?}", c, target.vk_code);
                        send_combined_input(target.vk_code, target.modifiers);
                        *space_state_guard = SpaceState::ComboEngaged;
                        return LRESULT(1); // 消耗此键
                    }
                    // 3. 尝试匹配修饰符激活键 (f, d, g)
                    match c {
                        'f' => {
                            // println!("[MODIFIER] Space + 'f' -> ModifierActive(Shift)");
                            send_key_event(VK_SHIFT, KeyAction::Press);
                            *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_SHIFT, activating_key_vk: vk_code };
                            return LRESULT(1); // 消耗此键
                        },
                        'd' => {
                            // println!("[MODIFIER] Space + 'd' -> ModifierActive(Ctrl)");
                            send_key_event(VK_CONTROL, KeyAction::Press);
                            *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: vk_code };
                            return LRESULT(1); // 消耗此键
                        },
                        'g' => {
                            // println!("[MODIFIER] Space + 'g' -> ModifierActive(Ctrl+Shift)");
                            send_key_event(VK_CONTROL, KeyAction::Press);
                            send_key_event(VK_SHIFT, KeyAction::Press);
                            // 注意：这里我们选择 VK_CONTROL 作为主修饰符，因为 g 触发 Ctrl+Shift
                            *space_state_guard = SpaceState::ModifierActive { active_vk_mod: VK_CONTROL, activating_key_vk: vk_code };
                            return LRESULT(1); // 消耗此键
                        },
                        _ => {
                            // 未匹配到任何组合或修饰符激活键
                            // println!("[FALLBACK] Space + '{}' -> Emitting Space, passing through original key", c);
                            send_key_event(VIRTUAL_KEY(0x20), KeyAction::Press); // 模拟发出一个空格
                            send_key_event(VIRTUAL_KEY(0x20), KeyAction::Release);
                            *space_state_guard = SpaceState::NotPressed; // 重置状态
                            return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // 传递原始键
                        }
                    }
                } else {
                    // 非字符键（如 Esc, Tab 等）被按下，且未在映射中，视为误操作
                    // println!("[FALLBACK] Space + non-char-key -> Emitting Space, passing through original key");
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Press);
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Release);
                    *space_state_guard = SpaceState::NotPressed;
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }
            },
            SpaceState::ModifierActive { active_vk_mod, activating_key_vk } => {
                let mut space_state_guard = SPACE_STATE.lock().unwrap();
                if let Some(c) = vk_code_to_char(vk_code) {
                    let mut target: Option<&TargetKey> = None;

                    if active_vk_mod == VK_SHIFT {
                        target = KEY_MAP_SHIFT.get().unwrap().get(&c);
                    } else if active_vk_mod == VK_CONTROL {
                        // 如果激活键是 'g'，则应该检查 Ctrl+Shift 映射
                        if activating_key_vk == vk_code_from_char('g').unwrap() {
                            target = KEY_MAP_CTRL_SHIFT.get().unwrap().get(&c);
                        } else { // 否则是 'd' 激活的 Ctrl
                            target = KEY_MAP_CTRL.get().unwrap().get(&c);
                        }
                    }

                    if let Some(target_key_action) = target {
                        // println!("[COMBO] Space + Mod({:?}) + '{}' -> {:?}", active_vk_mod, c, target_key_action.vk_code);
                        // 由于修饰符已经通过 SendInput 处于按下状态，这里只需发送目标键
                        // 但是为了确保完整性，我们调用 send_combined_input 明确释放它。
                        // send_combined_input 内部会再次按下它并释放，然后释放我们已经按下的修饰符。
                        // 这样有点冗余，但更可靠地处理了释放。
                        send_combined_input(target_key_action.vk_code, target_key_action.modifiers);
                        // 释放之前按下的虚拟修饰符
                        if activating_key_vk == vk_code_from_char('g').unwrap() {
                            send_key_event(VK_SHIFT, KeyAction::Release);
                        }
                        send_key_event(active_vk_mod, KeyAction::Release);
                        *space_state_guard = SpaceState::ComboEngaged;
                        return LRESULT(1); // 消耗此键
                    } else {
                        // 修饰符活跃状态下，按下了未映射的键
                        // println!("[FALLBACK] Space + Mod({:?}) + unmapped key '{}' -> Releasing Mod, Emitting Space, passing through original key", active_vk_mod, c);
                        if activating_key_vk == vk_code_from_char('g').unwrap() {
                            send_key_event(VK_SHIFT, KeyAction::Release);
                        }
                        send_key_event(active_vk_mod, KeyAction::Release); // 释放之前按下的虚拟修饰符
                        send_key_event(VIRTUAL_KEY(0x20), KeyAction::Press); // 模拟发出一个空格
                        send_key_event(VIRTUAL_KEY(0x20), KeyAction::Release);
                        *space_state_guard = SpaceState::NotPressed; // 重置状态
                        return unsafe { CallNextHookEx(None, n_code, wparam, lparam) }; // 传递原始键
                    }
                } else {
                    // 非字符键（如 Esc, Tab 等）被按下，且未在映射中
                    // println!("[FALLBACK] Space + Mod({:?}) + non-char-key -> Releasing Mod, Emitting Space, passing through original key", active_vk_mod);
                    if activating_key_vk == vk_code_from_char('g').unwrap() {
                        send_key_event(VK_SHIFT, KeyAction::Release);
                    }
                    send_key_event(active_vk_mod, KeyAction::Release);
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Press);
                    send_key_event(VIRTUAL_KEY(0x20), KeyAction::Release);
                    *space_state_guard = SpaceState::NotPressed;
                    return unsafe { CallNextHookEx(None, n_code, wparam, lparam) };
                }
            },
            SpaceState::ComboEngaged => {
                // 如果组合已触发，Space 键仍按下，其他键的按下通常应被忽略
                // println!("[INFO] Space in ComboEngaged, ignoring other key down.");
                return LRESULT(1);
            },
            SpaceState::NotPressed => {
                // Space 键未按下，不处理此事件
                // println!("[INFO] Space NotPressed, passing through original key.");
            }
        }
    } else if is_key_up {
        // 如果是修饰符激活键（f, d, g）的释放，并且 Space 仍处于 ModifierActive 状态
        let mut space_state_guard = SPACE_STATE.lock().unwrap();
        if let SpaceState::ModifierActive { active_vk_mod, activating_key_vk } = *space_state_guard {
            if vk_code == activating_key_vk {
                // 用户释放了激活键，但没有按下最终组合键
                // println!("[MODIFIER_RELEASE_EARLY] Releasing Modifier {:?} (Activating key: '{}')", active_vk_mod, vk_code_to_char(activating_key_vk).unwrap_or('?'));
                if activating_key_vk == vk_code_from_char('g').unwrap() {
                    send_key_event(VK_SHIFT, KeyAction::Release);
                }
                send_key_event(active_vk_mod, KeyAction::Release);
                *space_state_guard = SpaceState::PressedWaiting; // 回退到等待组合或Space释放
                return LRESULT(1); // 消耗此键的释放
            }
        }
    }


    // 默认行为：将事件传递给下一个钩子（如果我们的逻辑没有消耗它）
    unsafe {
        CallNextHookEx(None, n_code, wparam, lparam)
    }
}

// 辅助函数：将char转换为VIRTUAL_KEY (仅对a-z和特定符号)
fn vk_code_from_char(c: char) -> Option<VIRTUAL_KEY> {
    if c >= 'a' && c <= 'z' {
        Some(VIRTUAL_KEY(c.to_ascii_uppercase() as u16))
    } else {
        match c {
            '[' => Some(VIRTUAL_KEY(0xDB)),
            ']' => Some(VIRTUAL_KEY(0xDD)),
            '.' => Some(VIRTUAL_KEY(0xBE)),
            _ => None,
        }
    }
}


fn main() -> windows::core::Result<()> {
    // 初始化键位映射
    init_key_maps();

    println!("空格增强脚本已启动...");
    println!("请注意：本脚本运行时，控制台可能不会显示键盘输入，但功能将在其他应用程序中生效。");
    println!("关闭此窗口即可停止脚本。");

    // 获取当前模块的句柄，SetWindowsHookExW 需要
    let h_instance = unsafe { windows::Win32::System::LibraryLoader::GetModuleHandleA(None)? };

    // 设置低级键盘钩子
    // WH_KEYBOARD_LL (13) 表示低级键盘钩子
    // low_level_keyboard_proc 是回调函数
    // h_instance 是模块句柄 (可选，这里传入 None)
    // 0 是线程 ID，0 表示全局钩子
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

    // 消息循环，保持钩子活跃
    // Hook 线程必须有一个消息循环，否则系统会取消钩子。
    let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).into() {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // 程序退出时卸载钩子
    unsafe {
        UnhookWindowsHookEx(hook_handle.unwrap());
    }
    println!("键盘钩子已卸载。脚本退出。");

    Ok(())
}

