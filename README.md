# Space Enhancer

Enhance your typing experience by transforming your Spacebar into a powerful command key for efficient navigation, text editing, and system operations on Windows. Inspired by `vim` and `karabiner` concepts, this utility centralizes common actions under your thumb, reducing hand movement and increasing productivity.

## ✨ Features

The `Space Enhancer` script redefines the behavior of your Spacebar when held down, allowing it to act as a modifier for various commands.

### 🚀 Core Principle: Space as a Universal Modifier

*   **Alone:** A single press of the `Spacebar` acts as a regular space character.
*   **Held Down:** While `Spacebar` is held, other key presses trigger special commands. The script intelligently manages modifier keys (Shift, Ctrl) to enable a multi-layered command system.

### ⌨️ Key Combinations

All combinations are triggered by **holding down the Spacebar** and then pressing the subsequent keys.

#### 1. Basic Navigation & Editing (`Space + Key`)

These combinations execute basic movement or editing actions.

| Shortcut    | Function               | Description                                  |
| :---------- | :--------------------- | :------------------------------------------- |
| `Space + i` | `↑` (Arrow Up)         | Move cursor up                               |
| `Space + j` | `←` (Arrow Left)       | Move cursor left                             |
| `Space + k` | `↓` (Arrow Down)       | Move cursor down                             |
| `Space + l` | `→` (Arrow Right)      | Move cursor right                            |
| `Space + h` | `Home`                 | Jump to the beginning of the line            |
| `Space + n` | `End`                  | Jump to the end of the line                  |
| `Space + o` | `Page Up`              | Scroll/navigate one page up                  |
| `Space + .` | `Page Down`            | Scroll/navigate one page down                |
| `Space + u` | `Backspace`            | Delete the character before the cursor       |

#### 2. Modifier-Activated Navigation (`Space + Modifier Key + Direction Key`)

These combinations activate temporary modifier layers (Shift, Ctrl, or Ctrl+Shift) while Space is held, allowing for more advanced selection and navigation.

*   `Space + f + [i/j/k/l]`: Activates `Shift` for selection.
    *   Example: `Space + f` (hold `f`) then `j` will send `Shift + ←`.
*   `Space + d + [i/j/k/l]`: Activates `Ctrl` for word/paragraph navigation.
    *   Example: `Space + d` (hold `d`) then `j` will send `Ctrl + ←`.
*   `Space + g + [j/l]`: Activates `Ctrl + Shift` for word/paragraph selection.
    *   Example: `Space + g` (hold `g`) then `j` will send `Ctrl + Shift + ←`.

#### 3. System Functions (`Space + System Key`)

Specific keys are mapped to Windows system functions.

| Shortcut    | Function               | Description                                     |
| :---------- | :--------------------- | :---------------------------------------------- |
| `Space + [` | `Ctrl + Win + ←`       | Switch to the previous virtual desktop          |
| `Space + ]` | `Ctrl + Win + →`       | Switch to the next virtual desktop              |

#### 4. Passthrough for Native System Hotkeys

The script prioritizes native Windows hotkeys involving `Space`.

*   `Ctrl + Space`: **Preserves native behavior** (e.g., input method switching).
*   `Alt + Space`: **Preserves native behavior** (e.g., window system menu).
*   `Win + Space`: **Preserves native behavior** (e.g., language bar, desktop preview).

If you press `Ctrl` (or `Alt`) while `Space` is already held (and in a waiting state), the script will momentarily release the "consumed" `Space` event to the system and enter a passthrough mode, ensuring the native system hotkey works as expected.

### 💡 Spacebar Release Behavior

*   If you **only** press and release the `Spacebar` (without triggering any combinations or modifier activations), it will output a regular space character.
*   If you trigger **any** (valid or invalid) combination (including activating a modifier layer like `Space + f` or any unmapped key) during a Space press-release cycle, no additional space will be sent when Space is released.

## ⚙️ Installation

This project is built with Rust and is designed for **Windows only**.

> The prebuild binary can be found at [Release](https://github.com/zerosignal0101/space_enhancer/releases). Just start the program and it will run in the background.

### Prerequisites

*   [Rust programming language](https://www.rust-lang.org/tools/install) (with `cargo` package manager).

### Building from Source

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/zerosignal0101/space_enhancer
    cd space_enhancer
    ```

2.  **Build the project:**
    *   **For Release (recommended):** This builds an executable that runs silently in the background without a console window.
        ```bash
        cargo build --release
        ```
        The executable will be located at `target/release/space_enhancer.exe`.
    *   **For Debugging:** This runs the script with a console window showing debug logs.
        ```bash
        cargo run
        ```
        You can control the log level using the `RUST_LOG` environment variable (e.g., `RUST_LOG=debug cargo run`).

## ▶️ Usage

1.  **Run the Executable:**
    *   Navigate to the `target/release/` directory (or wherever you built it).
    *   Double-click `space_enhancer.exe`.
    *   The script will start running in the background. If you built the `--release` version, there will be no visible window.

2.  **Stop the Script:**
    *   If you ran `cargo run` (debug mode), simply close the console window.
    *   For `release` builds, open `Task Manager` (Ctrl+Shift+Esc), find `space_enhancer.exe` in the "Processes" tab, right-click, and select "End task".

## 🛠️ How It Works (For Developers)

The `Space Enhancer` operates as a low-level keyboard hook on Windows:

*   It uses `SetWindowsHookExW` with `WH_KEYBOARD_LL` to intercept all keyboard events system-wide.
*   A `SpaceState` enum (`NotPressed`, `PressedWaiting`, `ModifierActive`, `PassthroughActive`) manages the current Spacebar context.
*   When `VK_SPACE` is pressed, its event is *consumed* (`LRESULT(1)` is returned), preventing it from reaching other applications. The state transitions.
*   Subsequent key presses are evaluated against statically defined `KEY_MAP`s (e.g., `KEY_MAP_PRIMARY`, `KEY_MAP_SHIFT`, `KEY_MAP_CTRL`, `KEY_MAP_CTRL_SHIFT`, `KEY_MAP_SYSTEM`).
*   If a match is found:
    *   The script simulates the corresponding key combination (e.g., `VK_LEFT`, `VK_SHIFT + VK_LEFT`) using `SendInput`.
    *   The `IS_SENDING_INPUT` global mutex ensures that these simulated inputs do not trigger the hook again, preventing infinite loops.
*   Modifier keys (`VK_SHIFT`, `VK_CONTROL`) are "virtually" pressed/released by the script when a modifier-activating key (`f`, `d`, `g`) is used.
*   Special logic is in place to detect and passthrough `Ctrl+Space`, `Alt+Space`, and `Win+Space` combinations to preserve native OS functionality.

## 🔗 Dependencies

The project relies on the following crates:

*   `windows`: For interacting with the Windows API.
    *   `Win32_Foundation`
    *   `Win32_UI_Input_KeyboardAndMouse`
    *   `Win32_UI_WindowsAndMessaging`
    *   `Win32_System_LibraryLoader`
*   `log`: For logging messages (info, debug, error).
*   `env_logger`: For configuring the `log` implementation based on environment variables.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check [issues page](https://github.com/zerosignal0101/space_enhancer/issues).

### Customization

The key mappings are currently hardcoded in `src/main.rs` using `OnceLock<HashMap>`. For advanced users or contributors, modifications can be made directly in the `init_key_maps()` function. Future versions might include external configuration options.

## 📝 License

This project is licensed under the MIT License.
