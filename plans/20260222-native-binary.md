# Native Desktop Binary Plan

Date: 2026-02-22
Status: Proposed
Owner: GUI (`sis-pdf-gui`), CLI (`sis-pdf`)

## Problem statement

The `sis-pdf-gui` crate has a `start_native()` entry point and a complete set of
native code paths in `app.rs`, but no binary target invokes them. The application
is deployed exclusively as a WASM bundle served from a browser. A native desktop
binary does not exist.

The two concrete blockers are:

1. **No binary entry point.** `sis-pdf-gui` is `crate-type = ["cdylib", "rlib"]`
   only. Nothing calls `start_native()`. There is no `[[bin]]` in the GUI crate
   and no `sis gui` subcommand in the CLI.

2. **winit 0.30 requires a live display server at runtime on Linux.** There is no
   headless or offscreen rendering path through eframe's public API. `eframe::run_native`
   calls `EventLoop::new()` which panics if neither `DISPLAY` nor `WAYLAND_DISPLAY`
   is set. This is not a compile-time blocker (the library compiles cleanly with
   `--features gui`) but it prevents CI from running the binary without infrastructure
   changes.

## Verified current state

- `cargo build -p sis-pdf-gui --features gui` succeeds today (eframe 0.33.3,
  winit 0.30.12, glow 0.16.0, glutin 0.32.3).
- System libraries present: `libX11-1.8.12`, `libxkbcommon-1.11.0`,
  `libwayland-client-1.24.0` (Fedora 43).
- `DISPLAY=:0` and `WAYLAND_DISPLAY=wayland-1` are set in the development
  environment; the runtime blocker does not affect local dev.
- Native code paths in `app.rs` are already implemented:
  - `request_file_upload_native()` via `rfd::FileDialog`
  - `download_bytes_native()` via `rfd::FileDialog::save_file`
  - `handle_file_path_drop()` / `handle_file_drop()` — shared with WASM
  - `process_analysis()` runs analysis inline on native (no Web Worker)
  - File drag-and-drop via `ctx.input(|i| i.raw.dropped_files)` — same both platforms
- `sis-pdf-gui` is absent from `workspace.default-members`; `cargo build` at the
  workspace root does not build it.
- No CI configuration exists (no `.github/` directory).

## Assumptions

1. The `sis gui` subcommand is the preferred binary entry strategy; a standalone
   app binary is not required for v1.
2. The WASM deployment path remains the primary target; native is additive and
   must not regress WASM builds.
3. macOS and Windows support are explicitly out of scope for this plan; Linux
   (x11 + Wayland) is the only target platform.
4. CI virtual display strategy uses Xvfb + Mesa software rendering; no GPU is
   assumed in CI.
5. `crate-type = ["cdylib", "rlib"]` is preserved; the GUI crate is not split.
6. No new unsafe code; no unwraps.

## Goals

1. `cargo run -p sis-pdf --features gui -- gui` opens a desktop window.
2. `cargo build -p sis-pdf --features gui` produces a single native binary with
   the `gui` subcommand included.
3. `start_native()` is hardened with correct window options, tracing, and panic
   handling.
4. CI compiles and links the native binary; a smoke test opens a window and loads
   a fixture PDF via CLI argument.
5. The WASM build (`trunk build` in `crates/sis-pdf-gui/`) continues to pass.
6. All native-divergent code paths are covered by tests or smoke-test assertions.

## Non-goals

1. macOS or Windows native targets.
2. Headless rendering without a display server.
3. System packaging (`.deb`, `.rpm`, `.AppImage`) — a follow-on plan.
4. Automatic updates or auto-launch.
5. `sis-pdf-gui` added to workspace `default-members`.

## Architecture: `sis gui` subcommand

The CLI binary (`sis`) gains an optional `gui` feature that activates `sis-pdf-gui`
as a dependency. This keeps eframe, glutin, glow, and winit entirely out of the
CLI's dependency graph when the feature is disabled. Server deployments that only
need `sis scan` / `sis query` are not affected.

```
sis-pdf [features = ["gui"]]
    └── sis-pdf-gui [features = ["gui"]]
            ├── eframe 0.33 (glow + x11 + wayland)
            │   ├── egui-winit → winit 0.30.12
            │   ├── egui_glow → glow 0.16.0
            │   └── glutin-winit → glutin 0.32.3
            └── rfd 0.15 (native file dialogs)
```

The `cdylib` crate type in `sis-pdf-gui` is a non-issue for this strategy: when
the CLI links against `sis-pdf-gui`, cargo uses the `rlib` form. The cdylib is
compiled alongside but not linked into the CLI binary. Position-independent code
requirements imposed by `cdylib` apply to the shared library artefact only.

## Workstream A: `sis gui` CLI subcommand

### A1. Feature flag and dependency in `crates/sis-pdf/Cargo.toml`

```toml
[dependencies]
# … existing deps …
sis-pdf-gui = { path = "../sis-pdf-gui", features = ["gui"], optional = true }

[features]
gui = ["dep:sis-pdf-gui"]
# existing features remain unchanged:
ml-graph = ["sis-pdf-core/ml-graph", "sis-pdf-ml-graph"]
font-dynamic = ["sis-pdf-detectors/font-dynamic"]
```

### A2. `Command::Gui` variant in `crates/sis-pdf/src/main.rs`

Add to the `Command` enum, gated so the feature is compile-time enforced:

```rust
/// Open the GUI desktop window.
#[cfg(feature = "gui")]
Gui(GuiArgs),
```

```rust
#[cfg(feature = "gui")]
#[derive(clap::Args)]
pub struct GuiArgs {
    /// PDF file to open immediately on launch.
    #[arg(value_name = "FILE")]
    pub file: Option<std::path::PathBuf>,
}
```

Dispatch in `main()`:

```rust
#[cfg(feature = "gui")]
Command::Gui(args) => {
    sis_pdf_gui::start_native(args.file)
        .map_err(|err| anyhow::anyhow!("GUI exited with error: {err}"))?;
}
```

The compile-time guard means the `Gui` arm is omitted when `--features gui` is
absent, avoiding any runtime "feature not enabled" branch.

### A3. Pass the optional initial file into `start_native`

Update the signature in `crates/sis-pdf-gui/src/lib.rs`:

```rust
#[cfg(all(not(target_arch = "wasm32"), feature = "gui"))]
pub fn start_native(initial_file: Option<std::path::PathBuf>) -> eframe::Result {
    init_native_tracing();
    let options = native_options();
    eframe::run_native(
        "sis — PDF security analyser",
        options,
        Box::new(move |cc| Ok(Box::new(app::SisApp::new_with_file(cc, initial_file)))),
    )
}
```

`SisApp::new_with_file` calls the existing `handle_file_path_drop` immediately
after construction if `initial_file` is `Some`, allowing `sis gui /path/to.pdf`
to open the file on launch without additional UI interaction.

### A4. Validation

1. `cargo build -p sis-pdf --features gui` compiles without errors.
2. `cargo run -p sis-pdf --features gui -- gui --help` prints usage.
3. `cargo build -p sis-pdf` (without `--features gui`) compiles without eframe
   in the dependency graph — verify with `cargo tree -p sis-pdf | grep eframe`.
4. WASM: `trunk build` in `crates/sis-pdf-gui/` still succeeds.

## Workstream B: Harden `start_native()`

### B1. Tracing initialisation

The native binary needs `tracing-subscriber` initialised before `eframe::run_native`.
Add a private `init_native_tracing()` function in `lib.rs`:

```rust
#[cfg(all(not(target_arch = "wasm32"), feature = "gui"))]
fn init_native_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .compact()
        .init();
}
```

`tracing-subscriber` must be added as a non-default dependency in
`sis-pdf-gui/Cargo.toml`:

```toml
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
```

`RUST_LOG=sis_pdf_gui=debug sis gui` should then print structured log output.

### B2. `NativeOptions` configuration

Replace `eframe::NativeOptions::default()` with a dedicated `native_options()`
function:

```rust
#[cfg(all(not(target_arch = "wasm32"), feature = "gui"))]
fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("sis — PDF security analyser")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([900.0, 580.0])
            .with_app_id("sis-pdf-gui"),  // Wayland/X11 compositor hint
        persist_window: true,             // Save/restore window geometry via eframe storage
        ..Default::default()
    }
}
```

Field notes:
- `with_inner_size`: overrides eframe's default (800×600) which is too small for
  the multi-panel layout.
- `with_min_inner_size`: prevents the layout from collapsing below usable state.
- `with_app_id`: sets the Wayland `app_id` and X11 `WM_CLASS`, enabling the
  compositor to group windows and apply saved geometry. Must match the `.desktop`
  file entry if one is added later.
- `persist_window`: eframe's built-in geometry persistence via its storage backend;
  no additional implementation needed.

### B3. Panic hook

On native there is no `console_error_panic_hook`. The default Rust panic hook
(stderr backtrace) is sufficient. No change required, but document explicitly
that the native binary should be run with `RUST_BACKTRACE=1` when debugging
crashes.

### B4. Validation

1. Window opens at 1280×800 on first launch.
2. Window geometry is restored on second launch (eframe persistence).
3. `RUST_LOG=debug sis gui` emits structured log output to stderr.
4. `cargo test -p sis-pdf-gui` still passes (no regression from new deps).

## Workstream C: Native code path audit

### C1. Analysis threading

On native, `process_analysis()` runs on the egui render thread, blocking the UI
for the duration. For large PDFs this causes a frozen window (no repaints) for
several seconds.

WASM avoids this via `AppState::AnalysingWorker` dispatching to a Web Worker.
The native equivalent is `std::thread::spawn`.

**Required change**: add a `std::sync::mpsc` channel pair to `SisApp` gated on
`#[cfg(not(target_arch = "wasm32"))]`. On `AppState::Analysing`, spawn a thread
that calls `analyze_bytes` and sends the result back. The main thread polls the
receiver each frame via `ctx.request_repaint_after(Duration::from_millis(50))`.
Keep the inline (blocking) path as a fallback for test builds.

This is the most significant native-only addition. Scope it as a separate task
within this workstream; it can ship as a follow-up if needed without blocking
the initial binary.

### C2. File drop via `file.path` on native

`ctx.input(|i| i.raw.dropped_files)` already handles both platforms. On native,
winit provides `DroppedFile { path: Some(PathBuf), bytes: None }`. The existing
`handle_file_path_drop` path in `app.rs` handles this correctly. Confirm with a
manual test.

### C3. Window title update

When a PDF is loaded, update the window title to include the filename:

```rust
ctx.send_viewport_cmd(egui::ViewportCommand::Title(
    format!("{} — sis", self.active_file_name()),
));
```

This call is no-op on WASM (eframe ignores it). Add it to `SisApp::update` after
a successful analysis result is set.

### C4. Keyboard shortcut parity

`shortcuts.rs` already adjusts bindings by `cfg!(target_arch = "wasm32")`. Verify
on native that Ctrl+O (file open), Ctrl+W (close tab), and the findings navigation
keys all fire correctly. No code changes expected; this is a test-only item.

### C5. Clipboard

egui handles clipboard via winit's `arboard` integration on native. No explicit
code is needed. Verify that Ctrl+C on a selected finding exports JSON to the
clipboard (existing shortcut in `shortcuts.rs`).

### C6. Recent files (new feature)

The WASM path has no persistent storage for recent files (browser state is
ephemeral). On native, eframe provides a `Storage` trait backed by a file in
`$XDG_DATA_HOME/sis-pdf-gui/`. Add a `recent_files: Vec<PathBuf>` field to
`SisApp`, populated from eframe storage on `new()` and written back on each file
open. Render in the File menu as "Recent files ▶".

This is additive native-only UX. Gate the entire feature on
`#[cfg(not(target_arch = "wasm32"))]`.

### C7. Validation

1. Manual: drag-and-drop a PDF onto the native window — file loads.
2. Manual: Ctrl+O opens native file picker, file loads.
3. Manual: window title updates to filename after load.
4. Manual: Ctrl+C on selected finding — clipboard contains JSON.
5. Manual: reopen app — recent files appear in File menu.

## Workstream D: CI virtual display

No `.github/` directory exists. The CI strategy below targets GitHub Actions as
the most common choice; adapt to the actual CI provider when one is configured.

### D1. Required CI environment

For compile-only validation (sufficient for v1):

```yaml
- name: Build native GUI binary
  run: cargo build -p sis-pdf --features gui
```

No display server needed; this only links.

For running the binary and loading a fixture (smoke test):

```yaml
- name: Install virtual display dependencies
  run: |
    sudo apt-get install -y xvfb mesa-utils libgles2-mesa-dev
    # or on Fedora/RHEL:
    sudo dnf install -y xorg-x11-server-Xvfb mesa-dri-drivers

- name: Run GUI smoke test
  run: |
    export DISPLAY=:99
    Xvfb :99 -screen 0 1280x800x24 &
    sleep 1
    LIBGL_ALWAYS_SOFTWARE=1 \
      cargo run -p sis-pdf --features gui -- gui \
      crates/sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf &
    GUI_PID=$!
    sleep 5
    kill $GUI_PID || true
```

`LIBGL_ALWAYS_SOFTWARE=1` forces Mesa's llvmpipe software renderer, avoiding GPU
requirements in CI. This is sufficient for verifying that the window opens, the
PDF loads, and the event loop does not panic.

### D2. Longer-term: screenshot-based smoke test

Mirror the existing WASM Playwright test pattern
(`scripts/run_wasm_gui_bench.sh`) but using a native screenshot tool:

```bash
DISPLAY=:99 import -window root -delay 5000 /tmp/sis_gui_smoke.png
```

Assert that the screenshot is non-trivially non-blank (pixel variance check).
This catches renderer panics and blank-window regressions. Defer to a follow-on
plan once the basic binary is established.

### D3. Validation

1. `cargo build -p sis-pdf --features gui` succeeds in CI without a display server.
2. Smoke test (D1) passes: process exits cleanly (SIGKILL after 5s with no panic
   beforehand counts as success).
3. WASM build (`trunk build --release`) continues to pass in CI.

## Workstream E: `SisApp::new_with_file` implementation

### E1. API

```rust
impl SisApp {
    pub fn new(cc: &eframe::CreationContext) -> Self { /* existing */ }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_with_file(
        cc: &eframe::CreationContext,
        initial_file: Option<std::path::PathBuf>,
    ) -> Self {
        let mut app = Self::new(cc);
        if let Some(path) = initial_file {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file.pdf".to_string());
            app.handle_file_path_drop(name, path);
        }
        app
    }
}
```

### E2. Validation

1. `sis gui /path/to.pdf` opens the file without requiring any UI interaction.
2. `sis gui` (no argument) opens the idle/drop-zone screen.
3. `sis gui /nonexistent.pdf` shows an error in the UI (the existing error path
   from `handle_file_path_drop` → `std::fs::read` failure).

## Delivery stages

### Stage 1: Binary entry point and hardened options (A + B)

1. Add `gui` feature and `sis-pdf-gui` optional dep to CLI crate.
2. Add `Command::Gui` variant with `GuiArgs`.
3. Update `start_native` signature; add `new_with_file`; add `native_options()`;
   add `init_native_tracing()`.
4. Add `tracing-subscriber` as native-only dep in GUI crate.
5. Verify compile: `cargo build -p sis-pdf --features gui`.
6. Verify no regression: `cargo build -p sis-pdf` (no eframe in tree).
7. Verify WASM: `trunk build`.

### Stage 2: Native UX polish (C, except C1)

1. Window title update after analysis.
2. Recent files in File menu.
3. Manual verification of file drop, Ctrl+O, Ctrl+C, keyboard shortcuts.

### Stage 3: CI compile validation (D1)

1. Add build step to CI pipeline.
2. No smoke test (display) required at this stage.

### Stage 4: Analysis threading (C1)

1. Design the native worker thread + channel architecture.
2. Implement; verify that the UI remains responsive during analysis of a 5MB PDF.
3. This may be a separate plan if scope warrants it.

### Stage 5: CI smoke test (D2)

1. Add Xvfb + Mesa step to CI.
2. Run smoke test with CVE fixture.

## Risks and mitigations

1. **Risk**: `cdylib` crate type causes linker issues when CLI links against
   `sis-pdf-gui` as rlib on Fedora.
   **Mitigation**: The `cdylib` artefact is compiled in parallel but not linked
   into the CLI; this is standard Cargo behaviour and has no known issues on
   Linux. Verified by a successful `cargo build -p sis-pdf-gui --features gui`
   at time of writing.

2. **Risk**: eframe's `persist_window` storage conflicts with WASM path where
   eframe uses `LocalStorage`.
   **Mitigation**: `persist_window` is only set in `native_options()`, which is
   `#[cfg(not(target_arch = "wasm32"))]`. WASM path unchanged.

3. **Risk**: `tracing-subscriber` version conflicts with the CLI crate's existing
   `tracing-subscriber` dep.
   **Mitigation**: Use a workspace-wide version declaration if a conflict occurs.
   Both crates can use the same version; `tracing-subscriber` has a stable API
   at 0.3.x.

4. **Risk**: Analysis blocking the UI (C1) makes the native binary feel unresponsive
   before the threading work in Stage 4.
   **Mitigation**: Document the limitation explicitly in `sis gui --help` until
   Stage 4 ships. The `progress_state` spinner already renders during
   `AppState::Analysing`, so the UI is not fully frozen — only the repaint rate
   drops.

5. **Risk**: `LIBGL_ALWAYS_SOFTWARE=1` + Mesa llvmpipe is unavailable in some CI
   environments.
   **Mitigation**: Stage 3 (compile-only) does not require it. Stage 5 requires
   `mesa-dri-drivers` or equivalent; document as a CI dependency.

6. **Risk**: `with_app_id` Wayland hint does not match a future `.desktop` file
   entry, causing the compositor to not group windows.
   **Mitigation**: Use `"sis-pdf-gui"` consistently in both `NativeOptions` and
   any future `.desktop` file. Note explicitly in the packaging follow-on plan.

## Acceptance criteria

1. `cargo build -p sis-pdf --features gui` produces a binary with a `gui`
   subcommand that opens a desktop window.
2. `cargo build -p sis-pdf` (no flag) produces no eframe/winit/glow/glutin
   dependency in `cargo tree` output.
3. `sis gui /path/to.pdf` opens the app and loads the PDF without UI interaction.
4. Window geometry persists across restarts.
5. `RUST_LOG=debug sis gui` emits structured tracing output to stderr.
6. `trunk build` in `crates/sis-pdf-gui/` passes without modification.
7. `cargo test -p sis-pdf-gui -p sis-pdf-core -p sis-pdf` passes.
8. CI step `cargo build -p sis-pdf --features gui` passes without a display server.
9. File drag-and-drop, native file picker (Ctrl+O), and clipboard copy all
   function correctly on native.

## Follow-on plans (explicitly deferred)

1. Analysis threading for native (non-blocking UI during large PDF analysis).
2. CI screenshot smoke test with Xvfb + Mesa.
3. System packaging: `.desktop` file, application icon, `.rpm`/`.deb`/`.AppImage`.
4. macOS and Windows native targets (blocked on `eframe` feature activation and
   platform-specific `NativeOptions` configuration).
