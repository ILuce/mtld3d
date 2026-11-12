# About this fork

This repository is an **altered version** of mtld3d. The original is
<https://github.com/athei/mtld3d>, by Alexander Theissen, under the zlib licence
([LICENSE](LICENSE), kept as it is). The fork is maintained by ILuce
(<https://github.com/ILuce>) and holds changes its maintainers needed and upstream did not have
at the time. It is not the original software, and the original author neither publishes nor
supports it. It is built only for Apple Silicon macOS.

## How the fork is kept

- The branch `iluce` is an upstream release tag plus the patches below, one commit per gap
  that a real program showed, each with a test.
- A release of the fork is a tag `v<upstream version>+iluce.<N>` on that branch; both
  workspaces carry the same version, and the libraries log it
  (`d3d9.dll v0.15.3+iluce.2 ... loaded`).
- When upstream publishes a release, the patches are carried onto it; a patch upstream made
  unnecessary is dropped.

## Releases

| Fork release | Upstream base | Patches |
|---|---|---|
| `v0.15.3+iluce.1` | `v0.15.3` (`aedfa404910522d2cd9459c283f52de54a3f7599`) | 1 |
| `v0.15.3+iluce.2` | `v0.15.3` (`aedfa404910522d2cd9459c283f52de54a3f7599`) | 1, 2 |

A release carries the five files an arm64 Wine of the wine-build family loads from its
`lib/wine/d3d9/mtld3d` tree: `i386-windows/d3d9.dll` and `mtld3d.dll`,
`aarch64-windows/d3d9.dll` and `mtld3d.dll` (ARM64X), and `aarch64-unix/mtld3d.so`. They are
built from the release tag with `make windows-i686 windows-arm64x unix-arm64 PROD=1`
([docs/BUILDING.md](docs/BUILDING.md)), installed with upstream's install step, which marks the
Windows libraries as Wine builtins, and stripped of debug sections.

## Patches

### 1. The start-up import walk survives a packed executable

**The gap.** `d3d9.dll` redirects a few imports of the process's main module when it is loaded
(`windows/d3d9/src/import_patch.rs`: the display-mode list and the exit status). The walk over
the main module's import directory took every RVA of its headers on trust. The exit-status
hook searches every import descriptor, whichever module it names. An executable packed so
that its only import descriptor names **one table as both its name table and its address
table** (`OriginalFirstThunk == FirstThunk`) has, once the loader bound it, function addresses
where the walk expected the RVAs of names; the walk read a string at `base + address + 2`,
outside the image, inside `DllMain`. The loader caught the access violation and failed the
library's initialisation, and the program could not start.

**The program.** Just Cause 1 (2006), the Steam release: its own loader then reports "The
procedure * could not be located in the DLL d3d9.dll."; Wine reports `Initialization of
L"d3d9.dll" failed`.

**The change.**

- The walk moved to `windows/core/src/import_table.rs` (`mtld3d-core`), where the host unit
  tests run it. It reads through a reader that may refuse, holds every RVA, table entry and
  string inside the image's own `SizeOfImage`, passes over a descriptor whose name table is its
  address table (as it already passed over one without a name table), and limits the length of
  the descriptor list and of each name table.
- On the Windows side the reader asks the system, through the crash handler's existing region
  query, whether the pages are committed and readable before it copies from them.
- An ordinary executable is read as before and gives the same slot. A program that binds its
  imports itself is still not covered by the hooks, as upstream documents.

**The tests.** `import_table::tests` in `mtld3d-core`, over synthetic mapped images written in
the tests: an ordinary bound image in both formats, the packed shape, and tables that leave
the image, never end or cannot be read. On upstream's walk the packed shape reads outside the
image; with the patch nothing outside it is read.

### 2. A fullscreen device that leaves its window to the application fills the display

**The gap.** A device created with `D3DCREATE_NOWINDOWCHANGES` sets the display mode and leaves
the window's style, rect and visibility to the application. Under Wine the mode-set is virtual
(`EmulateModeset`): win32u maps a window onto the physical monitor when the window's position
is applied, and Wine sizes the client view the frames are shown in when the client surface is
presented again. A window the device manages gets both from the placement that follows each
mode-set. A window left to the application got neither, so a window sized to a mode smaller
than the desktop's kept its physical size and the picture stood unscaled in a part of the
display. On Windows the mode-set is physical and exclusive fullscreen covers the display,
whatever the window is.

**The program.** Just Cause 1 (2006), the Steam release: a 1024x768 fullscreen device with the
flag was shown 1:1 in a part of a 1710x1112 display (`present: guest 1024x768, layer
1024x768pt`).

**The change.**

- After every mode change of such a session (entering fullscreen, a `Reset` that keeps it,
  re-activation, leaving, a rejected windowed `Reset`) the device has win32u apply the position
  the window already has: one `SetWindowPos` with `SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER |
  SWP_NOACTIVATE | SWP_NOSENDCHANGING` (`windows/d3d9/src/fullscreen.rs`,
  `reapply_app_window`). Nothing moves and the window's procedure receives no message, as on
  native D3D9, which makes no position change under the flag.
- The device then asks its next `Present` to show the client surface again
  (`windows/d3d9/src/device.rs`, `follow_app_window`), as the window subclass does after a
  managed window's position change.
- The transition line names where the application has its window: `window left to the app
  (D3DCREATE_NOWINDOWCHANGES): 1024x768 at (0, 0)`.
- Not covered: a window the application did not size to its mode shows the picture where that
  window is mapped, and a second device on the same window is not asked for its client surface.

**The tests.** `device::nowindowchanges_fullscreen_fills_the_display` in the end-to-end suite:
on a window the test sized to the mode, the presenter's drawable grows from the window's size
once the device is fullscreen and returns to it after the windowed `Reset`, while the window's
rect and style stay as the application left them. Without the patch the drawable keeps the
window's size. Unit tests of the flag set and of the transition line in `mtld3d-core`.
