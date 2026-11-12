//! The `SetWindowPos` flags, and which position changes can move a window's client area.
//!
//! Wine shows a device's frames through a client surface whose cocoa view
//! has to cover the window's client rect. Some Wines leave that surface out
//! of the updates a window position change makes and size it only when it is
//! presented, so the device asks Wine to present it again after any change
//! that can have moved the client rect within the window.

/// `SWP_NOSIZE`: the change keeps the window's size.
pub const SWP_NOSIZE: u32 = 0x0001;
/// `SWP_NOMOVE`: the change keeps the window's position.
pub const SWP_NOMOVE: u32 = 0x0002;
/// `SWP_NOZORDER`: the change keeps the window's place in the z-order.
pub const SWP_NOZORDER: u32 = 0x0004;
/// `SWP_NOACTIVATE`: the change does not activate the window.
pub const SWP_NOACTIVATE: u32 = 0x0010;
/// `SWP_FRAMECHANGED`: the window's frame was recomputed, which can move its client rect.
pub const SWP_FRAMECHANGED: u32 = 0x0020;
/// `SWP_SHOWWINDOW`: the change shows the window.
pub const SWP_SHOWWINDOW: u32 = 0x0040;
/// `SWP_HIDEWINDOW`: the change hides the window.
pub const SWP_HIDEWINDOW: u32 = 0x0080;
/// `SWP_NOSENDCHANGING`: the change is not announced with `WM_WINDOWPOSCHANGING`.
pub const SWP_NOSENDCHANGING: u32 = 0x0400;

/// A `SetWindowPos` that changes nothing the window's owner can observe.
///
/// No move, no size, no z-order change, no activation and no
/// `WM_WINDOWPOSCHANGING`; with nothing changed and no frame recomputed,
/// user32 sends no `WM_WINDOWPOSCHANGED`, `WM_NCCALCSIZE`, `WM_MOVE` or
/// `WM_SIZE` either. What is left of the call is its other half: win32u
/// hands the driver the window's rect again, mapped for the display mode in
/// place now.
pub const SWP_REAPPLY_ONLY: u32 =
    SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING;

/// Whether a `WM_WINDOWPOSCHANGED` with `flags` can have moved the window's client rect.
///
/// A resize, a recomputed frame and showing the window can; a move, a z-order
/// change, an activation or a hide alone keep the client rect where it was
/// relative to the window's content, which is all the client surface's frame
/// depends on for a top-level window. A child device window that moves inside
/// its parent is the one case this leaves out.
#[must_use]
pub const fn moves_client_area(flags: u32) -> bool {
    flags & SWP_NOSIZE == 0 || flags & (SWP_FRAMECHANGED | SWP_SHOWWINDOW) != 0
}

#[cfg(test)]
mod tests;
