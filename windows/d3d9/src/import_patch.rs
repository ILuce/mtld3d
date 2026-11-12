//! Redirecting imports of the process's main module to entry points of ours.
//!
//! The loader resolves a static import into one slot of the importing
//! image's import address table, and every call the image makes goes through
//! that slot, so writing one redirects the main module's calls without
//! touching the exporting DLL or any other importer. This DLL's own imports
//! are never patched, so it keeps reaching the real entry points. A module
//! that resolves the same entry point through `GetProcAddress` is not
//! covered: nothing it calls goes through an import slot.

use core::{
    cell::Cell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use log::warn;
use mtld3d_core::import_table::{self, ImageBytes};

use super::LOG_TARGET;

/// `VirtualProtect` protection that lets an import slot be written.
const PAGE_READWRITE: u32 = 0x04;
unsafe extern "system" {
    fn GetModuleHandleA(module_name: *const u8) -> *mut c_void;
    fn VirtualProtect(
        address: *mut c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
}

/// One import to redirect.
pub struct Hook<'a> {
    /// The exporting module's file name, or `None` for whichever imports the name.
    pub dll: Option<&'a [u8]>,
    /// The imported entry point's name, as `IMAGE_IMPORT_BY_NAME` spells it.
    pub func: &'a [u8],
    /// The entry point calls are sent to instead.
    pub replacement: *const (),
}

/// A PE image mapped by the loader, addressed by its base.
///
/// The invariant the constructor asserts is that `base` is the base of an image the loader
/// mapped in this process. Nothing more is taken from it on trust: the image is read through
/// [`ImageBytes`], whose `read` asks the system whether the bytes are there (fork patch
/// 1: a packed main module's headers and tables do not have to describe what is mapped).
pub struct MappedImage {
    base: *const u8,
    /// The address range the system last reported as committed and readable.
    ///
    /// Kept so that the reads of one table ask once.
    readable: Cell<(usize, usize)>,
}

/// A fixed set of the main module's import slots, redirected to entry points of ours.
///
/// One static per group of related imports. The slots keep the order of the
/// hooks they were installed from, so a replacement reaches the entry point
/// it displaced through [`PatchedImports::original`] with its own index.
pub struct PatchedImports<const N: usize> {
    /// The patched slots, in hook order; null where the import is absent.
    slots: [AtomicPtr<*const ()>; N],
    /// The entry points the slots held; null where the import is absent.
    ///
    /// Recorded before the write is tried and never cleared: another thread
    /// can be inside a replacement at any moment the slot names it, and a
    /// little after, so the original it forwards to has to be there first
    /// and stay.
    originals: [AtomicPtr<()>; N],
    /// Whether [`PatchedImports::install`] has already run.
    installed: AtomicBool,
}

impl MappedImage {
    /// # Safety
    ///
    /// `base` must be the base address of a PE image the loader mapped in
    /// this process (an `HMODULE`).
    const unsafe fn new(base: *const u8) -> Self {
        Self {
            base,
            readable: Cell::new((0, 0)),
        }
    }

    /// The import-address-table slot for `func`, if the image imports it.
    ///
    /// `dll` names the exporting module the import must come from; `None`
    /// takes the first import descriptor that carries the name, whichever
    /// module it is. The walk is [`import_table::import_slot_rva`]: it reads
    /// nothing outside the image and nothing the system does not report as
    /// readable, so an image whose import tables are not usable (a packed
    /// executable) has no slot here and costs no fault.
    pub fn import_slot(&self, dll: Option<&[u8]>, func: &[u8]) -> Option<*mut *const ()> {
        let slot = import_table::import_slot_rva(self, size_of::<usize>(), dll, func)?;
        // An import-address-table entry is pointer-aligned by the PE layout;
        // the walk held it inside the image and read it, and the address
        // keeps the image's provenance.
        let address = self.base.expose_provenance().checked_add(slot)?;
        Some(ptr::with_exposed_provenance_mut(address))
    }

    /// Whether every byte of `start..end` is committed memory that a read does not fault on.
    fn is_readable(&self, start: usize, end: usize) -> bool {
        let (known_start, known_end) = self.readable.get();
        if known_start <= start && end <= known_end {
            return true;
        }
        let mut at = start;
        while at < end {
            let Some((region_start, region_end)) = super::crash::readable_region(at) else {
                return false;
            };
            if region_end <= at {
                return false;
            }
            self.readable.set((region_start, region_end));
            at = region_end;
        }
        true
    }
}

impl ImageBytes for MappedImage {
    fn read(&self, rva: usize, out: &mut [u8]) -> bool {
        let Some(start) = self.base.addr().checked_add(rva) else {
            return false;
        };
        let Some(end) = start.checked_add(out.len()) else {
            return false;
        };
        if !self.is_readable(start, end) {
            return false;
        }
        // SAFETY: `base + rva` is `start`, the first byte of a range the system reported
        // as committed memory of this process just above, so the offset stays inside one
        // mapping.
        let from = unsafe { self.base.add(rva) };
        // SAFETY: `start..end` is committed, readable memory as of that query, and the
        // loader lock `DllMain` runs under keeps the main module mapped; `out` is a distinct
        // writable buffer of the same length, and bytes have no alignment.
        unsafe { ptr::copy_nonoverlapping(from, out.as_mut_ptr(), out.len()) };
        true
    }
}

impl<const N: usize> PatchedImports<N> {
    /// A set with nothing patched yet, for a `static`.
    pub const fn empty() -> Self {
        Self {
            slots: [const { AtomicPtr::new(ptr::null_mut()) }; N],
            originals: [const { AtomicPtr::new(ptr::null_mut()) }; N],
            installed: AtomicBool::new(false),
        }
    }

    /// Redirect each hook's import of the main module; how many were patched.
    ///
    /// Idempotent, and every hook is optional: an import the main module
    /// does not have and a slot whose page will not open are both skipped,
    /// leaving the replacement unreached. The original is recorded before
    /// the write is tried, so it is null only where the import is absent.
    pub fn install(&self, hooks: &[Hook<'_>; N]) -> usize {
        if self.installed.swap(true, Ordering::AcqRel) {
            return 0;
        }
        let Some(image) = main_module() else {
            return 0;
        };
        let mut patched = 0;
        for (i, hook) in hooks.iter().enumerate() {
            let Some(slot) = image.import_slot(hook.dll, hook.func) else {
                continue;
            };
            // The original is published before the slot names the
            // replacement, so a thread that calls through the slot the moment
            // it changes finds the entry point it forwards to.
            // SAFETY: `slot` is an aligned, readable entry of the main
            // module's import address table (`MappedImage::import_slot`).
            let original = unsafe { slot.read_volatile() };
            self.originals[i].store(original.cast_mut(), Ordering::Release);
            let Some(previous) = write_slot(slot, hook.replacement) else {
                warn!(
                    target: LOG_TARGET,
                    "import patch: the import slot of {} is not writable",
                    String::from_utf8_lossy(hook.func)
                );
                continue;
            };
            if previous != original {
                // Something else rewrote the slot between the read and the
                // write; forward to what the slot held when it was replaced.
                self.originals[i].store(previous.cast_mut(), Ordering::Release);
                mtld3d_shared::log_once_warn!(
                    target: LOG_TARGET,
                    "import patch: an import slot changed while it was being patched → \
                     forwarding to the entry point it held at the write",
                );
            }
            self.slots[i].store(slot, Ordering::Release);
            patched += 1;
        }
        patched
    }

    /// Put the original entry points back. Idempotent.
    ///
    /// Called on the `FreeLibrary` path the process survives, so no slot
    /// keeps pointing into an image that is about to unmap. The originals
    /// stay recorded: a thread that entered a replacement before its slot
    /// was restored still forwards through them.
    pub fn uninstall(&self) {
        for (slot, original) in self.slots.iter().zip(&self.originals) {
            let slot = slot.swap(ptr::null_mut(), Ordering::AcqRel);
            if slot.is_null() {
                continue;
            }
            write_slot(slot, original.load(Ordering::Acquire));
        }
        self.installed.store(false, Ordering::Release);
    }

    /// The entry point the slot at `index` held, as the function type `F`.
    pub fn original<F>(&self, index: usize) -> F {
        let original = self.originals[index].load(Ordering::Acquire);
        // SAFETY: the slot held an entry point of exactly the signature `F`
        // names before `install` replaced it, and `install` records it before
        // the slot can lead a caller into a replacement and never clears it,
        // so the pointer is that entry point and `F` is a pointer-sized `fn`
        // type.
        unsafe { core::mem::transmute_copy(&original) }
    }
}

/// The process's main module, if the loader can name it.
fn main_module() -> Option<MappedImage> {
    // SAFETY: Win32; a null name selects the process's main module.
    let base = unsafe { GetModuleHandleA(ptr::null()) };
    if base.is_null() {
        return None;
    }
    // SAFETY: `GetModuleHandleA(NULL)` is the base of the main module the
    // loader mapped in this process.
    Some(unsafe { MappedImage::new(base.cast::<u8>().cast_const()) })
}

/// Write `value` into an import slot, returning what it held; `None` if the page cannot be opened.
fn write_slot(slot: *mut *const (), value: *const ()) -> Option<*const ()> {
    let mut old_protect = 0;
    // SAFETY: `slot` lies inside the main module's mapped import table
    // (`MappedImage::import_slot`); `old_protect` is an owned local.
    let opened = unsafe {
        VirtualProtect(
            slot.cast::<c_void>(),
            size_of::<usize>(),
            PAGE_READWRITE,
            &raw mut old_protect,
        )
    };
    if opened == 0 {
        return None;
    }
    // SAFETY: the slot's page is writable as of the call above and the slot
    // is a valid, aligned pointer-sized entry of the import address table.
    let previous = unsafe { slot.replace(value) };
    // SAFETY: restoring the protection the page had; a failure here leaves
    // the page writable, which is harmless.
    unsafe {
        VirtualProtect(
            slot.cast::<c_void>(),
            size_of::<usize>(),
            old_protect,
            &raw mut old_protect,
        )
    };
    Some(previous)
}
