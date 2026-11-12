//! Finding an import slot in a mapped PE image, without trusting the image.
//!
//! Fork patch 1 (this file is not part of upstream mtld3d 0.15.3; see `FORK.md`).
//!
//! Upstream's walk, in `d3d9`'s `import_patch`, read the main module's import directory on
//! the assumption that every RVA in its headers resolves inside the mapping. A packed
//! executable breaks that:
//! the only import descriptor of Just Cause 1 names one table as both its name table and its
//! address table, so once the loader has bound it the "names" are function addresses, and
//! the walk read memory far outside the image from inside `DllMain`. The load of `d3d9.dll`
//! failed and the game could not start. The walk lives here, where the host unit tests run
//! it, and takes nothing on trust:
//!
//! - every read goes through [`ImageBytes`], which may refuse (the Windows side asks the
//!   system whether the pages are committed and readable), and a refused read is "no such
//!   import", never a fault;
//! - every RVA, table entry and string is held inside the image's own `SizeOfImage` before
//!   it is read;
//! - a descriptor whose name table is its address table is passed over, like one without a
//!   name table: once bound, neither holds names;
//! - the descriptor list and each name table have a length limit, so a list that lost its
//!   terminator ends.
//!
//! An ordinary executable is read as before and gives the same slot.

/// The bytes of a PE image as the loader mapped it, addressed by RVA.
pub trait ImageBytes {
    /// Copy `out.len()` bytes at `rva` into `out`; `false` when any of them cannot be read.
    fn read(&self, rva: usize, out: &mut [u8]) -> bool;
}

/// The first page of an image, which the loader always maps.
///
/// The headers of an image the loader accepted begin there, and they are read inside it,
/// before the image's size is known.
const FIRST_PAGE: usize = 0x1000;
/// `IMAGE_DOS_HEADER.e_lfanew`: file offset of the NT headers.
const E_LFANEW_OFFSET: usize = 0x3c;
/// Size of `IMAGE_FILE_HEADER`, which sits between the PE signature and the optional header.
const FILE_HEADER_SIZE: usize = 20;
/// `IMAGE_OPTIONAL_HEADER.Magic` for PE32 and PE32+.
const PE32_MAGIC: u16 = 0x10b;
const PE32PLUS_MAGIC: u16 = 0x20b;
/// Offset of `SizeOfImage` inside the optional header, in both formats.
const SIZE_OF_IMAGE_OFFSET: usize = 56;
/// Offset of `DataDirectory` inside the optional header, per format.
///
/// `NumberOfRvaAndSizes` is the four bytes before it.
const PE32_DATA_DIRECTORY_OFFSET: usize = 96;
const PE32PLUS_DATA_DIRECTORY_OFFSET: usize = 112;
/// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
const IMPORT_DIRECTORY: usize = 1;
/// Size of `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// More import descriptors than an image has; a list without its terminator stops here.
const MAX_DESCRIPTORS: usize = 4096;
/// More named imports from one module than an image has.
///
/// A table without its terminator stops here.
const MAX_IMPORTS_PER_MODULE: usize = 65_536;

/// Bounded reads of one image.
struct Walk<'a, I> {
    image: &'a I,
    /// No read goes past this RVA: the first page until the headers gave `SizeOfImage`.
    size: usize,
    /// Width of a thunk entry and of an import slot: 4 for PE32, 8 for PE32+.
    width: usize,
}

impl<I: ImageBytes> Walk<'_, I> {
    /// `N` bytes at `rva`, when they lie inside the image and can be read.
    fn bytes<const N: usize>(&self, rva: usize) -> Option<[u8; N]> {
        if rva.checked_add(N)? > self.size {
            return None;
        }
        let mut out = [0; N];
        self.image.read(rva, &mut out).then_some(out)
    }

    fn u32(&self, rva: usize) -> Option<usize> {
        usize::try_from(u32::from_le_bytes(self.bytes(rva)?)).ok()
    }

    /// One entry of a name table or an address table.
    fn thunk(&self, rva: usize) -> Option<u64> {
        if self.width == 8 {
            self.bytes(rva).map(u64::from_le_bytes)
        } else {
            self.bytes(rva)
                .map(|bytes| u64::from(u32::from_le_bytes(bytes)))
        }
    }

    /// Whether the NUL-terminated string at `rva` is `expected`.
    ///
    /// A string that leaves the image or cannot be read is not.
    fn string_is(&self, rva: usize, expected: &[u8], ignore_ascii_case: bool) -> bool {
        let inside = rva
            .checked_add(expected.len())
            .and_then(|end| end.checked_add(1))
            .is_some_and(|end| end <= self.size);
        if !inside {
            return false;
        }
        let mut buffer = [0u8; 64];
        let mut at = rva;
        for chunk in expected.chunks(buffer.len()) {
            let read = &mut buffer[..chunk.len()];
            if !self.image.read(at, read) {
                return false;
            }
            let same = if ignore_ascii_case {
                read.eq_ignore_ascii_case(chunk)
            } else {
                read == chunk
            };
            if !same {
                return false;
            }
            at += chunk.len();
        }
        self.bytes::<1>(at) == Some([0])
    }

    /// The RVA of the address-table slot of `func` in one descriptor's name table.
    fn named_slot(&self, names: usize, addresses: usize, func: &[u8]) -> Option<usize> {
        let ordinal_flag = 1u64 << (self.width * 8 - 1);
        for j in 0..MAX_IMPORTS_PER_MODULE {
            let offset = j * self.width;
            let entry = self.thunk(names.checked_add(offset)?)?;
            if entry == 0 {
                return None;
            }
            if entry & ordinal_flag != 0 {
                continue;
            }
            // `IMAGE_IMPORT_BY_NAME`: a u16 hint, then the name. An entry that is no RVA
            // into the image names nothing.
            let Some(name) = usize::try_from(entry)
                .ok()
                .and_then(|hint| hint.checked_add(2))
            else {
                continue;
            };
            if self.string_is(name, func, false) {
                // The caller reads and writes the slot, so it has to be there as well.
                let slot = addresses.checked_add(offset)?;
                self.thunk(slot)?;
                return Some(slot);
            }
        }
        None
    }
}

/// The RVA of the import-address-table slot for `func`, if the image imports it by name.
///
/// `dll` names the exporting module the import must come from; `None` takes the first import
/// descriptor that carries the name, whichever module it is. `pointer_size` is the width of a
/// pointer in the process: the main module of a process has that format, and an image of
/// the other one has no slot a pointer could be written into.
///
/// Nothing outside the image's own `SizeOfImage` is read, and nothing `image` refuses to
/// read; whatever the walk cannot read is an import the image does not have.
pub fn import_slot_rva<I: ImageBytes>(
    image: &I,
    pointer_size: usize,
    dll: Option<&[u8]>,
    func: &[u8],
) -> Option<usize> {
    let headers = Walk {
        image,
        size: FIRST_PAGE,
        width: pointer_size,
    };
    if headers.bytes::<2>(0)? != *b"MZ" {
        return None;
    }
    let nt = headers.u32(E_LFANEW_OFFSET)?;
    if headers.bytes::<4>(nt)? != *b"PE\0\0" {
        return None;
    }
    let optional = nt.checked_add(4 + FILE_HEADER_SIZE)?;
    let (directory, width) = match u16::from_le_bytes(headers.bytes(optional)?) {
        PE32_MAGIC => (PE32_DATA_DIRECTORY_OFFSET, 4),
        PE32PLUS_MAGIC => (PE32PLUS_DATA_DIRECTORY_OFFSET, 8),
        _ => return None,
    };
    if width != pointer_size {
        return None;
    }
    let size = headers.u32(optional.checked_add(SIZE_OF_IMAGE_OFFSET)?)?;
    let walk = Walk { image, size, width };
    let directories = walk.u32(optional.checked_add(directory - 4)?)?;
    if directories <= IMPORT_DIRECTORY {
        return None;
    }
    let imports = walk.u32(optional.checked_add(directory + IMPORT_DIRECTORY * 8)?)?;
    if imports == 0 {
        return None;
    }
    for i in 0..MAX_DESCRIPTORS {
        let descriptor = imports.checked_add(i * IMPORT_DESCRIPTOR_SIZE)?;
        let name_rva = walk.u32(descriptor.checked_add(12)?)?;
        if name_rva == 0 {
            return None;
        }
        let names = walk.u32(descriptor)?;
        let addresses = walk.u32(descriptor.checked_add(16)?)?;
        // Without a separate name table the address table held the names until the loader
        // overwrote it with addresses, and the loader has. That is a descriptor with no
        // name table, and equally one that names the address table as its name table (what
        // a packer's stub writes): neither is searchable here.
        if names == 0 || addresses == 0 || names == addresses {
            continue;
        }
        if dll.is_some_and(|dll| !walk.string_is(name_rva, dll, true)) {
            continue;
        }
        if let Some(slot) = walk.named_slot(names, addresses, func) {
            return Some(slot);
        }
    }
    None
}

#[cfg(test)]
mod tests;
