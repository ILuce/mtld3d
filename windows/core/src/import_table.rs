//! Finding an import slot in a mapped PE image, without trusting the image.
//!
//! Fork patch 1 (this file is not part of upstream mtld3d 0.15.3; see `FORK.md`).
//!
//! Upstream's walk, in `d3d9`'s `import_patch`, read the main module's import directory on the assumption that
//! every RVA in its headers resolves inside the mapping. A packed executable breaks that:
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

/// The first page of an image, which the loader always maps and where the headers of an
/// image it accepted begin. The headers are read inside it, before the image's size is known.
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
/// Offset of `DataDirectory` inside the optional header, per format; `NumberOfRvaAndSizes`
/// is the four bytes before it.
const PE32_DATA_DIRECTORY_OFFSET: usize = 96;
const PE32PLUS_DATA_DIRECTORY_OFFSET: usize = 112;
/// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
const IMPORT_DIRECTORY: usize = 1;
/// Size of `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// More import descriptors than an image has; a list without its terminator stops here.
const MAX_DESCRIPTORS: usize = 4096;
/// More named imports from one module than an image has; a table without its terminator
/// stops here.
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

    /// Whether the NUL-terminated string at `rva` is `expected`. A string that leaves the
    /// image or cannot be read is not.
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
mod tests {
    use super::*;

    /// A synthetic image as the loader maps it: `bytes` is the whole mapping (`SizeOfImage`
    /// long). A read beyond it is what an access violation is in a process, so it fails the
    /// test; a read inside `unreadable` (a page the program decommitted or protected) is
    /// refused, as the Windows-side reader refuses it.
    struct Mapped {
        bytes: Vec<u8>,
        unreadable: Vec<core::ops::Range<usize>>,
    }

    impl ImageBytes for Mapped {
        fn read(&self, rva: usize, out: &mut [u8]) -> bool {
            let end = rva
                .checked_add(out.len())
                .expect("the walk's RVA overflowed");
            assert!(
                end <= self.bytes.len(),
                "access violation: read of {:#x}..{end:#x} outside the image of {:#x} bytes",
                rva,
                self.bytes.len()
            );
            if self
                .unreadable
                .iter()
                .any(|hole| rva < hole.end && hole.start < end)
            {
                return false;
            }
            out.copy_from_slice(&self.bytes[rva..end]);
            true
        }
    }

    /// One import descriptor of the synthetic image.
    struct Module {
        dll: &'static str,
        funcs: &'static [&'static str],
        /// `OriginalFirstThunk == FirstThunk`: one table is the name table and the address
        /// table, as a packer's stub writes it (Just Cause 1).
        shared_table: bool,
    }

    const SIZE: usize = 0x4000;
    const NT: usize = 0x80;
    const IMPORTS: usize = 0x1000;

    /// An RVA or a size of the test image as a header field holds it.
    fn rva(value: usize) -> [u8; 4] {
        u32::try_from(value)
            .expect("the test image is smaller than 4 GiB")
            .to_le_bytes()
    }

    fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
        bytes[at..at + value.len()].copy_from_slice(value);
    }

    fn put_thunk(bytes: &mut [u8], at: usize, width: usize, value: u64) {
        put(bytes, at, &value.to_le_bytes()[..width]);
    }

    /// A PE32 (`width` 4) or PE32+ (8) image with `modules` imported by name, as it is on
    /// disk: every thunk holds the RVA of its hint/name entry. Returns the image and, per
    /// module, the RVA of its address table.
    fn image(width: usize, modules: &[Module]) -> (Mapped, Vec<usize>) {
        let mut bytes = vec![0u8; SIZE];
        put(&mut bytes, 0, b"MZ");
        put(&mut bytes, E_LFANEW_OFFSET, &rva(NT));
        put(&mut bytes, NT, b"PE\0\0");
        let optional = NT + 4 + FILE_HEADER_SIZE;
        let (magic, directory) = if width == 8 {
            (PE32PLUS_MAGIC, PE32PLUS_DATA_DIRECTORY_OFFSET)
        } else {
            (PE32_MAGIC, PE32_DATA_DIRECTORY_OFFSET)
        };
        put(&mut bytes, optional, &magic.to_le_bytes());
        put(&mut bytes, optional + 56, &rva(SIZE)); // SizeOfImage
        put(&mut bytes, optional + directory - 4, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
        put(
            &mut bytes,
            optional + directory + IMPORT_DIRECTORY * 8,
            &rva(IMPORTS),
        );
        // Descriptors first (one more, all zero, ends the list), then each module's tables
        // and strings.
        let mut at = IMPORTS + (modules.len() + 1) * IMPORT_DESCRIPTOR_SIZE;
        let mut tables = Vec::new();
        for (i, module) in modules.iter().enumerate() {
            let table = (module.funcs.len() + 1) * width;
            let names = at;
            let addresses = if module.shared_table {
                names
            } else {
                names + table
            };
            at = addresses + table;
            let dll = at;
            put(&mut bytes, dll, module.dll.as_bytes());
            at += module.dll.len() + 1;
            for (j, func) in module.funcs.iter().enumerate() {
                at += at % 2;
                put(&mut bytes, at + 2, func.as_bytes());
                put_thunk(&mut bytes, names + j * width, width, at as u64);
                put_thunk(&mut bytes, addresses + j * width, width, at as u64);
                at += 2 + func.len() + 1;
            }
            let descriptor = IMPORTS + i * IMPORT_DESCRIPTOR_SIZE;
            put(&mut bytes, descriptor, &rva(names));
            put(&mut bytes, descriptor + 12, &rva(dll));
            put(&mut bytes, descriptor + 16, &rva(addresses));
            tables.push(addresses);
        }
        assert!(at < SIZE);
        (
            Mapped {
                bytes,
                unreadable: Vec::new(),
            },
            tables,
        )
    }

    /// What the loader does when it binds the image: every address-table entry becomes the
    /// address of the imported function, here `base + 0x10 * (index + 1)`.
    fn bind(mapped: &mut Mapped, width: usize, table: usize, count: usize, base: u64) {
        for j in 0..count {
            put_thunk(
                &mut mapped.bytes,
                table + j * width,
                width,
                base + 0x10 * (j as u64 + 1),
            );
        }
    }

    const KERNEL32: Module = Module {
        dll: "KERNEL32.dll",
        funcs: &["GetLastError", "ExitProcess", "Sleep"],
        shared_table: false,
    };
    const USER32: Module = Module {
        dll: "USER32.dll",
        funcs: &["EnumDisplaySettingsA", "MessageBoxA"],
        shared_table: false,
    };

    /// An ordinary executable, bound by the loader: the slot of each import is found, with
    /// and without the exporting module named, in both image formats.
    #[test]
    fn an_ordinary_bound_image_gives_the_slot_of_a_named_import() {
        for width in [4usize, 8] {
            let (mut mapped, tables) = image(width, &[KERNEL32, USER32]);
            let base = if width == 8 {
                0x0000_7ff8_1234_0000
            } else {
                0x7b62_0000
            };
            bind(&mut mapped, width, tables[0], 3, base);
            bind(&mut mapped, width, tables[1], 2, base + 0x10_0000);
            assert_eq!(
                import_slot_rva(&mapped, width, None, b"ExitProcess"),
                Some(tables[0] + width)
            );
            assert_eq!(
                import_slot_rva(&mapped, width, Some(b"user32.dll"), b"EnumDisplaySettingsA"),
                Some(tables[1])
            );
            assert_eq!(
                import_slot_rva(&mapped, width, Some(b"user32.dll"), b"ExitProcess"),
                None
            );
            assert_eq!(import_slot_rva(&mapped, width, None, b"exit"), None);
            // An image of the other format cannot be this process's main module.
            assert_eq!(
                import_slot_rva(&mapped, 12 - width, None, b"ExitProcess"),
                None
            );
        }
    }

    /// Just Cause 1 (`JustCause.exe`, a packed executable): its only import descriptor names
    /// one table as its name table and its address table. Once the loader has bound it, the
    /// table holds the addresses of the four `kernel32` functions; read as hint/name RVAs
    /// they point outside the image. Upstream 0.15.3 read there, inside `DllMain`, and the
    /// load of `d3d9.dll` failed. Such a descriptor is not
    /// searchable and is passed over.
    #[test]
    fn a_descriptor_whose_name_table_is_its_address_table_is_passed_over() {
        let stub = Module {
            dll: "kernel32.dll",
            funcs: &[
                "LoadLibraryA",
                "GetProcAddress",
                "VirtualAlloc",
                "VirtualFree",
            ],
            shared_table: true,
        };
        let (mut mapped, tables) = image(4, &[stub]);
        // Where Wine maps the 32-bit kernel32 (the addresses are below 0x8000_0000, so they do
        // not read as imports by ordinal).
        bind(&mut mapped, 4, tables[0], 4, 0x7b62_0000);
        for func in [
            &b"ExitProcess"[..],
            b"RtlExitUserProcess",
            b"exit",
            b"LoadLibraryA",
        ] {
            assert_eq!(import_slot_rva(&mapped, 4, None, func), None);
        }
        assert_eq!(
            import_slot_rva(&mapped, 4, Some(b"user32.dll"), b"EnumDisplaySettingsA"),
            None
        );
        // A module after it is still searched.
        let stub = Module {
            dll: "kernel32.dll",
            funcs: &["LoadLibraryA", "GetProcAddress"],
            shared_table: true,
        };
        let (mut mapped, tables) = image(4, &[stub, USER32]);
        bind(&mut mapped, 4, tables[0], 2, 0x7b62_0000);
        bind(&mut mapped, 4, tables[1], 2, 0x7e41_0000);
        assert_eq!(
            import_slot_rva(&mapped, 4, None, b"MessageBoxA"),
            Some(tables[1] + 4)
        );
    }

    /// What other packers and protectors leave behind: tables, strings and descriptor lists
    /// that point outside the image or never end, and pages the program took away. None of
    /// it is an import the walk can use, and none of it may be read.
    #[test]
    fn tables_that_leave_the_image_or_cannot_be_read_are_no_imports() {
        let optional = NT + 4 + FILE_HEADER_SIZE;
        let directory = optional + PE32_DATA_DIRECTORY_OFFSET + IMPORT_DIRECTORY * 8;
        // The import directory itself lies beyond the image.
        let (mut mapped, _) = image(4, &[KERNEL32]);
        put(&mut mapped.bytes, directory, &0x0001_0000u32.to_le_bytes());
        assert_eq!(import_slot_rva(&mapped, 4, None, b"ExitProcess"), None);
        // A name-table entry points beyond the image (a table the stub overwrote).
        let (mut mapped, tables) = image(4, &[KERNEL32]);
        let names = tables[0] - 4 * 4;
        put(&mut mapped.bytes, names, &0x7b62_0010u32.to_le_bytes());
        assert_eq!(import_slot_rva(&mapped, 4, None, b"GetLastError"), None);
        assert_eq!(
            import_slot_rva(&mapped, 4, None, b"ExitProcess"),
            Some(tables[0] + 4),
            "the entries after it are still read"
        );
        // The module's name lies beyond the image.
        let (mut mapped, tables) = image(4, &[KERNEL32]);
        put(
            &mut mapped.bytes,
            IMPORTS + 12,
            &0x00ff_fff0u32.to_le_bytes(),
        );
        assert_eq!(
            import_slot_rva(&mapped, 4, Some(b"kernel32.dll"), b"ExitProcess"),
            None
        );
        assert_eq!(
            import_slot_rva(&mapped, 4, None, b"ExitProcess"),
            Some(tables[0] + 4),
            "without a module to match, its name is not read"
        );
        // A descriptor list without its terminator runs to the end of the image.
        let mut mapped = image(4, &[]).0;
        for at in (IMPORTS..SIZE).step_by(4) {
            put(&mut mapped.bytes, at, &0x0000_3ff0u32.to_le_bytes());
        }
        assert_eq!(import_slot_rva(&mapped, 4, None, b"ExitProcess"), None);
        // A name table without its terminator does too.
        let (mut mapped, tables) = image(4, &[KERNEL32]);
        let names = tables[0] - 4 * 4;
        for at in (names..SIZE).step_by(4) {
            put(&mut mapped.bytes, at, &0x8000_0001u32.to_le_bytes());
        }
        assert_eq!(import_slot_rva(&mapped, 4, None, b"ExitProcess"), None);
        // The headers claim a larger image than the one that is there to read: the reader
        // refuses, and that is no import either.
        let (mut mapped, tables) = image(4, &[KERNEL32]);
        mapped.unreadable.push(tables[0] - 4 * 4..tables[0]);
        assert_eq!(import_slot_rva(&mapped, 4, None, b"ExitProcess"), None);
        let (mut mapped, _) = image(4, &[KERNEL32]);
        mapped.unreadable.push(0..0x1000);
        assert_eq!(import_slot_rva(&mapped, 4, None, b"ExitProcess"), None);
        // Not an image at all.
        let blank = Mapped {
            bytes: vec![0; SIZE],
            unreadable: Vec::new(),
        };
        assert_eq!(import_slot_rva(&blank, 4, None, b"ExitProcess"), None);
    }
}
