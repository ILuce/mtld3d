//! Unit tests for the import-table walk, over synthetic mapped images.

use super::*;

/// A synthetic image as the loader maps it.
///
/// `bytes` is the whole mapping (`SizeOfImage` long). A read beyond it is what an access
/// violation is in a process, so it fails the test; a read inside `unreadable` (a page the
/// program decommitted or protected) is refused, as the Windows-side reader refuses it.
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
    /// `OriginalFirstThunk == FirstThunk`, as a packer's stub writes it (Just Cause 1).
    ///
    /// One table is the name table and the address table.
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

/// A PE32 (`width` 4) or PE32+ (8) image with `modules` imported by name, as on disk.
///
/// Every thunk holds the RVA of its hint/name entry. Returns the image and, per module,
/// the RVA of its address table.
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

/// What the loader does when it binds the image.
///
/// Every address-table entry becomes the address of the imported function, here
/// `base + 0x10 * (index + 1)`.
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

/// An ordinary executable, bound by the loader, gives the slot of each import.
///
/// With and without the exporting module named, in both image formats.
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

/// Just Cause 1 (`JustCause.exe`, a packed executable).
///
/// Its only import descriptor names one table as its name table and its address table.
/// Once the loader has bound it, the
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

/// What other packers and protectors leave behind.
///
/// Tables, strings and descriptor lists that point outside the image or never end, and
/// pages the program took away. None of it is an import the walk can use, and none of it
/// may be read.
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
