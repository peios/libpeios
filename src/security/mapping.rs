//! Access-mask helpers — `peios_access_map_generic` (`<peios/security.h>`).
//!
//! The four generic rights (`GENERIC_READ/WRITE/EXECUTE/ALL`) are placeholders an
//! object class resolves into concrete rights via its generic mapping. This is
//! the standard MS-DTYP `MapGenericMask` fold: OR in the mapped bits for each
//! generic right present, then clear the generic bits themselves. The per-class
//! mappings (`peios_file_generic_mapping`, `peios_token_generic_mapping`) are
//! published by `<peios/file.h>` / `<peios/token.h>`.

use peios_uapi::{
    kacs_generic_mapping, KACS_ACCESS_GENERIC_ALL, KACS_ACCESS_GENERIC_EXECUTE,
    KACS_ACCESS_GENERIC_READ, KACS_ACCESS_GENERIC_WRITE,
};

const GENERIC_BITS: u32 = KACS_ACCESS_GENERIC_READ
    | KACS_ACCESS_GENERIC_WRITE
    | KACS_ACCESS_GENERIC_EXECUTE
    | KACS_ACCESS_GENERIC_ALL;

/// `peios_access_map_generic` — fold `mask`'s generic bits through `m`.
///
/// A NULL `m` is a misuse; the mask is returned unchanged rather than faulting.
#[no_mangle]
pub unsafe extern "C" fn peios_access_map_generic(
    mask: u32,
    m: *const kacs_generic_mapping,
) -> u32 {
    let Some(m) = m.as_ref() else { return mask };
    let mut mapped = 0u32;
    if mask & KACS_ACCESS_GENERIC_READ != 0 {
        mapped |= m.read;
    }
    if mask & KACS_ACCESS_GENERIC_WRITE != 0 {
        mapped |= m.write;
    }
    if mask & KACS_ACCESS_GENERIC_EXECUTE != 0 {
        mapped |= m.execute;
    }
    if mask & KACS_ACCESS_GENERIC_ALL != 0 {
        mapped |= m.all;
    }
    (mask & !GENERIC_BITS) | mapped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_and_clears_generic_bits() {
        let m = kacs_generic_mapping {
            read: 0x0012_0089,
            write: 0x0012_0116,
            execute: 0x0012_00A0,
            all: 0x001F_01FF,
        };
        unsafe {
            assert_eq!(
                peios_access_map_generic(KACS_ACCESS_GENERIC_READ, &m),
                0x0012_0089
            );
            assert_eq!(
                peios_access_map_generic(KACS_ACCESS_GENERIC_ALL, &m),
                0x001F_01FF
            );
            // Non-generic bits pass through; the generic bit is cleared.
            let mixed = peios_access_map_generic(KACS_ACCESS_GENERIC_WRITE | 0x40, &m);
            assert_eq!(mixed, 0x0012_0116 | 0x40);
            assert_eq!(mixed & GENERIC_BITS, 0);
            // NULL mapping returns the mask unchanged.
            assert_eq!(peios_access_map_generic(0x5, core::ptr::null()), 0x5);
        }
    }
}
