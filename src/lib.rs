pub mod ffi;

mod sanity {
    // We need this equality because in the build script we can only get the width
    // of a pointer, not that of a `usize`.
    const _: () = core::assert!(core::mem::size_of::<usize>() == core::mem::size_of::<*const u8>());
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
