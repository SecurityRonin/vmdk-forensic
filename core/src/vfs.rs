//! `forensic-vfs` integration: a decoded VMDK as an [`ImageSource`].
//!
//! A decoded VMDK is a read-only, randomly-addressable byte stream — the
//! `ImageSource` contract. [`VmdkReader`] resolves a virtual offset to physical
//! grains through a `Read + Seek` cursor (the translation advances an internal
//! position, so it needs `&mut self`). Unlike a `&self` positioned reader, it is
//! therefore wrapped here: [`VmdkSource`] holds the reader behind a
//! poison-recovering `Mutex` and serves `read_at` by seeking then reading under
//! the lock. Reads serialize through the mutex. Behind the `vfs` feature.

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use forensic_vfs::ImageSource;

    use super::VmdkSource;
    use crate::VmdkReader;

    /// A synthetic monolithicSparse VMDK whose single grain begins with a known
    /// marker, driven purely through the `ImageSource` API.
    #[test]
    fn vmdk_reader_is_an_image_source() {
        let marker = b"VMDK_VFS_MARKER_0123456789";
        let image = crate::testutil::test_sparse_vmdk(marker);
        let reader = VmdkReader::open(Cursor::new(image)).expect("open synthetic vmdk");
        let expected_len = reader.virtual_disk_size();

        // The load-bearing claim: a VmdkReader composes as a dyn ImageSource.
        let src: Arc<dyn ImageSource> = Arc::new(VmdkSource::new(reader));
        assert_eq!(src.len(), expected_len);
        assert!(!src.is_empty());

        // Positioned read of the first bytes returns the known marker.
        let mut buf = vec![0u8; marker.len()];
        let n = src.read_at(0, &mut buf).expect("read_at");
        assert_eq!(n, marker.len());
        assert_eq!(&buf, marker);

        // A read starting at EOF yields 0 (ImageSource short-read contract).
        let mut eof = [0u8; 16];
        assert_eq!(src.read_at(expected_len, &mut eof).expect("eof read"), 0);
    }
}
