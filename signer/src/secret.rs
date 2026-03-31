//! Zeroize-on-drop secret byte buffer.

use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

/// A byte buffer that is zeroed on drop.
///
/// Primary type for holding sensitive key material. On Unix with the `std`
/// feature, the buffer is `mlock`ed to prevent swapping to disk.
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Create from an owned `Vec`.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        let s = Self { inner: data };
        #[cfg(feature = "std")]
        if !s.inner.is_empty() {
            crate::hardening::mlock_slice(s.inner.as_ptr(), s.inner.len());
        }
        s
    }

    /// Create from a byte slice (copies the data).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Expose the underlying bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Length of the secret data.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the secret data is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(&self.inner)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        #[cfg(feature = "std")]
        let (ptr, len) = (self.inner.as_ptr(), self.inner.len());
        self.inner.zeroize();
        #[cfg(feature = "std")]
        crate::hardening::munlock_slice(ptr, len);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak() {
        let s = SecretBytes::new(alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let dbg = alloc::format!("{s:?}");
        assert!(!dbg.contains("DE"));
        assert!(dbg.contains("[REDACTED; 4 bytes]"));
    }

    #[test]
    fn expose_returns_data() {
        let data = alloc::vec![1, 2, 3, 4];
        let s = SecretBytes::new(data.clone());
        assert_eq!(s.expose(), &data[..]);
    }

    #[test]
    fn clone_independence() {
        let a = SecretBytes::new(alloc::vec![1, 2, 3]);
        let b = a.clone();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose().as_ptr(), b.expose().as_ptr());
    }
}
