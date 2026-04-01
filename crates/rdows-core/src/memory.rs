/// Access flags bitmask for Memory Region permissions per RFC Section 6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessFlags(pub u32);

impl AccessFlags {
    pub const LOCAL_WRITE: AccessFlags = AccessFlags(0x01);
    pub const REMOTE_WRITE: AccessFlags = AccessFlags(0x02);
    pub const REMOTE_READ: AccessFlags = AccessFlags(0x04);
    pub const REMOTE_ATOMIC: AccessFlags = AccessFlags(0x08);

    pub fn contains(self, flag: AccessFlags) -> bool {
        self.0 & flag.0 == flag.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for AccessFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        AccessFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for AccessFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Protection Domain identifier per RFC Section 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtectionDomain(pub u32);

/// Local Key for scatter/gather buffer identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LKey(pub u32);

/// Remote Key for RDMA access authorization per RFC Section 6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RKey(pub u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_flags_contains() {
        let flags = AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ;
        assert!(flags.contains(AccessFlags::REMOTE_WRITE));
        assert!(flags.contains(AccessFlags::REMOTE_READ));
        assert!(!flags.contains(AccessFlags::LOCAL_WRITE));
        assert!(!flags.contains(AccessFlags::REMOTE_ATOMIC));
    }

    #[test]
    fn access_flags_empty() {
        assert!(AccessFlags(0).is_empty());
        assert!(!AccessFlags::LOCAL_WRITE.is_empty());
    }

    #[test]
    fn access_flags_bitor_assign() {
        let mut flags = AccessFlags(0);
        flags |= AccessFlags::LOCAL_WRITE;
        flags |= AccessFlags::REMOTE_READ;
        assert!(flags.contains(AccessFlags::LOCAL_WRITE));
        assert!(flags.contains(AccessFlags::REMOTE_READ));
        assert_eq!(flags.0, 0x05);
    }
}
