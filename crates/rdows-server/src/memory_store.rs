use std::collections::{HashMap, HashSet};

use rand::rngs::OsRng;
use rand::RngCore;

use rdows_core::error::ErrorCode;
use rdows_core::memory::{AccessFlags, LKey, ProtectionDomain, RKey};

pub struct MemoryRegionEntry {
    pub pd: ProtectionDomain,
    pub lkey: LKey,
    pub rkey: RKey,
    pub access_flags: AccessFlags,
    pub data: Vec<u8>,
}

pub struct MemoryStore {
    regions: HashMap<u32, MemoryRegionEntry>,
    rkey_to_lkey: HashMap<u32, u32>,
    used_rkeys: HashSet<u32>,
    next_lkey: u32,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            regions: HashMap::new(),
            rkey_to_lkey: HashMap::new(),
            used_rkeys: HashSet::new(),
            next_lkey: 1,
        }
    }

    pub fn register(
        &mut self,
        pd: ProtectionDomain,
        access_flags: AccessFlags,
        region_len: u64,
    ) -> Result<(LKey, RKey), ErrorCode> {
        let lkey = LKey(self.next_lkey);
        self.next_lkey += 1;

        let rkey = self.generate_rkey()?;
        let data = vec![0u8; region_len as usize];

        let entry = MemoryRegionEntry {
            pd,
            lkey,
            rkey,
            access_flags,
            data,
        };

        self.rkey_to_lkey.insert(rkey.0, lkey.0);
        self.regions.insert(lkey.0, entry);

        Ok((lkey, rkey))
    }

    pub fn deregister(&mut self, pd: ProtectionDomain, lkey: LKey) -> Result<(), ErrorCode> {
        let entry = self
            .regions
            .get(&lkey.0)
            .ok_or(ErrorCode::ErrInvalidLkey)?;

        if entry.pd != pd {
            return Err(ErrorCode::ErrInvalidPd);
        }

        let rkey = entry.rkey;
        self.rkey_to_lkey.remove(&rkey.0);
        self.regions.remove(&lkey.0);
        // R_Key stays in used_rkeys — never reuse within session
        Ok(())
    }

    pub fn validate_rkey(
        &self,
        rkey: RKey,
        required_access: AccessFlags,
    ) -> Result<&MemoryRegionEntry, ErrorCode> {
        let lkey_val = self
            .rkey_to_lkey
            .get(&rkey.0)
            .ok_or(ErrorCode::ErrInvalidMkey)?;
        let entry = self
            .regions
            .get(lkey_val)
            .ok_or(ErrorCode::ErrInvalidMkey)?;

        if !entry.access_flags.contains(required_access) {
            return Err(ErrorCode::ErrAccessDenied);
        }

        Ok(entry)
    }

    pub fn write_region(
        &mut self,
        rkey: RKey,
        offset: u64,
        data: &[u8],
    ) -> Result<(), ErrorCode> {
        let lkey_val = self
            .rkey_to_lkey
            .get(&rkey.0)
            .ok_or(ErrorCode::ErrInvalidMkey)?;
        let entry = self
            .regions
            .get_mut(lkey_val)
            .ok_or(ErrorCode::ErrInvalidMkey)?;

        if !entry.access_flags.contains(AccessFlags::REMOTE_WRITE) {
            return Err(ErrorCode::ErrAccessDenied);
        }

        let start = offset as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(ErrorCode::ErrBounds)?;
        if end > entry.data.len() {
            return Err(ErrorCode::ErrBounds);
        }

        entry.data[start..end].copy_from_slice(data);
        Ok(())
    }

    pub fn read_region(&self, rkey: RKey, offset: u64, len: u64) -> Result<&[u8], ErrorCode> {
        let lkey_val = self
            .rkey_to_lkey
            .get(&rkey.0)
            .ok_or(ErrorCode::ErrInvalidMkey)?;
        let entry = self
            .regions
            .get(lkey_val)
            .ok_or(ErrorCode::ErrInvalidMkey)?;

        if !entry.access_flags.contains(AccessFlags::REMOTE_READ) {
            return Err(ErrorCode::ErrAccessDenied);
        }

        let start = offset as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or(ErrorCode::ErrBounds)?;
        if end > entry.data.len() {
            return Err(ErrorCode::ErrBounds);
        }

        Ok(&entry.data[start..end])
    }

    pub fn atomic_op(
        &mut self,
        rkey: RKey,
        remote_va: u64,
        atomic_type: u8,
        operand1: u64,
        operand2: u64,
    ) -> Result<u64, ErrorCode> {
        let lkey_val = self
            .rkey_to_lkey
            .get(&rkey.0)
            .ok_or(ErrorCode::ErrInvalidMkey)?;
        let entry = self
            .regions
            .get_mut(lkey_val)
            .ok_or(ErrorCode::ErrInvalidMkey)?;

        if !entry.access_flags.contains(AccessFlags::REMOTE_ATOMIC) {
            return Err(ErrorCode::ErrAccessDenied);
        }

        if !remote_va.is_multiple_of(8) {
            return Err(ErrorCode::ErrAlignment);
        }

        let start = remote_va as usize;
        let end = start.checked_add(8).ok_or(ErrorCode::ErrBounds)?;
        if end > entry.data.len() {
            return Err(ErrorCode::ErrBounds);
        }

        let original = u64::from_be_bytes(entry.data[start..end].try_into().unwrap());

        let new_value = match atomic_type {
            0x01 => {
                // CAS: if original == operand1, write operand2
                if original == operand1 {
                    operand2
                } else {
                    original
                }
            }
            0x02 => {
                // FAA: write original + operand1
                original.wrapping_add(operand1)
            }
            _ => return Err(ErrorCode::ErrUnknownOpcode),
        };

        entry.data[start..end].copy_from_slice(&new_value.to_be_bytes());
        Ok(original)
    }

    fn generate_rkey(&mut self) -> Result<RKey, ErrorCode> {
        for _ in 0..1000 {
            let mut buf = [0u8; 4];
            OsRng.fill_bytes(&mut buf);
            let val = u32::from_be_bytes(buf);
            if val != 0 && !self.used_rkeys.contains(&val) {
                self.used_rkeys.insert(val);
                return Ok(RKey(val));
            }
        }
        Err(ErrorCode::ErrInternal)
    }
}
