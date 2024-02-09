const SEED: u32 = 1;
const M: u32 = 0x5bd1_e995;

pub fn murmurhash2(key: &[u8]) -> u32 {
    Murmur2Digest::digest(key)
}

pub struct Murmur2Digest {
    hash: u32,
    remainder: [u8; 3],
    remainder_length: usize,
}

impl Murmur2Digest {
    pub fn digest(data: &[u8]) -> u32 {
        let mut digest = Self::new(data.len() as u32);
        digest.update(data);
        digest.finalize()
    }

    pub fn new(length: u32) -> Self {
        Self {
            hash: SEED ^ length,
            remainder: [0; 3],
            remainder_length: 0,
        }
    }

    #[inline]
    pub fn update(&mut self, mut data: &[u8]) {
        let combined_len = data.len() + self.remainder_length as usize;

        if combined_len >= 4 {
            let mut chunk = [0u8; 4];
            let rl = self.remainder_length as usize;
            chunk[..rl].copy_from_slice(&self.remainder[..rl]);
            chunk[rl..].copy_from_slice(&data[..4 - rl]);
            data = &data[4 - rl..];
            self.update_chunk(chunk);
        }

        while data.len() >= 4 {
            let chunk = std::array::from_fn(|i| data[i]);
            self.update_chunk(chunk);
            data = &data[4..];
        }

        let remlen = combined_len % 4;

        self.remainder[..remlen].copy_from_slice(data);
        self.remainder_length = remlen;
    }

    #[inline]
    fn update_chunk(&mut self, chunk: [u8; 4]) {
        let mut k = u32::from_le_bytes(chunk);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        self.hash = self.hash.wrapping_mul(M);
        self.hash ^= k;
    }

    pub fn finalize(mut self) -> u32 {
        match self.remainder_length {
            3 => {
                self.hash ^= u32::from(self.remainder[2]) << 16;
                self.hash ^= u32::from(self.remainder[1]) << 8;
                self.hash ^= u32::from(self.remainder[0]);
                self.hash = self.hash.wrapping_mul(M);
            }
            2 => {
                self.hash ^= u32::from(self.remainder[1]) << 8;
                self.hash ^= u32::from(self.remainder[0]);
                self.hash = self.hash.wrapping_mul(M);
            }
            1 => {
                self.hash ^= u32::from(self.remainder[0]);
                self.hash = self.hash.wrapping_mul(M);
            }
            _ => {}
        }

        self.hash ^= self.hash >> 13;
        self.hash = self.hash.wrapping_mul(M);
        self.hash ^ (self.hash >> 15)
    }
}

#[cfg(test)]
mod test {

    use super::murmurhash2;
    use std::collections::HashSet;

    #[test]
    fn test_murmur2() {
        let s1 = "abcdef";
        let s2 = "abcdeg";
        for i in 0..5 {
            assert_eq!(
                murmurhash2(&s1[i..5].as_bytes()),
                murmurhash2(&s2[i..5].as_bytes())
            );
        }
    }

    #[test]
    fn test_murmur_against_reference_impl() {
        assert_eq!(murmurhash2("".as_bytes()), 3_632_506_080);
        assert_eq!(murmurhash2("a".as_bytes()), 455_683_869);
        assert_eq!(murmurhash2("ab".as_bytes()), 2_448_092_234);
        assert_eq!(murmurhash2("abc".as_bytes()), 2_066_295_634);
        assert_eq!(murmurhash2("abcd".as_bytes()), 2_588_571_162);
        assert_eq!(murmurhash2("abcde".as_bytes()), 29_886_969_42);
        assert_eq!(murmurhash2("abcdefghijklmnop".as_bytes()), 2_350_868_870);
    }

    #[test]
    fn test_murmur_collisions() {
        let mut set: HashSet<u32> = HashSet::default();
        for i in 0..10_000 {
            let s = format!("hash{}", i);
            let hash = murmurhash2(s.as_bytes());
            set.insert(hash);
        }
        assert_eq!(set.len(), 10_000);
    }
}
