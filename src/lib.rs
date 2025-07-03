//! # VanityGPG
//!
//! It works.
//!
//! ```rust
//! use vanity_gpg::{Backend, DefaultBackend, CipherSuite};
//!
//! let backend = DefaultBackend::new(CipherSuite::Curve25519).unwrap();
//! println!("Fingerprint: {}", backend.fingerprint());
//! ```

extern crate anyhow;
extern crate byteorder;
#[cfg(feature = "rpgp")]
extern crate chrono;
#[cfg(feature = "rpgp")]
extern crate pgp;
#[cfg(feature = "rpgp")]
extern crate rand;
#[cfg(feature = "sequoia")]
extern crate sequoia_openpgp;
#[cfg(feature = "rpgp")]
extern crate sha1;
#[cfg(feature = "rpgp")]
extern crate smallvec;
extern crate thiserror;

pub mod pgp_backends;
#[cfg(feature = "rpgp")]
pub use pgp_backends::RPGPBackend;
#[cfg(feature = "sequoia")]
pub use pgp_backends::SequoiaBackend;
pub use pgp_backends::{ArmoredKey, Backend, CipherSuite, DefaultBackend, UserID};

#[derive(Copy, Clone)]
pub enum Match<T> {
    Yes(T),
    No,
}
trait BitOps where Self: Sized {
    fn contains(&self, flags: Self) -> bool;

    fn if_contains<Res>(&self, flags: Self, f: impl FnOnce() -> Res, default: Res) -> Res {
        if self.contains(flags) { f() } else { default }
    }

    fn contains_or(&self, flags: Self, f: impl FnOnce() -> bool) -> bool {
        self.contains(flags) || f()
    }

    fn contains_and(&self, flags: Self, f: impl FnOnce() -> bool) -> bool {
        self.contains(flags) && f()
    }
}

/*
impl BitOps for u16 {
    fn contains(&self, flags: Self) -> bool {
        (*self & flags) == flags
    }

    fn run_if<T>(&self, flags: Self, f: impl FnOnce() -> T, default: T) -> T {
        if self.contains(flags) { f() } else { default }
    }
}
*/

impl<T> BitOps for T where T: Copy + Eq + std::ops::BitAnd<Output=T>
{
    fn contains(&self, flags: Self) -> bool {
        (*self & flags) == flags
    }
}

const MAGIC: &[&[u8]] = &[
    b"DEAD",
    b"CAFE",
    b"BABE",
    b"D00D",
    b"F00D",
    b"FADE",
    b"FEE1",
    b"C0DE",
    b"FACE",
    b"FEED",
];

const MAGIC2: &[&[u8]] = &[
     b"DEFACED",
     b"DEBASED",
    b"DECEA5ED",
    b"D15EA5ED",
    b"DEAD1OCC",
];

pub fn score(fingerprint: &str) -> Match<u32> {
    let fpr = fingerprint.as_bytes();
    let len = fpr.len();
    let a = &fpr[len-8..len-6];
    let b = &fpr[len-6..len-4];
    let c = &fpr[len-4..len-2];
    let d = &fpr[len-2..len-0];

    let fpr2 = &fpr[0..len-8];
    let len2 = fpr2.len();
    let xa = &fpr2[len2-8..len2-6];
    let xb = &fpr2[len2-6..len2-4];
    let xc = &fpr2[len2-4..len2-2];
    let xd = &fpr2[len2-2..len2-0];

    if let Match::Yes(m1) = score_magic(fpr) {
        let mut score = m1;

        if let Match::Yes(m2) = score_magic(fpr2) {
            score += 1024 * m2;
        }
        else if (xa[0] == a[0] && xb[0] == a[0] && xc[0] == a[0] && xd[0] == a[0])
             || (xa[1] == a[1] && xb[1] == a[1] && xc[1] == a[1] && xd[1] == a[1]) {
            if let Match::Yes(m2) = score_pattern(fpr2) {
                score += 1024 * m2;
            }
            else {
                score += 1024;
            }
        }
        else if (xa == a || xb == b || xc == c || xd == d)
             || (           xb == a || xc == a || xd == a) {
            if let Match::Yes(m2) = score_pattern(fpr2) {
                score += 1024 * m2;
            }
        }
        return Match::Yes(score);

    } else if let Match::Yes(m1) = score_pattern(fpr) {
        let mut score = m1;

        if (a[0] == xd[0] && b[0] == xd[0] && c[0] == xd[0] && d[0] == xd[0])
        || (a[1] == xd[1] && b[1] == xd[1] && c[1] == xd[1] && d[1] == xd[1]) {
            if let Match::Yes(m2) = score_magic(fpr2) {
                score += 1024 * m2;
            }
            else {
                score += 1024;
            }
        }
        else if (xa == a || xb == b || xc == c || xd == d)
             || (xa == d || xb == d || xc == d           ) {
            if let Match::Yes(m2) = score_magic(fpr2) {
                score += 1024 * m2;
            }
        }
        return Match::Yes(score);
    }

    Match::No
}

fn score_magic(fpr: &[u8]) -> Match<u32> {
    let mut score= 0;

    let len = fpr.len();
    // let a = &fpr[len-8..len-6];
    // let b = &fpr[len-6..len-4];
    // let c = &fpr[len-4..len-2];
    // let d = &fpr[len-2..len-0];

    // let xab = &fpr[len-16..len-12];
    // let xcd = &fpr[len-12..len-8];
    let ab = &fpr[len-8..len-4];
    let cd = &fpr[len-4..len-0];
    let abcd = &fpr[len-8..len-0];

    for &magic in MAGIC2 {
        if abcd.ends_with(magic) {
            return Match::Yes(512);
        }
    }

    let is_magic =
        // (MAGIC.contains(&xab) as u32) << 3 |
        // (MAGIC.contains(&xcd) as u32) << 2 |
        (MAGIC.contains(&ab) as u32) << 1 |
        (MAGIC.contains(&cd) as u32) << 0;
    let has_magic = |arg| is_magic.contains(arg);
    // if has_magic(0b1100) && xab == xcd { return Match::No; }
    // if has_magic(0b0110) && xcd == ab { return Match::No; }
    if has_magic(0b0011) && ab == cd { return Match::No; }
    match is_magic {
        // 0b1111 => return Match::Yes(1024),
        // 0b0111 => return Match::Yes(768),
        0b0011 => return Match::Yes(512),
        0b0000 => (),
        _      => return Match::No,
    }

    Match::No
}

fn score_pattern(fpr: &[u8]) -> Match<u32> {
    let mut score= 0;

    let len = fpr.len();

    let a = &fpr[len-8..len-6];
    let b = &fpr[len-6..len-4];
    let c = &fpr[len-4..len-2];
    let d = &fpr[len-2..len-0];

    fn apply<F>(fpr: &[u8], len: usize, mut op: F)
    where
        F: FnMut(&[u8; 2]),
    {
        for x in fpr[0..len - 8].chunks_exact(2) {
            op(x.try_into().unwrap());
        }
    }

    fn apply_p<F>(fpr: &[u8], len: usize, score: &mut u32, matcher: F, adj: u32)
    where
        F: Fn(&[u8; 2]) -> bool,
    {
        apply(fpr, len, |x| if matcher(x.try_into().unwrap()) { *score += adj; });
    }

    if a[0] == b[0] && b[0] == c[0] && c[0] == d[0] {
        apply_p(&fpr, len, &mut score, |arg| arg[0] == a[0], 1);
    } else if a[1] == b[1] && b[1] == c[1] && c[1] == d[1] {
        apply_p(&fpr, len, &mut score, |arg| arg[1] == a[1], 1);
    } else {
        return Match::No;
    }

    if a == b && b == c && c == d {
        score += 256;
        apply_p(&fpr, len, &mut score, |arg| arg == a, 2);
    } else if a == b && c == d || a == c && b == d {
        assert_ne!(a, d);
        score += 128;
        let mut scores = [score; 2];
        for x in fpr[0..len-8].chunks_exact(2) {
                 if x == a { scores[0] += 2; }
            else if x == d { scores[1] += 2; }
        }
        score = scores.into_iter().max().unwrap();
    } else if a == b || c == d || a == c || b == d {
        score += 64;
        let mut scores = [score; 4];
        for x in fpr[0..len-8].chunks_exact(2) {
                 if x == a { scores[0] += 2; }
            else if x == b { scores[1] += 2; }
            else if x == c { scores[2] += 2; }
            else if x == d { scores[3] += 2; }
        }
        score = scores.into_iter().max().unwrap();
    } else {
        return Match::No;
    }

    Match::Yes(score)
}

#[cfg(test)]
mod meaningless_test {
    #[test]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
