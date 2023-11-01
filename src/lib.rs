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

pub fn score(fingerprint: &str) -> Match<u32> {
    let fpr = fingerprint.as_bytes();
    let len = fpr.len();
    let a = &fpr[len-8..len-6];
    let b = &fpr[len-6..len-4];
    let c = &fpr[len-4..len-2];
    let d = &fpr[len-2..len-0];

    let matcher: Box<dyn Fn(&[u8; 2]) -> bool>;
    let mut score= 0;
    if a[0] == b[0] && b[0] == c[0] && c[0] == d[0] {
        matcher = Box::new(|arg| arg[0] == a[0]);
    } else if a[1] == b[1] && b[1] == c[1] && c[1] == d[1] {
        matcher = Box::new(|arg| arg[1] == a[1]);
    } else {
        return Match::No;
    }

    for x in fpr[0..len-8].chunks_exact(2) {
        if matcher(x.try_into().unwrap()) {
            score += 1;
        }
    }

    if a == b && b == c && c == d {
        score += 256;
        for x in fpr[0..len-8].chunks_exact(2) {
            if x == a { score += 2; }
        }
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
