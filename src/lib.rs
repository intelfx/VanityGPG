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
    Match::Yes(0)
}

#[cfg(test)]
mod meaningless_test {
    #[test]
    fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
