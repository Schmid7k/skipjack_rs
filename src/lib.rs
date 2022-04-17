//! Pure Rust implementation of the [SKIPJACK](https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/skipjack/skipjack.pdf) cipher.
//!
//! # <span style="color:red">Security Warning</span>
//! SKIPJACK is a broken and outdated cipher.
//! This implementation should be used for educational purposes ONLY.
//! It should NEVER be used in a production environment and the author WILL NOT take on responsibility for damage caused by irresponsible usage of this library!
//!
//! USE AT YOUR OWN RISK!
//! # Implementation
//!
//! This crate implements the low-level cipher functions of the SkipJack cipher.
//! It supports a better optimized encryption/decryption of 64-bit blocks than the approach specified by the original SkipJack specification.
//!
//! # Examples
//!
//! ```
//! use skipjack_rs::*;
//!
//! let skipjack: Skipjack =
//!     Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
//! let mut buf = [0x3322, 0x1100, 0xddcc, 0xbbaa].into();
//! skipjack.encrypt(&mut buf);
//!
//! assert_eq!(buf, [0x2587, 0xcae2, 0x7a12, 0xd300].into());
//!
//! let skipjack: Skipjack =
//!     Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
//! let mut buf = [0x2587, 0xcae2, 0x7a12, 0xd300].into();
//! skipjack.decrypt(&mut buf);
//!
//! assert_eq!(buf, [0x3322, 0x1100, 0xddcc, 0xbbaa].into());
//! ```
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub(crate) mod utils;

use cipher::consts::{U10, U4};
use generic_array::GenericArray;

use crate::utils::*;

/// Type representing a SkipJack word
pub type Word = u16;
/// Type representing a SkipJack block
pub type Block = GenericArray<u16, U4>;
/// Type representing a SkipJack key
pub type SkipjackKey = GenericArray<u8, U10>;

/// SkipJack SBOX
pub(crate) static SBOX: [u8; 256] = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
];

/// Struct representing a Skipjack cipher instance.
pub struct Skipjack {
    key: SkipjackKey,
}

impl Skipjack {
    /// Constructs a new SkipJack instance
    ///
    /// # Arguments
    ///
    /// * `key` - 80-bit SkipJackKey (Array of 10 bytes)
    pub fn new(key: SkipjackKey) -> Skipjack {
        Skipjack { key: key }
    }

    /// SkipJack encryption function
    ///
    /// SkipJack encrypts 64-bit data blocks in-place by alternating between the two stepping rules A and B.
    ///
    /// The encryption requires a total of 32 steps. It begins with step 0 (counter at 1) and steps according to Rule A for 8 steps,
    /// then switches to Rule B for the next 8 steps.
    ///
    /// This procedure is repeated once, after which the ciphertext is returned.
    ///
    /// # Arguments
    ///
    /// * `block` - 16-bit plaintext array of length 4
    ///
    /// # Examples
    ///
    /// ```
    /// use skipjack_rs::*;
    ///
    /// let skipjack = Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
    ///
    /// let mut buf = [0x3322, 0x1100, 0xddcc, 0xbbaa].into();
    /// skipjack.encrypt(&mut buf);
    ///
    /// assert_eq!(buf, [0x2587, 0xcae2, 0x7a12, 0xd300].into());
    /// ```
    ///
    pub fn encrypt(&self, block: &mut Block) {
        // Instead of manually calling each stepping function one can bundle all calls and call them depending on the current counter
        for mut counter in 1..33 {
            match counter {
                // Execute rule A for the first 8 steps
                i if i <= 8 => rule_a(&self.key, block, &mut counter),
                // Then rule B for the next 8 steps
                i if i <= 16 => rule_b(&self.key, block, &mut counter),
                // Now rule A again for the next 8 steps
                i if i <= 24 => rule_a(&self.key, block, &mut counter),
                // At last rule a again for the last 8 steps
                _ => rule_b(&self.key, block, &mut counter),
            }
        }
    }

    /// SkipJack decryption function
    ///
    /// SkipJack decrypts 64-bit data block in-place by alternating between the two stepping rules A and B in reverse order.
    ///
    /// The decryption, just like the encryption, requires a total of 32 steps. It begins with step 32 (counter at 32) and counts down to 0.
    /// It steps according to Rule B for 8 steps, then switches to Rule A for 8 steps.
    ///
    /// This procedure is repeated once, after which the plaintext is returned.
    ///
    /// # Arguments
    ///
    /// * `block` - 16-bit ciphertext array of length 4
    ///
    /// # Examples
    ///
    /// ```
    /// use skipjack_rs::*;
    ///
    /// let skipjack: Skipjack =
    ///        Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
    ///    
    /// let mut buf = [0x2587, 0xcae2, 0x7a12, 0xd300].into();
    /// skipjack.decrypt(&mut buf);
    ///
    /// assert_eq!(buf, [0x3322, 0x1100, 0xddcc, 0xbbaa].into());
    /// ```
    ///
    pub fn decrypt(&self, block: &mut Block) {
        for mut counter in (1..33).rev() {
            match counter {
                i if i <= 8 => inv_rule_a(&self.key, block, &mut counter),
                i if i <= 16 => inv_rule_b(&self.key, block, &mut counter),
                i if i <= 24 => inv_rule_a(&self.key, block, &mut counter),
                _ => inv_rule_b(&self.key, block, &mut counter),
            }
        }
    }
}
