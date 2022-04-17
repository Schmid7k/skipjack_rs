# SKIPJACK
Pure Rust implementation of the [SKIPJACK](https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/skipjack/skipjack.pdf) cipher.

# SECURITY WARNING
SKIPJACK is a broken and outdated cipher.
This implementation should be used for educational purposes ONLY.
It should NEVER be used in a production environment and the author WILL NOT take on responsibility for damage caused by irresponsible usage of this library!

USE AT YOUR OWN RISK!

# Implementation
This crate implements the low-level cipher functions of the SkipJack cipher.
It supports a better optimized encryption/decryption of 64-bit blocks than the approach specified by the original SkipJack specification. 

There are benchmarks available in `/benches/`.

# Examples
```rust
use skipjack_rs::*;
let skipjack: Skipjack =
    Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
let mut buf = [0x3322, 0x1100, 0xddcc, 0xbbaa].into();
skipjack.encrypt(&mut buf);
assert_eq!(buf, [0x2587, 0xcae2, 0x7a12, 0xd300].into());
let skipjack: Skipjack =
    Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
let mut buf = [0x2587, 0xcae2, 0x7a12, 0xd300].into();
skipjack.decrypt(&mut buf);
assert_eq!(buf, [0x3322, 0x1100, 0xddcc, 0xbbaa].into());
```
