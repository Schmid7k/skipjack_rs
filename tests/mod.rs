#[cfg(test)]
mod tests {
    use skipjack_rs::*;

    #[test]
    fn test_encryption() {
        let skipjack: Skipjack =
            Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
        let mut buf = [0x3322, 0x1100, 0xddcc, 0xbbaa].into();
        skipjack.encrypt(&mut buf);

        assert_eq!(buf, [0x2587, 0xcae2, 0x7a12, 0xd300].into());
    }

    #[test]
    fn test_decryption() {
        let skipjack: Skipjack =
            Skipjack::new([0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11].into());
        let mut buf = [0x2587, 0xcae2, 0x7a12, 0xd300].into();
        skipjack.decrypt(&mut buf);

        assert_eq!(buf, [0x3322, 0x1100, 0xddcc, 0xbbaa].into());
    }
}
