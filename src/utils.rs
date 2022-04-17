use crate::{Block, SkipjackKey, Word, SBOX};

/// Helper function that converts a skipjack Word (u16) into a tuple of bytes
///
/// # Arguments
///
/// * `word` - A u16 representing a skipjack word
///
pub(crate) fn word_to_bytes(word: Word) -> (u8, u8) {
    ((word >> 8) as u8, word as u8)
}

/// Helper function that converts a tuple of bytes into a skipjack Word (u16)
///
/// # Arguments
///
/// * `bytes` - A tuple of bytes
///
pub(crate) fn bytes_to_word(bytes: (u8, u8)) -> u16 {
    ((bytes.0 as u16) << 8) | bytes.1 as u16
}

/// Helper function representing the G permutation on a single word needed by SkipJack's encryption.
///
/// This is a key-dependent permutation represented as a four-round Feistel structure.
/// The round function operates on a fixed byte-substitution table called the F-table.
/// Each round of G incorporates a byte of the key
///
/// # Arguments
///
/// * `key` - 80-bit encryption key
/// * `word` - 16-bit current word
/// * `step` - Current step of the encryption process
///
pub(crate) fn g_permutation(key: &SkipjackKey, word: Word, step: u16) -> Word {
    let (g1, g2): (u8, u8) = word_to_bytes(word);

    // Round 1: Use the XOR between g2 and a key byte as index into F, XOR the result with g1
    let g3: u8 = SBOX[(g2 ^ key[((4 * step) % 10) as usize]) as usize] ^ g1;
    // Round 2: Use the XOR between g3 and a key byte as index into F, XOR the result with g2
    let g4: u8 = SBOX[(g3 ^ key[(((4 * step) + 1) % 10) as usize]) as usize] ^ g2;
    // Round 3: Use the XOR between g4 and a key byte as index into F, XOR the result with g3
    let g5: u8 = SBOX[(g4 ^ key[(((4 * step) + 2) % 10) as usize]) as usize] ^ g3;
    // Round 4: Use the XOR between g5 and a key byte as index into F, XOR the result with g4
    let g6: u8 = SBOX[(g5 ^ key[(((4 * step) + 3) % 10) as usize]) as usize] ^ g4;

    // Return the combination of the final two bytes as a Word, where g5 represents the bits of highest and g6 the bits of lowest order
    bytes_to_word((g5, g6))
}

/// Helper function representing the inverse G permutation on a single word needed by SkipJack's decryption.
///
/// Like the normal G this is a key-dependent permutation represented as a four-round Feistel structure,
/// that operates on the F-table and incorporates a byte of the key each round
///
/// # Arguments
///
/// * `key` - 80-bit encryption key
/// * `word` - 16-bit current word
/// * `step` - Current step of the decryption process
///
pub(crate) fn inv_g_permutation(key: &SkipjackKey, word: Word, step: u16) -> Word {
    // In contrast to G we begin with g5 and g6 as start bytes and work our way down
    let (g5, g6): (u8, u8) = word_to_bytes(word);

    // Round 1: Use the XOR between g5 and a key byte as index into F, XOR the result with g6
    let g4: u8 = SBOX[(g5 ^ key[(((4 * step) + 3) % 10) as usize]) as usize] ^ g6;
    // Round 2: Use the XOR between g4 and a key byte as index into F, XOR the result with g5
    let g3: u8 = SBOX[(g4 ^ key[(((4 * step) + 2) % 10) as usize]) as usize] ^ g5;
    // Round 3: Use the XOR between g3 and a key byte as index into F, XOR the result with g4
    let g2: u8 = SBOX[(g3 ^ key[(((4 * step) + 1) % 10) as usize]) as usize] ^ g4;
    // Round 4: Use the XOR between g2 and a key byte as index into F, XOR the result with g3
    let g1: u8 = SBOX[(g2 ^ key[((4 * step) % 10) as usize]) as usize] ^ g3;

    // Return the combination of the final two bytes as a Word, where g1 represents the bits of the highest and g6 the bits of the lowest order
    bytes_to_word((g1, g2))
}

/// Stepping rule A of the SkipJack cipher encryption.
///
/// Takes a 64-bit Block and shuffles its words around according to the G permutation, the current round
/// and some predefined rules special to rule A.
///
/// # Arguments
///
/// * `key` - 80-bit encryption key
/// * `words` - Array of 16-bit words
/// * `counter` - Current encryption round
///
pub(crate) fn rule_a(key: &SkipjackKey, words: &mut Block, counter: &mut u16) {
    // Copy current block's contents, because we need the unaltered values
    let orig_words: Block = words.clone();

    // Word 1 becomes an application of the G permutation on itself XOR'ed with word 4 and the current counter
    words[0] = g_permutation(key, orig_words[0], *counter - 1) ^ orig_words[3] ^ *counter;
    // Word 2 becomes an application of the G permutation on Word 1
    words[1] = g_permutation(key, orig_words[0], *counter - 1);
    // Word 3 becomes a copy of the original word 2
    words[2] = orig_words[1];
    // Word 4 becomes a copy of the original word 3
    words[3] = orig_words[2];
}

/// Inverse stepping rule A of the SkipJack cipher decryption.
///
/// Takes a 64-bit Block and shuffles its words around according to the inverse G permutation, the current round
/// and some predefined rules special to inv A.
///
/// # Arguments
///
/// * `key` - 80-bit encryption key
/// * `words` - Array of 16-bit words
/// * `counter` - Current decryption round
///
pub(crate) fn inv_rule_a(key: &SkipjackKey, words: &mut Block, counter: &mut u16) {
    // Copy current block's contents, because we need the unaltered values
    let orig_words: Block = words.clone();

    // Word 1 becomes an application of the inverse G permutation on Word 2
    words[0] = inv_g_permutation(key, orig_words[1], *counter - 1);
    // Word 2 becomes a copy of the original word 3
    words[1] = orig_words[2];
    // Word 3 becomes a copy of the original word 4
    words[2] = orig_words[3];
    // Word 4 becomes the original word 1 XOR'ed with the original word 2 and the current counter
    words[3] = orig_words[0] ^ orig_words[1] ^ *counter;
}

/// Stepping rule B of the SkipJack cipher encryption.
///
/// Takes a 64-bit Block and shuffles its words around according to the G permutation, the current round
/// and some predefined rules special to rule B.
///
/// # Arguments
///
/// * `key` - 80-bit encryption key
/// * `words` - Array of 16-bit words
/// * `counter` - Current encryption round
///
pub(crate) fn rule_b(key: &SkipjackKey, words: &mut Block, counter: &mut u16) {
    // Copy current block's contents, because we need the unaltered values
    let orig_words: Block = words.clone();

    // Word 1 becomes a copy of the original word 4
    words[0] = orig_words[3];
    // Word 2 becomes an application of the G permutation on word 1
    words[1] = g_permutation(key, orig_words[0], *counter - 1);
    // Word 3 becomes the original word 1 XOR'ed with the original word 2 and the current counter
    words[2] = orig_words[0] ^ orig_words[1] ^ *counter;
    // Word 4 becomes a copy of the original word 3
    words[3] = orig_words[2];
}

/// Inverse stepping rule B of the SkipJack cipher decryption.
///
/// Takes a 64-bit Block and shuffles its words around according to the inverse G permutation, the current round
/// and some predefined rules special to inv B.
///
/// # Arguments
///
/// * `key` - 80-bit encryption key
/// * `words` - Array of 16-bit words
/// * `counter` - Current decryption round
///
pub(crate) fn inv_rule_b(key: &SkipjackKey, words: &mut Block, counter: &mut u16) {
    // Copy current block's contents, because we need the unaltered values
    let orig_words: Block = words.clone();

    // Word 1 becomes an application of the inverse G permutation on word 2
    words[0] = inv_g_permutation(key, orig_words[1], *counter - 1);
    // Word 2 becomes an application of the inverse G permutation on word 2 XOR'ed with the original word 3 and the current counter
    words[1] = inv_g_permutation(key, orig_words[1], *counter - 1) ^ orig_words[2] ^ *counter;
    // Word 3 becomes a copy of the original word 4
    words[2] = orig_words[3];
    // Word 4 becomes a copy of the original word 1
    words[3] = orig_words[0];
}
