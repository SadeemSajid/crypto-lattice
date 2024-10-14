mod regev;
use ndarray::{Array1, Array2};

fn bits_to_string(bits: Array1<i32>) -> String {
    // Ensure the bit array length is divisible by 8.
    assert!(
        bits.len() % 8 == 0,
        "Bit array length must be divisible by 8."
    );

    // Convert the bits into bytes.
    let bytes: Vec<u8> = bits
        .exact_chunks(8) // Split into 8-bit chunks.
        .into_iter()
        .map(|chunk| {
            chunk.iter().enumerate().fold(0, |acc, (i, &bit)| {
                acc | ((bit as u8) << (7 - i)) // Convert chunk to a byte (big-endian).
            })
        })
        .collect();

    // Convert the bytes to a UTF-8 string.
    String::from_utf8(bytes).expect("Invalid UTF-8 sequence")
}

fn main() {
    let preamble: Array2<i32>;
    let scalars: Array1<i32>;

    let pub_key: regev::PublicKey;
    let priv_key: regev::PrivateKey;

    let plain_text = String::from("I love lattices");

    println!("Plain Text: {:?}", plain_text);

    let params: regev::SecurityParameters = regev::setup();

    (pub_key, priv_key) = regev::key_gen(&params);

    (preamble, scalars) = regev::encrypt(plain_text, &pub_key, &params);

    let result = regev::decrypt(preamble, scalars, &priv_key, &params);

    println!("Decrypted Text: {:?}", bits_to_string(result));
}
