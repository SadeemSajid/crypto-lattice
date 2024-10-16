/*

Check Strings:

1. I love lattices
2. This is a secret message for you
3. This is a secret message for you heheheheheheheheheheheh

*/

mod regev;
use ascii_converter::*;
use ndarray::{Array1, Array2};
use std::time::{Duration, Instant};

pub fn string_to_bits(text: String) -> Array1<i64> {
    let base_vector: Vec<u64> = string_to_binary(&text)
        .unwrap()
        .into_iter()
        .map(|x| x as u64)
        .collect();
    let mut bit_stream: Vec<u64> = vec![];

    for byte in base_vector {
        let mut byte_string: String = byte.to_string();

        if byte_string.len() == 7 {
            byte_string = String::from("0") + &byte_string;
        } else if byte_string.len() == 6 {
            byte_string = String::from("00") + &byte_string;
        }

        for bit in byte_string.chars() {
            bit_stream.push(bit.to_digit(2).unwrap() as u64);
        }
    }

    return Array1::from(
        bit_stream
            .into_iter()
            .map(|x: u64| x as i64)
            .collect::<Vec<i64>>(),
    );
}

fn bits_to_string(bits: Array1<i64>) -> String {
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
    let preamble: Array2<i64>;
    let scalars: Array1<i64>;

    let pub_key: regev::PublicKey;
    let priv_key: regev::PrivateKey;

    let plain_text = String::from("This is a secret message for you heheheheheheheheheheheh");

    println!("Plain Text: {:?}", plain_text);

    let params: regev::SecurityParameters = regev::setup();

    // Measure times from here

    let plain_text_bits = string_to_bits(plain_text);

    let mut start: Instant = Instant::now();
    let mut duration: Duration;

    (pub_key, priv_key) = regev::key_gen(&params);

    duration = start.elapsed();
    println!("Time KeyGen: {:?}", duration);

    start = Instant::now();

    (preamble, scalars) = regev::encrypt(plain_text_bits, &pub_key, &params);

    duration = start.elapsed();
    println!("Time Enc: {:?}", duration);

    start = Instant::now();

    let result = regev::decrypt(preamble, scalars, &priv_key, &params);

    duration = start.elapsed();
    println!("Time Dec: {:?}", duration);

    println!("Decrypted Text: {:?}", bits_to_string(result));
}
