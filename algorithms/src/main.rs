mod regev;
use std::fmt::format;

use ascii_converter::*;
use ndarray::Array2;

fn main() {
    // let params: regev::SecurityParameters = regev::setup();

    // let pub_key: regev::PublicKey;
    // let priv_key: regev::PrivateKey;

    // (pub_key, priv_key) = regev::key_gen(params);

    let og_vector: Vec<u32> = string_to_binary("I love lattices").unwrap();

    let mut bit_stream: Vec<u32> = vec![];

    for byte in og_vector {
        let mut byte_string: String = byte.to_string();

        if byte_string.len() == 7 {
            byte_string = String::from("0") + &byte_string;
        } else if byte_string.len() == 6 {
            byte_string = String::from("00") + &byte_string;
        }

        for bit in byte_string.chars() {
            bit_stream.push(bit.to_digit(2).unwrap() as u32);
        }
    }

    println!(
        "{:?}",
        Array2::from_shape_vec((1, bit_stream.len() as usize), bit_stream).unwrap()
    );
}
