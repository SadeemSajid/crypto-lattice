/* Test Inputs: 128, 256, 512, 1024 */
// Comment this to allow warnings
#![allow(warnings)]
mod coppersmith;
// mod lizard;
mod lizard;
mod regev;
mod ringlwe;

use ndarray::{Array1, Array2};
use rand::Rng;
use rug::Integer;
use std::time::{Duration, Instant};

// Used to generate random bit stream for testing
fn __gen_random_array1__(size: i64, modulo: i64) -> Array1<i64> {
    let mut matrix = Array1::<i64>::zeros(size as usize);

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

fn regev(message_length: i64) {
    let preamble: Array2<i64>;
    let scalars: Array1<i64>;

    let pub_key: regev::PublicKey;
    let priv_key: regev::PrivateKey;

    let params: regev::SecurityParameters = regev::setup();

    println!("Message Length: {}", message_length);

    // Measure times from here

    let plain_text_bits = __gen_random_array1__(message_length, 2);

    let mut start: Instant = Instant::now();
    let mut duration: Duration;

    (pub_key, priv_key) = regev::key_gen(&params);

    duration = start.elapsed();
    println!("Time KeyGen: {:?}", duration);

    start = Instant::now();

    (preamble, scalars) = regev::encrypt(&plain_text_bits, &pub_key, &params);

    duration = start.elapsed();
    println!("Time Enc: {:?}", duration);

    // println!("Encryption: {:?} \n {:?}", preamble, scalars);

    start = Instant::now();

    let result = regev::decrypt(preamble, scalars, &priv_key, &params);

    duration = start.elapsed();
    println!("Time Dec: {:?}", duration);

    println!("Result: {}", plain_text_bits == result);
}

// FIXME: Incomplete
// fn lizard(message_length: i64) {
//     let pub_key: lizard::PublicKey;
//     let priv_key: lizard::PrivateKey;

//     let plain_text = __gen_random_array1__(message_length, 2);

//     let mut start: Instant = Instant::now();
//     let mut duration: Duration;

//     start = Instant::now();

//     let params: lizard::SecurityParameters = lizard::setup();

//     duration = start.elapsed();
//     println!("Time KeyGen: {:?}", duration);

//     (pub_key, priv_key) = lizard::key_gen(&params);

//     // let cipher = lizard::encrypt(&plain_text, &pub_key, &params);

//     // println!("{:?}", cipher);
// }

fn ringlwe(message_length: i64) {
    let pub_key: ringlwe::PublicKey;
    let priv_key: ringlwe::PrivateKey;

    let preamble: Vec<i64>;
    let scalars: Vec<i64>;

    let raw = __gen_random_array1__(message_length, 2);
    let plain_text: Vec<i64> = raw.to_vec();

    let mut start: Instant = Instant::now();
    let mut duration: Duration;

    let params: ringlwe::SecurityParameters = ringlwe::setup();

    duration = start.elapsed();
    println!("Time Setup: {:?}", duration);

    start = Instant::now();

    (pub_key, priv_key) = ringlwe::key_gen(&params);

    duration = start.elapsed();
    println!("Time KeyGen: {:?}", duration);

    start = Instant::now();

    (preamble, scalars) = ringlwe::encrypt(&plain_text, &params, &pub_key);

    duration = start.elapsed();
    println!("Time Enc: {:?}", duration);

    start = Instant::now();

    let result = ringlwe::decrypt(&preamble, &scalars, &params, &priv_key);

    duration = start.elapsed();
    println!("Time Dec: {:?}", duration);

    println!("Success: {}", result == plain_text);
}

fn main() {
    // Enable the one you want to test
    // for lengths in 1..=4 {
    //     println!("--------------");
    //     println!("Run: {}", lengths);
    //     println!("--- Regevs ---");
    //     regev(128 * lengths);
    //     // lizard(128 * lengths);
    // }
    // println!("======================");
    // println!("--- Ring-LWE (512) ---");
    // println!("======================");
    // ringlwe(512);

    // // Coppersmith Testing
    // let n = Integer::from(77); // Public modulus
    // let e = 3; // Public exponent
    // let c = Integer::from(64); // Ciphertext
    // println!("=======================");
    // println!("--- Coppersmith RSA ---");
    // println!("=======================");
    // match coppersmith::low_public_exponent_attack(&n, e, &c) {
    //     Some(plaintext) => {
    //         println!("Recovered plaintext: {}", plaintext);
    //     }
    //     None => {
    //         println!("No plaintext found. Ensure conditions are met (e.g., m^e < N).");
    //     }
    // }

    let sk = lizard::gen_sk();
    let pk = lizard::gen_pk(&sk);

    let plaintext = [1u16; 256];
    let ctx = lizard::encrypt(&pk, &plaintext);
    let decrypted = lizard::decrypt(&sk, &ctx);

    println!("Decrypted: {:?}", decrypted);
}
