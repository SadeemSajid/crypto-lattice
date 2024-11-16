/*

Test Inputs: 128, 256, 512, 1024

*/

mod lizard;
mod regev;
use ndarray::{Array1, Array2};
use rand::Rng;
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

fn lizard(message_length: i64) {
    let pub_key: lizard::PublicKey;
    let priv_key: lizard::PrivateKey;

    let plain_text = __gen_random_array1__(message_length, 2);

    println!("Message {:?}", plain_text);

    let params: lizard::SecurityParameters = lizard::setup();

    (pub_key, priv_key) = lizard::key_gen(&params);

    let cipher = lizard::encrypt(&plain_text, &pub_key, &params);

    println!("{:?}", cipher);
}

fn main() {
    // Enable the one you want to test
    // for lengths in 1..=4 {
    //     // regev(128 * lengths);
    //     lizard(128 * lengths);
    // }

    lizard(10);
}
