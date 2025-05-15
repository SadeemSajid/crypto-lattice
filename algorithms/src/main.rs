/* Test Inputs: 128, 256, 512 */
// Comment this to allow warnings
#![allow(warnings)]
mod coppersmith;
// mod lizard;
mod lizard;
mod module;
mod multiparty;
mod regev;
mod ringlwe;

use nalgebra::{DMatrix, DVector};
use ndarray::{Array1, Array2};
use rand::Rng;
use rug::Integer;
use rustfft::Length;
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

fn lizard() {
    println!("\n======== LIZARD ========");

    let mut start: Instant = Instant::now();
    let mut duration: Duration;

    let sk = lizard::gen_sk();
    let pk = lizard::gen_pk(&sk);

    duration = start.elapsed();
    println!("Time KeyGen: {:?}", duration);

    // println!("SECRET KEY: {:?}", sk);
    // println!("PUBLIC KEY: A {:?} || B: {:?}", pk.a, pk.b);

    let plaintext = [1u16; 256];

    // println!("PLAINTEXT: {:?}", plaintext);

    start = Instant::now();

    let ctx = lizard::encrypt(&pk, &plaintext);

    duration = start.elapsed();
    println!("Time Enc: {:?}", duration);

    // println!("CIPHERTEXT: Preamble {:?} || Scalars {:?}", ctx.a, ctx.b);

    start = Instant::now();

    let decrypted = lizard::decrypt(&sk, &ctx);

    duration = start.elapsed();
    println!("Time Dec: {:?}", duration);

    // println!("DECRYPTED: {:?}", decrypted);
}

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

fn modulwe(size: usize) {
    let k: usize = size;
    let q: i64 = 12289;

    let start = Instant::now();
    let (a, s0, _, p0) = module::keygen(k, q);
    let keygen_time = start.elapsed();

    let m = DVector::from_element(k, 1);

    let start = Instant::now();
    let (p1, c) = module::encrypt(&a, &p0, &m, q);
    let enc_time = start.elapsed();

    let start = Instant::now();
    let _ = module::decrypt(&p1, &c, &s0, q);
    let dec_time = start.elapsed();

    println!("\n======== MODULE-LWE ========");
    println!("Parameter size: {}", k);
    println!("Time KeyGen: {:.6}s", keygen_time.as_secs_f64());
    println!("Time Enc: {:.6}ms", enc_time.as_secs_f64() * 1000.0);
    println!("Time Dec: {:.6}ms", dec_time.as_secs_f64() * 1000.0);
}

fn main() {
    // Enable the one you want to test
    for lengths in 1..=4 {
        println!("======================");
        println!("--- REGEV ({}) ---", 128 * lengths);
        println!("======================");
        regev(128 * lengths);
    }

    // Test Module LWE
    modulwe(128);
    modulwe(256);
    modulwe(512);

    lizard();
    println!("\n======================\n");
    println!("--- Ring-LWE (512) ---");
    println!("======================");
    ringlwe(512);

    println!("\n======================");
    println!("--- Interactive Multi-Party KEP ---");
    println!("======================");

    let num_users = 4;
    multiparty::benchmark_key_exchange(num_users);

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
    //         println!("N, E: {}, {}", n, e);
    //         println!("Ciphertext: {}", c);
    //     }
    //     None => {
    //         println!("No plaintext found. Ensure conditions are met (e.g., m^e < N).");
    //     }
    // }
}
