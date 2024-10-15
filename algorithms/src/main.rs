mod regev;
use ndarray::{Array1, Array2};
use std::time::{Duration, Instant};

fn main() {
    let preamble: Array2<i64>;
    let scalars: Array1<i64>;

    let pub_key: regev::PublicKey;
    let priv_key: regev::PrivateKey;

    let plain_text = String::from("This is a secret message for you");

    println!("Plain Text: {:?}", plain_text);

    let params: regev::SecurityParameters = regev::setup();

    // Measure times from here

    let mut start: Instant = Instant::now();
    let mut duration: Duration;

    (pub_key, priv_key) = regev::key_gen(&params);

    duration = start.elapsed();
    println!("Time KeyGen: {:?}", duration);

    start = Instant::now();

    (preamble, scalars) = regev::encrypt(plain_text, &pub_key, &params);

    duration = start.elapsed();
    println!("Time Enc: {:?}", duration);

    start = Instant::now();

    let result = regev::decrypt(preamble, scalars, &priv_key, &params);

    duration = start.elapsed();
    println!("Time Dec: {:?}", duration);

    println!("Decrypted Text: {:?}", result);
}
