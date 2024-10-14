mod regev;
use ndarray::{Array1, Array2};

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

    println!("Decrypted Text: {:?}", result);
}
