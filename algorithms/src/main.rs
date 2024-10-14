mod regev;
use ndarray::{Array1, Array2};

fn main() {
    let preamble: Array2<i32>;
    let scalars: Array1<i32>;

    let pub_key: regev::PublicKey;
    let priv_key: regev::PrivateKey;

    let params: regev::SecurityParameters = regev::setup();

    (pub_key, priv_key) = regev::key_gen(&params);

    (preamble, scalars) = regev::encrypt(String::from("I love lattices"), &pub_key, &params);

    let result = regev::decrypt(preamble, scalars, &priv_key, &params);
}
