use ndarray::{Array1, Array2};
use rand::Rng;
use rand_distr::{Distribution, Normal};

// These are the recommended parameters
const N: i64 = 536;
const M: i64 = 1024;
const L: i64 = 256;
const LOG_Q: i64 = 11;
const LOG_P: i64 = 9;
const T: i64 = 2;
const LOG_T: i64 = 1;
const SIGMA: f64 = 1.0; // TODO: Change this later

// TODO: Add distributions according to the paper?
pub struct SecurityParameters {
    pub m: i64,
    pub n: i64,
    pub q: i64,
    pub p: i64,
    pub t: i64,
    pub l: i64,
    pub std_dev: f64,
}

// TODO
pub struct PublicKey {
    pub A: Array2<i64>,
    pub B: Array2<i64>,
}
pub struct PrivateKey {}

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// PRIVATE FUNCTIONS ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

fn gen_array_2d(rows: i64, cols: i64, modulo: i64) -> Array2<i64> {
    let mut matrix = Array2::<i64>::zeros((rows as usize, cols as usize));

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

fn gen_array_1d(size: i64, modulo: i64) -> Array1<i64> {
    let mut matrix = Array1::<i64>::zeros(size as usize);

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

pub fn setup() -> SecurityParameters {
    return SecurityParameters {
        m: M,
        n: N,
        q: Q,
        p: P,
        t: T,
        l: L,
        std_dev: SIGMA,
    };
}

pub fn key_gen(params: SecurityParameters) -> (PublicKey, PrivateKey) {
    let a = gen_array_2d(params.m, params.n, params.q);
}
