use ndarray::{Array1, Array2};
use rand::Rng;
use rand_distr::{Distribution, Normal};

// These are the recommended parameters
const M: i64 = 724;
const N: i64 = 480;
const L: i64 = 256;
const LOG_Q: i64 = 11; // 100000000000
const Q: i64 = 11;
const LOG_P: i64 = 9; // 1000000000
const P: i64 = 9;
const T: i64 = 2;
const LOG_T: i64 = 1;
const SIGMA: f64 = 0.3; // TODO: Change this later

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
    pub matrix_A: Array2<i64>,
    pub matrix_B: Array2<i64>,
}
pub struct PrivateKey {
    pub matrix_S: Array2<i64>,
}

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

// FIXME: Have a look at Q and P
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

pub fn key_gen(params: &SecurityParameters) -> (PublicKey, PrivateKey) {
    // Random Matrix A
    let A = gen_array_2d(params.m, params.n, params.q);

    // Generate Secret Matrix S (n x l)
    // Sample Columns S_i from Z^n

    // FIXME: Sample columns independently
    let S = gen_array_2d(params.n, params.l, params.q);

    // Sample Error matrix

    // FIXME: add standard deviation instead of 2
    let E = gen_array_2d(params.m, params.l, 2);

    // Generate B
    let B = (A.dot(&S) + E).mapv(|x| x % params.q);

    return (
        PublicKey {
            matrix_A: A,
            matrix_B: B,
        },
        PrivateKey { matrix_S: S },
    );
}

pub fn encrypt(
    plaintext: &Array1<i64>,
    public_key: &PublicKey,
    params: &SecurityParameters,
) -> (Array1<i64>, Array1<i64>) {
    // Choose vector r
    let r: Array1<i64> = gen_array_1d(params.m, params.q);

    // Compute head & tail
    let head: Array1<i64> = public_key.matrix_A.t().dot(&r).mapv(|x: i64| x % params.q);
    let tail: Array1<i64> = public_key.matrix_B.t().dot(&r).mapv(|x: i64| x % params.q);

    // Compute cipher
    let head_c = head.mapv(|val: i64| {
        let scaled = (params.p as f64 / params.q as f64).floor() as i64 * val;
        scaled % params.p
    });

    let tail_c = tail.mapv(|val: i64| {
        let scaled = (params.p as f64 / params.q as f64).floor() as i64 * val;
        scaled % params.p
    }) + plaintext.mapv(|val| {
        let scaled = (params.p as f64 / params.t as f64).floor() as i64 * val;
        scaled % params.p
    });

    println!("3");

    let cipher = (head_c, tail_c);

    return cipher;
}
