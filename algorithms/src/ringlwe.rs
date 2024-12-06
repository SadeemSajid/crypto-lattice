use std::vec;

use rustfft::num_traits::Zero;
use rustfft::{num_complex::Complex, FftPlanner};

use rand::Rng;
use rand_distr::{Distribution, Normal};

const N: i64 = 512;
const Q: i64 = 3329;
const STD_DEV: f64 = 1.0;

pub struct SecurityParameters {
    pub dimension: i64,
    pub modulo: i64,
}

pub struct PrivateKey {
    pub secret_vector: Vec<i64>,
}

pub struct PublicKey {
    pub polynomial: Vec<i64>,
    pub error_polynomial: Vec<i64>,
}

// Add polynomials
fn add(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut result: Vec<i64> = vec![0; a.len()];
    if a.len() != b.len() {
        panic!("Vector lengths must be equal for addition!");
    }

    for iter in 0..a.len() {
        result[iter] = a[iter] + b[iter];
    }
    result
}

// Subtract polynomials
fn sub(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut result: Vec<i64> = vec![0; a.len()];
    if a.len() != b.len() {
        panic!("Vector lengths must be equal for subtraction!");
    }

    for iter in 0..a.len() {
        result[iter] = a[iter] - b[iter];
    }
    result
}

// Reduce polynomial by X^n + 1
fn reduce(poly: &[i64], degree: i64, modulo: i64) -> Vec<i64> {
    let mut result: Vec<i64> = vec![0; degree as usize];
    for i in degree..poly.len() as i64 {
        let wrap = (i - degree) as usize;
        result[wrap] = (poly[wrap] - poly[i as usize]) % modulo;
    }

    result
}

// Multiply polynomials using FFT
fn multiply(a: &[i64], b: &[i64]) -> Vec<i64> {
    // Determine the size for zero-padding (next power of 2)
    let n = (a.len() + b.len() - 1).next_power_of_two();

    // Zero-pad the input arrays
    let mut a_padded: Vec<Complex<f64>> = vec![Complex::zero(); n];
    let mut b_padded: Vec<Complex<f64>> = vec![Complex::zero(); n];
    for (i, &coeff) in a.iter().enumerate() {
        a_padded[i] = Complex::new(coeff as f64, 0.0);
    }
    for (i, &coeff) in b.iter().enumerate() {
        b_padded[i] = Complex::new(coeff as f64, 0.0);
    }

    // Create the FFT planner
    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(n);
    let ifft = planner.plan_fft_inverse(n);

    // Perform FFT on both padded polynomials
    fft.process(&mut a_padded);
    fft.process(&mut b_padded);

    // Pointwise multiply the FFT results
    let mut result_fft: Vec<Complex<f64>> = a_padded
        .iter()
        .zip(b_padded.iter())
        .map(|(a, b)| a * b)
        .collect();

    // Perform the inverse FFT
    ifft.process(&mut result_fft);

    // Normalize and round the results to integers (scale by 1/n due to IFFT)
    result_fft
        .iter()
        .map(|x| (x.re / n as f64).round() as i64)
        .collect()
}

// Sample a small polynomial
fn gen_small_polynomial(size: i64) -> Vec<i64> {
    let mut matrix: Vec<i64> = vec![0; size as usize];

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(-1..=1);
    }

    return matrix;
}

fn error(mean: f64, std_dev: f64, length: i64) -> Vec<i64> {
    let mut matrix: Vec<i64> = vec![0; length as usize];
    let normal: Normal<f64> = Normal::new(mean, std_dev).unwrap();

    for elem in matrix.iter_mut() {
        *elem = normal.sample(&mut rand::thread_rng()) as i64;
    }

    return matrix;
}

pub fn setup() -> SecurityParameters {
    return SecurityParameters {
        dimension: N,
        modulo: Q,
    };
}

pub fn key_gen(params: &SecurityParameters) -> (PublicKey, PrivateKey) {
    // Secret vector
    let secret: Vec<i64> = gen_small_polynomial(params.dimension);

    // Random polynomial
    let poly: Vec<i64> = gen_small_polynomial(params.dimension);

    // B
    // a.s
    let mul_result: Vec<i64> = reduce(&multiply(&poly, &secret), params.dimension, params.modulo);
    // a.s + e1
    let mut error_poly: Vec<i64> = add(&mul_result, &error(0.0, STD_DEV, params.dimension));
    error_poly.iter_mut().for_each(|x| *x %= params.modulo);

    return (
        PublicKey {
            polynomial: poly,
            error_polynomial: error_poly,
        },
        PrivateKey {
            secret_vector: secret,
        },
    );
}

// TODO: Complete this
fn encrypt_chunk() {}

pub fn encrypt(
    plaintext: &[i64],
    params: &SecurityParameters,
    key: &PublicKey,
) -> (Vec<i64>, Vec<i64>) {
    let error_1 = error(0.0, STD_DEV, params.dimension);
    let error_2 = error(0.0, STD_DEV, params.dimension);
    let r = error(0.0, STD_DEV, params.dimension);

    // preamble
    let preamble = add(
        &reduce(
            &multiply(&key.polynomial, &r),
            params.dimension,
            params.modulo,
        ),
        &error_1,
    );

    // scalars
    let prepend = add(
        &reduce(
            &multiply(&key.error_polynomial, &r),
            params.dimension,
            params.modulo,
        ),
        &error_2,
    );
    let mut append = vec![0; params.dimension as usize];
    for i in 0..params.dimension {
        append[i as usize] = plaintext[i as usize] * (params.modulo / 2);
    }

    let mut scalars = add(&prepend, &append);
    scalars.iter_mut().for_each(|x| *x %= params.modulo);

    return (preamble, scalars);
}

pub fn decrypt(
    preamble: &Vec<i64>,
    scalars: &Vec<i64>,
    params: &SecurityParameters,
    key: &PrivateKey,
) -> Vec<i64> {
    let mut r: Vec<i64> = sub(
        &scalars,
        &reduce(
            &multiply(&preamble, &key.secret_vector),
            params.dimension,
            params.modulo,
        ),
    );
    r.iter_mut().for_each(|x| *x %= params.modulo);

    let mut result: Vec<i64> = vec![0; params.dimension as usize];
    for i in 0..params.dimension {
        if r[i as usize] < params.modulo / 4 {
            result[i as usize] = 0;
        } else {
            result[i as usize] = 1;
        }
    }
    result
}
