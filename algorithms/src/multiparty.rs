// Interactive Multiparty Key Exchange based on RLWE (Test Only)
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::iter::repeat_with;
use std::time::Instant;
// N =   8,  Q =   97 , Duration = 1.3121ms
// N =   64, Q =   257, Duration = 11.5776ms
// N =  128, Q =   769, Duration = 40.4004ms
// N =  256, Q = 12289, Duration = 145.3538ms
const N: usize = 8; // Polynomial degree (must be power of 2)
const Q: i32 = 97; // Modulus (small prime for testing)
const STDDEV: f64 = 0.1; // Standard deviation for noise

// Sample error polynomial with clamped Gaussian noise
fn sample_error(n: usize, q: i32, stddev: f64) -> Vec<i32> {
    let mut rng = rand::thread_rng();
    let normal = Normal::new(0.0, stddev).unwrap();
    (0..n)
        .map(|_| {
            let mut sample = normal.sample(&mut rng).round() as i32;
            if sample.abs() > 1 {
                sample = sample.signum() * 1;
            }
            (sample + q) % q
        })
        .collect()
}

// Generate non-zero secret polynomial
fn generate_secret(n: usize, q: i32) -> Vec<i32> {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| rng.gen_range(1..q)).collect()
}

// Polynomial multiplication in R_q = Z_q[x]/(x^n + 1)
fn poly_mul(a: &[i32], b: &[i32], n: usize, q: i32) -> Vec<i32> {
    let mut result = vec![0; n];
    for i in 0..n {
        for j in 0..n {
            let index = (i + j) % n;
            let sign = if i + j >= n { -1 } else { 1 };
            result[index] = ((result[index] + sign * (a[i] * b[j]) % q) + q) % q;
        }
    }
    result
}

// Extract shared key using thresholding and basic correction
fn extract_shared_key(poly: &[i32], q: i32) -> Vec<i32> {
    let threshold = q / 2;
    poly.iter()
        .map(|&x| if x > threshold { 1 } else { 0 })
        .collect()
}

// Interactive Multiparty Key Exchange
fn multiparty_key_exchange(k: usize) {
    let mut rng = rand::thread_rng();
    let m: Vec<i32> = repeat_with(|| rng.gen_range(1..Q)).take(N).collect();

    let mut secrets = vec![];
    let mut initial_msgs = vec![];
    let mut intermediary_msgs = vec![vec![0; N]; k];

    // Step 1: Each user selects secret s_i and sends p_i^0 to next user
    for i in 0..k {
        let s_i = generate_secret(N, Q);
        let e_i0 = sample_error(N, Q, STDDEV);
        let p_i0: Vec<i32> = poly_mul(&m, &s_i, N, Q)
            .iter()
            .zip(e_i0.iter())
            .map(|(&a, &b)| ((a + 2 * b) % Q + Q) % Q)
            .collect();

        secrets.push(s_i);
        initial_msgs.push(p_i0);
    }

    // Step 2: Propagate messages
    for i in 0..k {
        let mut p = initial_msgs[i].clone();
        for j in 1..(k - 1) {
            let idx = (i + j) % k;
            let s = &secrets[idx];
            let e = sample_error(N, Q, STDDEV);
            p = poly_mul(&p, s, N, Q)
                .iter()
                .zip(e.iter())
                .map(|(&a, &b)| ((a + 2 * b) % Q + Q) % Q)
                .collect();
        }
        intermediary_msgs[(i + k - 1) % k] = p;
    }

    // Step 3: User 0 computes K0, encodes sigma and broadcasts it
    let e_0 = sample_error(N, Q, STDDEV);
    let s_0 = &secrets[0];
    let k_0_poly: Vec<i32> = poly_mul(&intermediary_msgs[0], s_0, N, Q)
        .iter()
        .zip(e_0.iter())
        .map(|(&a, &b)| ((a + 2 * b) % Q + Q) % Q)
        .collect();
    let sigma = extract_shared_key(&k_0_poly, Q);

    // Step 4: All users derive shared key SK_i = E(K_i, sigma)
    println!("Shared key (sigma): {:?}", sigma);

    for i in 0..k {
        let e_i = sample_error(N, Q, STDDEV);
        let k_i = poly_mul(&intermediary_msgs[i], &secrets[i], N, Q)
            .iter()
            .zip(e_i.iter())
            .map(|(&a, &b)| ((a + 2 * b) % Q + Q) % Q)
            .collect::<Vec<i32>>();

        let sk_i = extract_shared_key(&k_i, Q);
        println!("User {} shared key: {:?}", i, sk_i);
    }
}

pub fn benchmark_key_exchange(k: usize) {
    let start = Instant::now();

    multiparty_key_exchange(k);
    let duration = start.elapsed();

    println!("N = {:>4}, Q = {:>6} -> Time: {:?}", N, Q, duration);
}

fn main() {
    let num_users = 4; // Adjust number of parties here
    benchmark_key_exchange(num_users);
}
