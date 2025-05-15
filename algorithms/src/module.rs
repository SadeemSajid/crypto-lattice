use nalgebra::{DMatrix, DVector};
use rand::{thread_rng, Rng};
use std::env;
use std::time::Instant;

fn sample_ring_vector(n: usize, q: i64) -> DVector<i64> {
    DVector::from_fn(n, |_, _| thread_rng().gen_range(0..q))
}

fn sample_ring_matrix(k: usize, q: i64) -> DMatrix<i64> {
    DMatrix::from_fn(k, k, |_, _| thread_rng().gen_range(0..q))
}

fn modular(v: DVector<i64>, q: i64) -> DVector<i64> {
    v.map(|x| ((x % q) + q) % q)
}

fn modular_mat(m: DMatrix<i64>, q: i64) -> DMatrix<i64> {
    m.map(|x| ((x % q) + q) % q)
}

pub fn keygen(k: usize, q: i64) -> (DMatrix<i64>, DVector<i64>, DVector<i64>, DVector<i64>) {
    let a = sample_ring_matrix(k, q);
    let s0 = sample_ring_vector(k, q);
    let e0 = sample_ring_vector(k, q);
    let p0 = modular(&(&a * &s0) + &e0, q);
    (a, s0, e0, p0)
}

pub fn encrypt(
    a: &DMatrix<i64>,
    p0: &DVector<i64>,
    m: &DVector<i64>,
    q: i64,
) -> (DVector<i64>, DVector<i64>) {
    let s1 = sample_ring_vector(a.nrows(), 2); // binary vector
    let e1 = sample_ring_vector(a.ncols(), q);
    let e = thread_rng().gen_range(0..q);

    let p1 = modular((&s1.transpose() * a).transpose() + &e1, q);
    let scalar = (&s1.transpose() * p0)[0];
    let c = modular(
        (m * (q / 2)) + DVector::from_element(m.len(), e) + DVector::from_element(m.len(), scalar),
        q,
    );
    (p1, c)
}

pub fn decrypt(p1: &DVector<i64>, c: &DVector<i64>, s0: &DVector<i64>, q: i64) -> DVector<i64> {
    let inner = (&p1.transpose() * s0)[0];
    c.map(|ci| {
        let m_approx = 2.0 * ((ci - inner) as f64) / (q as f64);
        if m_approx.round() as i64 > 0 {
            1
        } else {
            0
        }
    })
}
