// Short Message Attack
// Partial Key Exposure Attack
// Low Exponent Attack

use lll_rs::lll::biglll::lattice_reduce;
use lll_rs::matrix::Matrix;
use lll_rs::vector::BigVector;
use rug::ops::Pow;
use rug::{Assign, Integer};

// LOW EXPONENT ATTACK

/*
If the exponent is small, then the modulo N operation does not wrap around the result in c = m^e mod N
(P1) So, we can safely say c = m^e.

We can therefore setup a polynomial f(x) = x^e - c, for which x must be a root.
(P2) f(x) = x^e - c = 0

We can find more small polynomials based on this root, LLL reduce their coefficients, and extract the root then.

Algorithm:
1. Construct polynomials.
2. Generate basis.
3. LLL reduce basis.
4. Extract root from reduced polynomials.

*/

pub fn low_public_exponent_attack(n: &Integer, e: usize, c: &Integer) -> Option<Integer> {
    // Step 1: Define the polynomial f(x) = x^e - c
    let mut x = Integer::new();
    x.assign(0);

    // Step 2: Brute-force small roots
    // Increment x and check if x^e == c mod N
    loop {
        let candidate = x.clone().pow(e as u32) % n;

        if candidate == *c {
            return Some(x); // Found the root
        }

        x += 1;

        // Break condition if we exceed N^(1/e) (for efficiency)
        let limit = n.clone().root(e as u32);
        if x > limit {
            break;
        }
    }

    None // No root found
}
