use rand::Rng;
use std::time::{Duration, Instant};

// Parameters
const LWE_N: usize = 536;
const LWE_M: usize = 1024;
const LWE_L: usize = 256;
const LOG_Q: u32 = 11;
const _16_LOG_Q: u32 = 5;
const LOG_P: u32 = 9;
const RD_ADD: u16 = 0x40;
const RD_AND: u16 = 0xff80;
const LOG_T: u32 = 1;
const _16_LOG_T: u32 = 15;
const T: u16 = 2;
const DEC_ADD: u16 = 0x4000;
const HR: usize = 134;

// Noise distribution
const CDF_TABLE: [u16; 9] = [78, 226, 344, 425, 473, 495, 506, 510, 511];
const RANDBITS: u32 = 10;
const TABLE_LENGTH: usize = 9;

// Sample from the discrete Gaussian distribution
fn sample_d2() -> u16 {
    let mut rng = rand::thread_rng();
    let rnd: u16 = rng.gen::<u16>() & 0x01ff;
    let sign: u16 = rng.gen::<u16>() & 0x01;
    let mut sample: u16 = 0;

    for i in 0..TABLE_LENGTH - 1 {
        let diff = (CDF_TABLE[i] as i32 - rnd as i32) >> 15;
        sample = sample.wrapping_add(diff as u16);
    }
    sample = ((-(sign as i16) as u16 ^ sample).wrapping_add(sign));
    sample
}

// Secret key
type SecretKey = [[i16; LWE_N]; LWE_L];

// Public key
pub struct PublicKey {
    a: [[u16; LWE_N]; LWE_M],
    b: [[u16; LWE_L]; LWE_M],
}

// Ciphertext
pub struct Ciphertext {
    a: [u16; LWE_N],
    b: [u16; LWE_L],
}

// Generate secret key
pub fn gen_sk() -> SecretKey {
    let mut sk = [[0i16; LWE_N]; LWE_L];
    let mut rng = rand::thread_rng();

    for i in 0..LWE_L {
        for j in 0..LWE_N {
            sk[i][j] = (rng.gen::<u16>() & 0x01) as i16 + (rng.gen::<u16>() & 0x01) as i16 - 1;
        }
    }
    sk
}

// Generate public key
pub fn gen_pk(sk: &SecretKey) -> PublicKey {
    let mut pk = PublicKey {
        a: [[0; LWE_N]; LWE_M],
        b: [[0; LWE_L]; LWE_M],
    };
    let mut rng = rand::thread_rng();

    // Generate matrix A
    for i in 0..LWE_M {
        for j in 0..LWE_N {
            pk.a[i][j] = rng.gen::<u16>() << _16_LOG_Q;
        }
    }

    // Generate matrix B = A * sk + E
    for i in 0..LWE_M {
        for j in 0..LWE_L {
            let mut sum = 0u16;
            for k in 0..LWE_N {
                sum = sum.wrapping_add(pk.a[i][k].wrapping_mul(sk[j][k] as u16));
            }
            pk.b[i][j] = sum.wrapping_add(sample_d2() << _16_LOG_Q);
        }
    }
    pk
}

// Encrypt plaintext
pub fn encrypt(pk: &PublicKey, plaintext: &[u16; LWE_L]) -> Ciphertext {
    let mut ctx = Ciphertext {
        a: [0; LWE_N],
        b: plaintext.clone(),
    };
    let mut rng = rand::thread_rng();

    // Generate sparse vector r
    let mut r_idx = [0usize; HR];
    let neg_start = {
        let mut neg_start = 0;
        for i in 0..HR / 2 {
            let tmp: u64 = rng.gen();
            neg_start += (tmp & 0x01) as usize;
            r_idx[2 * i] = ((tmp >> 1) & 0x03ff) as usize % LWE_M;
            neg_start += ((tmp >> 10) & 0x01) as usize;
            r_idx[2 * i + 1] = ((tmp >> 12) & 0x03ff) as usize % LWE_M;
        }
        neg_start
    };

    // Compute A^T * r and B^T * r
    for i in 0..HR {
        let s = if i < neg_start { 1 } else { 0 };
        let pk_a_ri = &pk.a[r_idx[i]];
        let pk_b_ri = &pk.b[r_idx[i]];

        for j in 0..LWE_N {
            ctx.a[j] = ctx.a[j].wrapping_add((s as u16).wrapping_mul(pk_a_ri[j]));
            ctx.a[j] = ctx.a[j]
                .wrapping_sub((1 - s) as u16)
                .wrapping_mul(pk_a_ri[j]);
        }
        for j in 0..LWE_L {
            ctx.b[j] = ctx.b[j].wrapping_add((s as u16).wrapping_mul(pk_b_ri[j]));
            ctx.b[j] = ctx.b[j]
                .wrapping_sub((1 - s) as u16)
                .wrapping_mul(pk_b_ri[j]);
        }
    }

    // Round to modulus p
    for i in 0..LWE_N {
        ctx.a[i] = (ctx.a[i].wrapping_add(RD_ADD)) & RD_AND;
    }
    for i in 0..LWE_L {
        ctx.b[i] = (ctx.b[i].wrapping_add(RD_ADD)) & RD_AND;
    }
    ctx
}

// Decrypt ciphertext
pub fn decrypt(sk: &SecretKey, ctx: &Ciphertext) -> [u16; LWE_L] {
    let mut plaintext = ctx.b.clone();

    for i in 0..LWE_L {
        let sk_i = &sk[i]; // Access the i-th row of sk
        for j in 0..LWE_N {
            plaintext[i] = plaintext[i].wrapping_add(ctx.a[j].wrapping_mul(sk_i[j] as u16));
        }
    }

    for i in 0..LWE_L {
        plaintext[i] = (plaintext[i].wrapping_add(DEC_ADD)) >> _16_LOG_T;
    }
    plaintext
}
