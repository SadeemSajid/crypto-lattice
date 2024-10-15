use ascii_converter::*;
use ndarray::{Array1, Array2};
use rand::Rng;
use rand_distr::{Distribution, Normal};

// We'll internally handle security parameter generations as well
pub struct SecurityParameters {
    pub dimensions: i64, // n
    pub rank: i64,       // m
    pub modulo: i64,     // q
}

pub struct PublicKey {
    pub matrix: Array2<i64>,
    pub public_vector: Array1<i64>,
}

pub struct PrivateKey {
    pub secret_vector: Array1<i64>,
}

fn __gen_random_array2__(rows: i64, cols: i64, modulo: i64) -> Array2<i64> {
    let mut matrix = Array2::<i64>::zeros((rows as usize, cols as usize));

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

fn __gen_random_array1__(size: i64, modulo: i64) -> Array1<i64> {
    let mut matrix = Array1::<i64>::zeros(size as usize);

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

pub fn __str_to_bit__(text: String) -> Array1<i64> {
    let base_vector: Vec<u64> = string_to_binary(&text)
        .unwrap()
        .into_iter()
        .map(|x| x as u64)
        .collect();
    let mut bit_stream: Vec<u64> = vec![];

    for byte in base_vector {
        let mut byte_string: String = byte.to_string();

        if byte_string.len() == 7 {
            byte_string = String::from("0") + &byte_string;
        } else if byte_string.len() == 6 {
            byte_string = String::from("00") + &byte_string;
        }

        for bit in byte_string.chars() {
            bit_stream.push(bit.to_digit(2).unwrap() as u64);
        }
    }

    return Array1::from(
        bit_stream
            .into_iter()
            .map(|x: u64| x as i64)
            .collect::<Vec<i64>>(),
    );
}

fn __bits_to_string__(bits: Array1<i64>) -> String {
    // Ensure the bit array length is divisible by 8.
    assert!(
        bits.len() % 8 == 0,
        "Bit array length must be divisible by 8."
    );

    // Convert the bits into bytes.
    let bytes: Vec<u8> = bits
        .exact_chunks(8) // Split into 8-bit chunks.
        .into_iter()
        .map(|chunk| {
            chunk.iter().enumerate().fold(0, |acc, (i, &bit)| {
                acc | ((bit as u8) << (7 - i)) // Convert chunk to a byte (big-endian).
            })
        })
        .collect();

    // Convert the bytes to a UTF-8 string.
    String::from_utf8(bytes).expect("Invalid UTF-8 sequence")
}

fn __error__(mean: f64, std_dev: f64, length: i64) -> Array1<i64> {
    let mut matrix = Array1::<i64>::zeros(length as usize);
    let normal: Normal<f64> = Normal::new(mean, std_dev).unwrap();

    for elem in matrix.iter_mut() {
        *elem = normal.sample(&mut rand::thread_rng()) as i64;
    }

    return matrix;
}

// Initialize security parameters and other things. Call: 1

pub fn setup() -> SecurityParameters {
    // Security params for the sessions
    let params: SecurityParameters = SecurityParameters {
        dimensions: 128, // N = Your choice
        rank: 594,       // M: 1.1 * N * LogQ
        modulo: 16411,   // Prime: N^2 < Q < 2N^2
    };

    return params;
}

// pub fn modify_params(_dimensions: i64, _rank: i64, _modulo: i64) -> SecurityParameters {
//     return SecurityParameters {
//         dimensions: _dimensions,
//         rank: _rank,
//         modulo: _modulo,
//     };
// }

// Call: 2
pub fn key_gen(params: &SecurityParameters) -> (PublicKey, PrivateKey) {
    let a = __gen_random_array2__(params.dimensions, params.rank, params.modulo);

    let s = __gen_random_array1__(params.dimensions, params.modulo);

    let b = s.dot(&a) + __error__(0.0, 0.069, params.rank);

    // Use this to show error
    // println!("Error: {:?}", &b - s.dot(&a));

    // Return after modulo operations
    return (
        PublicKey {
            matrix: a,
            public_vector: b.mapv(|x: i64| x % params.modulo),
        },
        PrivateKey { secret_vector: s },
    );
}

pub fn encrypt(
    plain_text: String,
    public_key: &PublicKey,
    params: &SecurityParameters,
) -> (Array2<i64>, Array1<i64>) {
    let bit_stream = __str_to_bit__(plain_text);

    // random vector x
    let x = __gen_random_array2__(params.rank, bit_stream.len() as i64, 2);

    let preamble = public_key.matrix.dot(&x).mapv(|x: i64| x % params.modulo);

    let scalars = (public_key.public_vector.dot(&x) + ((bit_stream * params.modulo) / 2))
        .mapv(|x: i64| x % params.modulo);

    return (preamble, scalars);
}

pub fn decrypt(
    preabmle: Array2<i64>,
    scalars: Array1<i64>,
    private_key: &PrivateKey,
    params: &SecurityParameters,
) -> String {
    let mut result =
        (scalars - private_key.secret_vector.dot(&preabmle)).mapv(|x: i64| x.abs() % params.modulo);

    // Use this to print result
    // println!("Result: {:?}", result);

    for elem in result.iter_mut() {
        if *elem <= params.modulo / 4 {
            *elem = 0;
        } else {
            *elem = 1;
        }
    }

    return __bits_to_string__(result);
}
