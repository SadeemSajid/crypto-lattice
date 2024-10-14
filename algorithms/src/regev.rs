use ascii_converter::*;
use ndarray::{Array1, Array2};
use rand::Rng;
use rand_distr::{Distribution, Normal};

// We'll internally handle security parameter generations as well
pub struct SecurityParameters {
    pub dimensions: i32, // n
    pub rank: i32,       // m
    pub modulo: i32,     // q
}

pub struct PublicKey {
    pub matrix: Array2<i32>,
    pub public_vector: Array1<i32>,
}

pub struct PrivateKey {
    pub secret_vector: Array1<i32>,
}

fn __gen_random_array2__(rows: i32, cols: i32, modulo: i32) -> Array2<i32> {
    let mut matrix = Array2::<i32>::zeros((rows as usize, cols as usize));

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

fn __gen_random_array1__(size: i32, modulo: i32) -> Array1<i32> {
    let mut matrix = Array1::<i32>::zeros(size as usize);

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

pub fn __str_to_bit__(text: String) -> Array1<i32> {
    let base_vector: Vec<u32> = string_to_binary(&text).unwrap();
    let mut bit_stream: Vec<u32> = vec![];

    for byte in base_vector {
        let mut byte_string: String = byte.to_string();

        if byte_string.len() == 7 {
            byte_string = String::from("0") + &byte_string;
        } else if byte_string.len() == 6 {
            byte_string = String::from("00") + &byte_string;
        }

        for bit in byte_string.chars() {
            bit_stream.push(bit.to_digit(2).unwrap() as u32);
        }
    }

    return Array1::from(
        bit_stream
            .into_iter()
            .map(|x: u32| x as i32)
            .collect::<Vec<i32>>(),
    );
}

fn __error__(mean: f64, std_dev: f64, length: i32) -> Array1<i32> {
    let mut matrix = Array1::<i32>::zeros(length as usize);
    let normal: Normal<f64> = Normal::new(mean, std_dev).unwrap();

    for elem in matrix.iter_mut() {
        *elem = normal.sample(&mut rand::thread_rng()) as i32;
    }

    return matrix;
}

// Initialize security parameters and other things. Call: 1

pub fn setup() -> SecurityParameters {
    // Security params for the sessions
    let params: SecurityParameters = SecurityParameters {
        dimensions: 10,
        rank: 25,
        modulo: 181,
    };

    return params;
}

// pub fn modify_params(_dimensions: i32, _rank: i32, _modulo: i32) -> SecurityParameters {
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

    let b = s.dot(&a) + __error__(0.0, 0.3, params.rank);

    // Use this to show error
    // println!("Error: {:?}", &b - s.dot(&a));

    // Return after modulo operations
    return (
        PublicKey {
            matrix: a,
            public_vector: b.mapv(|x: i32| x % params.modulo),
        },
        PrivateKey { secret_vector: s },
    );
}

pub fn encrypt(
    plain_text: String,
    public_key: &PublicKey,
    params: &SecurityParameters,
) -> (Array2<i32>, Array1<i32>) {
    let bit_stream = __str_to_bit__(plain_text);

    // random vector x
    let x = __gen_random_array2__(params.rank, bit_stream.len() as i32, 2);

    let preamble = public_key.matrix.dot(&x).mapv(|x: i32| x % params.modulo);

    let scalars = (public_key.public_vector.dot(&x) + ((bit_stream * params.modulo) / 2))
        .mapv(|x: i32| x % params.modulo);

    return (preamble, scalars);
}

pub fn decrypt(
    preabmle: Array2<i32>,
    scalars: Array1<i32>,
    private_key: &PrivateKey,
    params: &SecurityParameters,
) -> Array1<i32> {
    let mut result =
        (scalars - private_key.secret_vector.dot(&preabmle)).mapv(|x: i32| x.abs() % params.modulo);

    // Use this to print result
    println!("Result: {:?}", result);

    for elem in result.iter_mut() {
        if *elem <= params.modulo / 4 {
            *elem = 0;
        } else {
            *elem = 1;
        }
    }

    return result;
}
