use ndarray::Array2;
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
    pub public_vector: Array2<i32>,
}

pub struct PrivateKey {
    pub secret_vector: Array2<i32>,
}

fn __gen_random_matrix__(rows: i32, cols: i32, modulo: i32) -> Array2<i32> {
    let mut matrix = Array2::<i32>::zeros((rows as usize, cols as usize));

    let mut rng = rand::thread_rng();
    for elem in matrix.iter_mut() {
        *elem = rng.gen_range(0..modulo);
    }

    return matrix;
}

fn __error__(mean: f64, std_dev: f64, length: i32) -> Array2<i32> {
    let mut matrix = Array2::<i32>::zeros((1, length as usize));
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

pub fn modify_params(_dimensions: i32, _rank: i32, _modulo: i32) -> SecurityParameters {
    return SecurityParameters {
        dimensions: _dimensions,
        rank: _rank,
        modulo: _modulo,
    };
}

// Call: 2
pub fn key_gen(params: SecurityParameters) -> (PublicKey, PrivateKey) {
    let a = __gen_random_matrix__(params.dimensions, params.rank, params.modulo);

    let s = __gen_random_matrix__(1, params.dimensions, params.modulo);

    let b = s.dot(&a) + __error__(0.0, 1.0, params.rank);

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

pub fn encrypt(plain_text: String, public_key: PublicKey, params: SecurityParameters) {}

// pub fn decrypt() {}
