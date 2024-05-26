use fhe_min_rs::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // encoder
    let encoder = Encoder::new(0., 1., 4, 2)?;

    // expected precision
    let precision = 0.2;

    // secret keys
    let sk_rlwe = RLWESecretKey::new(&RLWE128_1024_1);
    let sk_in = LWESecretKey::new(&LWE128_1024);
    let sk_out = sk_rlwe.to_lwe_secret_key();

    // encryption of 0
    let zero = LWE::encode_encrypt(&sk_in, 0., &encoder)?;

    // key switching key
    let ksk = LWEKSK::new(&sk_out, &sk_in, 5, 5);

    // bootstrapping key
    let bsk = LWEBSK::new(&sk_in, &sk_rlwe, 5, 5);

    let messages: Vec<f64> = vec![0.159, 0.423, 0.7, 0.99];
    // encrypt the messages
    let ciphers: Vec<LWE> = messages
        .iter()
        .map(|m| LWE::encode_encrypt(&sk_in, *m, &encoder))
        .collect::<Result<Vec<LWE>, CryptoAPIError>>()?;

    // perform the calculation
    let cipher_min = compute_min_array(&ciphers, &ksk, &bsk, &encoder, &zero)?;
    let mut min_val = cipher_min.decrypt_decode(&sk_in)?;
    min_val = (min_val / precision).round() * precision;
    println!("minimum: {}", min_val);

    Ok(())
}
