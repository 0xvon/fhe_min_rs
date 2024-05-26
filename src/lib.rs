pub use concrete::*;

fn compute_min(
    cipher_1: &LWE,
    cipher_2: &LWE,
    ksk: &LWEKSK,
    bsk: &LWEBSK,
    encoder: &Encoder,
    zero: &LWE,
) -> Result<LWE, CryptoAPIError> {
    // difference between the two ciphers
    let cipher_diff = cipher_2.add_centered(&cipher_1.opposite()?)?;

    // programmable bootstrap to check if the difference is positive
    let mut cipher_diff_pos =
        cipher_diff.bootstrap_with_function(bsk, |x| if x >= 0. { x } else { 0. }, encoder)?;

    // change the key back to the original one
    cipher_diff_pos = cipher_diff_pos.keyswitch(ksk)?;

    // subtract the result from cipher_2
    let mut result = cipher_2.add_centered(&cipher_diff_pos.opposite()?)?;

    // add 0 to reset the encoder offset
    result.add_centered_inplace(zero)?;

    Ok(result)
}

pub fn compute_min_array(
    ciphers: &[LWE],
    ksk: &LWEKSK,
    bsk: &LWEBSK,
    encoder: &Encoder,
    zero: &LWE,
) -> Result<LWE, Box<dyn std::error::Error>> {
    let mut ciphers_iter = ciphers.iter();
    let mut result = ciphers_iter
        .next()
        .ok_or("Empty cipher array!".to_string())?
        .clone();

    for cipher in ciphers_iter {
        result = compute_min(&result, cipher, ksk, bsk, encoder, &zero)?;
    }
    Ok(result)
}
