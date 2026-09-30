//! Pure numeric helpers shared by `pool` and `pool-gvk`.
//!
//! The base functions take no `DataKey`/error type, so each contract calls
//! them directly and maps the result to its own `Error` enum; the
//! `require_*` variants do that mapping through the [`PoolError`] trait.

use crate::{error::PoolError, policy};
use soroban_sdk::{BytesN, Env, I256, U256, Vec};
use soroban_utils::constants::bn256_modulus;

/// Convert a U256 into a 32-byte big-endian field element.
pub fn u256_to_bytes(env: &Env, v: &U256) -> BytesN<32> {
    let mut buf = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

/// Maximum absolute external amount allowed (2^248).
pub fn max_ext_amount(env: &Env) -> U256 {
    U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
}

/// Convert a non-negative I256 to i128 with bounds checking.
pub fn i256_to_i128_nonneg(env: &Env, v: &I256) -> Option<i128> {
    if *v < I256::from_i32(env, 0) {
        return None;
    }
    v.to_i128()
}

/// Convert I256 to its absolute value as U256.
pub fn i256_abs_to_u256(env: &Env, v: &I256) -> U256 {
    let zero = I256::from_i32(env, 0);
    let abs = if *v >= zero { v.clone() } else { zero.sub(v) };
    U256::from_be_bytes(env, &abs.to_be_bytes())
}

/// Calculate the public amount from external amount:
/// `public_amount = ext_amount` in the BN256 field, wrapping negative values
/// to `FIELD_SIZE - |ext_amount|`. Returns `None` if `|ext_amount|` exceeds
/// the 2^248 bound.
pub fn calculate_public_amount(env: &Env, ext_amount: I256) -> Option<U256> {
    let abs_ext = i256_abs_to_u256(env, &ext_amount);
    if abs_ext >= max_ext_amount(env) {
        return None;
    }

    let zero = I256::from_i32(env, 0);

    if ext_amount >= zero {
        let pa_bytes = ext_amount.to_be_bytes();
        Some(U256::from_be_bytes(env, &pa_bytes))
    } else {
        let neg = zero.sub(&ext_amount);
        let neg_bytes = neg.to_be_bytes();
        let neg_u256 = U256::from_be_bytes(env, &neg_bytes);

        let field = bn256_modulus(env);
        Some(field.sub(&neg_u256))
    }
}

/// Whether a value is within the canonical BN254 scalar-field range.
pub fn is_canonical_bn256_public_input(value: &U256, modulus: &U256) -> bool {
    value < modulus
}

/// `i256_to_i128_nonneg` mapped onto the caller's error domain.
///
/// # Errors
///
/// Returns [`PoolError::wrong_ext_amount`] if `v` is negative or exceeds
/// `i128`.
pub fn require_i128_nonneg<E: PoolError>(env: &Env, v: &I256) -> Result<i128, E> {
    i256_to_i128_nonneg(env, v).ok_or_else(E::wrong_ext_amount)
}

/// `calculate_public_amount` mapped onto the caller's error domain.
///
/// # Errors
///
/// Returns [`PoolError::wrong_ext_amount`] if `|ext_amount|` exceeds the
/// 2^248 bound.
pub fn require_public_amount<E: PoolError>(env: &Env, ext_amount: I256) -> Result<U256, E> {
    calculate_public_amount(env, ext_amount).ok_or_else(E::wrong_ext_amount)
}

/// Reject a value outside the canonical BN254 scalar-field range.
///
/// `Bn254Fr::from_bytes` expects field elements, so any `U256` that will be
/// converted into a verifier public input must be checked before conversion.
///
/// # Errors
///
/// Returns [`PoolError::non_canonical_public_input`] if `value` is at least
/// `modulus`.
pub fn require_canonical_bn256_input<E: PoolError>(value: &U256, modulus: &U256) -> Result<(), E> {
    if is_canonical_bn256_public_input(value, modulus) {
        Ok(())
    } else {
        Err(E::non_canonical_public_input())
    }
}

/// Validate every `U256` field of a transact proof that contributes to the
/// verifier's public-input vector: root, public amount, input nullifiers,
/// both output commitments, and the ASP roots the policy flags enable.
///
/// The transaction path checks `ext_data_hash` against `hash_ext_data`
/// before proof verification, so this covers the remaining public-input
/// values. Contract-specific extra fields (pool-gvk's ciphertexts) are
/// validated by the caller on top.
///
/// # Errors
///
/// Returns [`PoolError::non_canonical_public_input`] on the first
/// non-canonical field.
#[allow(clippy::too_many_arguments)]
pub fn require_canonical_transact_inputs<E: PoolError>(
    root: &U256,
    public_amount: &U256,
    input_nullifiers: &Vec<U256>,
    output_commitment0: &U256,
    output_commitment1: &U256,
    asp_membership_root: &U256,
    asp_non_membership_root: &U256,
    policy_flags: u32,
    modulus: &U256,
) -> Result<(), E> {
    require_canonical_bn256_input(root, modulus)?;
    require_canonical_bn256_input(public_amount, modulus)?;
    for nullifier in input_nullifiers.iter() {
        require_canonical_bn256_input(&nullifier, modulus)?;
    }
    require_canonical_bn256_input(output_commitment0, modulus)?;
    require_canonical_bn256_input(output_commitment1, modulus)?;
    if policy::requires_membership_proofs(policy_flags) {
        require_canonical_bn256_input(asp_membership_root, modulus)?;
    }
    if policy::requires_non_membership_proofs(policy_flags) {
        require_canonical_bn256_input(asp_non_membership_root, modulus)?;
    }

    Ok(())
}
