//! Variant constructors for the errors shared by `pool` and `pool-gvk`.
//!
//! Each contract exports its own `#[contracterror]` `Error` enum — the error
//! domain is part of a contract's ABI, and the two contract crates must not
//! share types that could collide at link time (see the crate docs on
//! `pool-core`). Helpers in `pool-core` are therefore generic over this
//! trait: they raise the calling contract's own variants, and each contract
//! implements the trait for its `Error` with one line per variant.

use crate::merkle_with_history::Error as MerkleError;

/// The error variants the shared helpers raise.
///
/// `pool::Error` and `pool_gvk::Error` assign identical codes to the
/// variants covered by the [`PoolError::from_merkle`] table (both documents
/// `pool::Error` as their source), so the mapping table lives here once and
/// cannot drift apart between the contracts.
pub trait PoolError: Sized {
    /// Map a [`MerkleError`] onto the contract's error domain.
    fn from_merkle(e: MerkleError) -> Self {
        match e {
            MerkleError::AlreadyInitialized => Self::already_initialized(),
            MerkleError::WrongLevels => Self::wrong_levels(),
            MerkleError::MerkleTreeFull => Self::merkle_tree_full(),
            MerkleError::NextIndexNotEven => Self::next_index_not_even(),
            MerkleError::NotInitialized => Self::not_initialized(),
            MerkleError::Overflow => Self::overflow(),
        }
    }

    /// Contract has already been initialized.
    fn already_initialized() -> Self;
    /// Invalid Merkle tree levels configuration.
    fn wrong_levels() -> Self;
    /// Merkle tree has reached maximum capacity.
    fn merkle_tree_full() -> Self;
    /// Internal error: next leaf index is not even.
    fn next_index_not_even() -> Self;
    /// Contract is not initialized.
    fn not_initialized() -> Self;
    /// Arithmetic overflow occurred.
    fn overflow() -> Self;
    /// External amount is invalid (negative or exceeds the 2^248 bound).
    fn wrong_ext_amount() -> Self;
    /// A public input is not canonical in the BN254 scalar field.
    fn non_canonical_public_input() -> Self;
}
