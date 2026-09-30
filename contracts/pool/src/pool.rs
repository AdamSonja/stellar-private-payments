//! Privacy Pool Contract
//!
//! This contract implements a privacy-preserving transaction pool with embedded
//! policy (membership and non-membership in an association set).
//! It enables users to deposit, transfer, and withdraw
//! tokens while maintaining transaction privacy through zero-knowledge proofs.
//!
//! # Architecture
//!
//! The contract maintains:
//! - A Merkle tree of commitments (via `MerkleTreeWithHistory`)
//! - A nullifier set to track spent UTXOs
//! - Token integration for deposits and withdrawals

#![allow(clippy::too_many_arguments)]
use contract_types::Groth16Proof;
use pool_core::{
    ASPMembershipClient, ASPNonMembershipClient, CircomGroth16VerifierClient, amounts,
    error::PoolError,
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy, storage,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec, contract, contracterror, contractevent,
    contractimpl, contracttype, crypto::bn254::Bn254Fr, token::TokenClient,
};
use soroban_utils::constants::bn256_modulus;

// Re-exported rather than merely imported so `pool::ExtData` and
// `pool::hash_ext_data` keep resolving for existing consumers (`e2e-tests`,
// the SDK encoding tests) after the move into `pool-core`.
pub use pool_core::{ExtData, hash_ext_data};

/// Contract error types for the privacy pool
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Caller is not authorized to perform this operation
    NotAuthorized = 1,
    /// Merkle tree has reached maximum capacity
    MerkleTreeFull = 2,
    /// Contract has already been initialized
    AlreadyInitialized = 3,
    /// Invalid Merkle tree levels configuration
    WrongLevels = 4,
    /// Internal error: next leaf index is not even
    NextIndexNotEven = 5,
    /// External amount is invalid (negative or exceeds 2^248)
    WrongExtAmount = 6,
    /// Zero-knowledge proof verification failed or proof is empty
    InvalidProof = 7,
    /// Provided Merkle root is not in the recent history
    UnknownRoot = 8,
    /// Nullifier has already been spent (double-spend attempt)
    AlreadySpentNullifier = 9,
    /// External data hash does not match the provided data
    WrongExtHash = 10,
    /// Contract is not initialized
    NotInitialized = 11,
    /// Arithmetic overflow occurred
    Overflow = 12,
    /// Public input is not canonical in the BN254 scalar field
    NonCanonicalPublicInput = 13,
    /// Unsupported policy flag bits.
    InvalidPolicyFlags = 14,
}

/// Conversion from MerkleTreeWithHistory errors to pool contract errors
/// Errors from MerkleTreeWithHistory are not `contracterror`
impl From<MerkleError> for Error {
    fn from(e: MerkleError) -> Self {
        PoolError::from_merkle(e)
    }
}

/// The shared `pool-core` helpers raise this contract's own variants.
impl PoolError for Error {
    fn already_initialized() -> Self {
        Self::AlreadyInitialized
    }

    fn wrong_levels() -> Self {
        Self::WrongLevels
    }

    fn merkle_tree_full() -> Self {
        Self::MerkleTreeFull
    }

    fn next_index_not_even() -> Self {
        Self::NextIndexNotEven
    }

    fn not_initialized() -> Self {
        Self::NotInitialized
    }

    fn overflow() -> Self {
        Self::Overflow
    }

    fn wrong_ext_amount() -> Self {
        Self::WrongExtAmount
    }

    fn non_canonical_public_input() -> Self {
        Self::NonCanonicalPublicInput
    }
}

/// Zero-knowledge proof data for a transaction
///
/// Contains all the cryptographic data needed to verify a transaction,
/// including the proof itself, public inputs, and nullifiers.
#[contracttype]
pub struct Proof {
    /// The serialized zero-knowledge proof
    pub proof: Groth16Proof,
    /// Merkle root the proof was generated against
    pub root: U256,
    /// Nullifiers for spent input UTXOs (prevents double-spending)
    pub input_nullifiers: Vec<U256>,
    /// Commitment for the first output UTXO
    pub output_commitment0: U256,
    /// Commitment for the second output UTXO
    pub output_commitment1: U256,
    /// Net public amount (deposit - withdrawal, modulo field size)
    pub public_amount: U256,
    /// Hash of the external data (binds proof to transaction parameters)
    pub ext_data_hash: BytesN<32>,
    /// Merkle root the policy membership proof was generated against
    pub asp_membership_root: U256,
    /// Merkle root the policy NON-membership proof was generated against
    pub asp_non_membership_root: U256,
}

/// Storage keys for contract data
///
/// The configuration the constructor writes, [`DataKey::Token`],
/// [`DataKey::Verifier`], [`DataKey::MaximumDepositAmount`],
/// [`DataKey::ASPMembership`], [`DataKey::ASPNonMembership`], and
/// [`DataKey::PolicyFlags`], lives in the contract's instance entry.
/// [`DataKey::Admin`] and [`DataKey::Nullifier`] are persistent keys.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DataKey {
    /// Administrator address with permissions to modify contract settings
    Admin,
    /// Address of the token contract used for deposits/withdrawals
    Token,
    /// Address of the ZK proof verifier contract
    Verifier,
    /// Maximum allowed deposit amount per transaction
    MaximumDepositAmount,
    /// Spent nullifier marker keyed by nullifier (presence-only; value unused).
    Nullifier(U256),
    /// Address of the ASP Membership contract
    ASPMembership,
    /// Address of the ASP Non-Membership contract
    ASPNonMembership,
    /// Pool ASP policy flags (bitset; see `crate::policy`).
    PolicyFlags,
}

/// Event emitted when a new commitment is added to the Merkle tree
///
/// This event allows off-chain observers to track new UTXOs and decrypt
/// outputs intended for them.
#[contractevent]
#[derive(Clone)]
pub struct NewCommitmentEvent {
    /// The commitment hash added to the tree
    #[topic]
    pub commitment: U256,
    /// Index position in the Merkle tree
    pub index: u32,
    /// Encrypted output data (decryptable by the recipient)
    pub encrypted_output: Bytes,
}

/// Event emitted when a nullifier is spent
///
/// This event allows off-chain observers to track which UTXOs have been spent.
#[contractevent]
#[derive(Clone)]
pub struct NewNullifierEvent {
    /// The nullifier that was spent
    #[topic]
    pub nullifier: U256,
}

/// Privacy Pool Contract
///
/// Implements a private transaction pool.
/// Users can deposit tokens, perform private transfers, and withdraw while
/// maintaining transaction privacy through zero-knowledge proofs.
#[contract]
pub struct PoolContract;

#[contractimpl]
impl PoolContract {
    /// Constructor: initialize the privacy pool contract
    ///
    /// Sets up the contract with the specified token, verifier, and Merkle tree
    /// configuration. This function can only be called once.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `admin` - Address of the contract administrator
    /// * `token` - Address of the token contract for deposits/withdrawals
    /// * `verifier` - Address of the ZK proof verifier contract
    /// * `asp_membership` - Address of the ASP Membership contract
    /// * `asp_non_membership` - Address of the ASP Non-Membership contract
    /// * `maximum_deposit_amount` - Maximum allowed deposit per transaction
    /// * `levels` - Number of levels in the commitment Merkle tree (1-32)
    /// * `policy_flags` - ASP policy flag bitset enforced by the transact
    ///   circuit
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if already initialized or
    /// invalid configuration
    pub fn __constructor(
        env: Env,
        admin: Address,
        token: Address,
        verifier: Address,
        asp_membership: Address,
        asp_non_membership: Address,
        maximum_deposit_amount: U256,
        levels: u32,
        policy_flags: u32,
    ) -> Result<(), Error> {
        if !policy::is_valid(policy_flags) {
            return Err(Error::InvalidPolicyFlags);
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        let instance = env.storage().instance();
        instance.set(&DataKey::Token, &token);
        instance.set(&DataKey::Verifier, &verifier);
        instance.set(&DataKey::ASPMembership, &asp_membership);
        instance.set(&DataKey::ASPNonMembership, &asp_non_membership);
        instance.set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        instance.set(&DataKey::PolicyFlags, &policy_flags);

        // Initialize the Merkle tree for commitment storage
        MerkleTreeWithHistory::init(&env, levels)?;

        Ok(())
    }

    /// Verify a zero-knowledge proof
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    ///
    /// Returns `true` if the proof is valid, and `Err(Error::InvalidProof)` if
    /// the verifier refuses it. The verifier never answers `false`: every
    /// rejection is a `Groth16Error`, so that error is translated here rather
    /// than allowed to cross the contract boundary raw.
    fn verify_proof(env: &Env, proof: &Proof) -> Result<bool, Error> {
        // Check proof is not empty
        if proof.proof.is_empty() {
            return Err(Error::InvalidProof);
        }
        let policy_flags = Self::load_policy_flags(env)?;
        let verifier = Self::get_verifier(env)?;
        let client = CircomGroth16VerifierClient::new(env, &verifier);
        amounts::require_canonical_transact_inputs::<Error>(
            &proof.root,
            &proof.public_amount,
            &proof.input_nullifiers,
            &proof.output_commitment0,
            &proof.output_commitment1,
            &proof.asp_membership_root,
            &proof.asp_non_membership_root,
            policy_flags,
            &bn256_modulus(env),
        )?;

        // Public inputs must match the policy circuit:
        // [root, public_amount, ext_data_hash, input_nullifiers,
        // output_commitments, membership_roots?, non_membership_roots]
        let mut public_inputs: Vec<Bn254Fr> = Vec::new(env);
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.root,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.public_amount,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(proof.ext_data_hash.clone()));
        for nullifier in proof.input_nullifiers.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &nullifier)));
        }
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.output_commitment0,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.output_commitment1,
        )));
        if policy::requires_membership_proofs(policy_flags) {
            for _ in 0..proof.input_nullifiers.len() {
                public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
                    env,
                    &proof.asp_membership_root,
                )));
            }
        }
        if policy::requires_non_membership_proofs(policy_flags) {
            for _ in 0..proof.input_nullifiers.len() {
                public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
                    env,
                    &proof.asp_non_membership_root,
                )));
            }
        }

        // `try_verify`, not `verify`. `Groth16Error` and this contract's
        // `Error` are separate `#[repr(u32)]` enums whose codes overlap:
        // `MalformedPublicInputs` is 1 and so is `NotAuthorized`,
        // `MalformedProof` is 2 and so is `MerkleTreeFull`. A plain `verify`
        // lets a verifier rejection trap out of this frame carrying the
        // verifier's own code, and the caller reads that code against the
        // pool's enum — a refused proof arrives as an authorization failure.
        // Catching the call here keeps the pool's errors the pool's own.
        match client.try_verify(&proof.proof, &public_inputs) {
            Ok(Ok(is_valid)) => Ok(is_valid),
            _ => Err(Error::InvalidProof),
        }
    }

    /// Execute a shielded transaction with deposit handling
    ///
    /// This is the main entry point for users to interact with the pool.
    /// If `ext_amount > 0`, tokens are transferred from the sender to the
    /// pool only after the transaction has been fully verified
    /// (checks-effects-interactions: no token may move while any check can
    /// still fail).
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - Zero-knowledge proof and public inputs
    /// * `ext_data` - External transaction data
    /// * `sender` - Address of the transaction sender (must authorize funding
    ///   transaction)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if validation fails
    pub fn transact(
        env: &Env,
        proof: Proof,
        ext_data: ExtData,
        sender: Address,
    ) -> Result<(), Error> {
        sender.require_auth();
        // The tree entry is rewritten in `settle_transact` below; keep the
        // configuration it reads on the same lifetime.
        pool_core::extend_instance(env);

        // CHECKS: verify the transaction fully before any token moves.
        Self::verify_transact(env, &proof, &ext_data)?;

        // INTERACTION: collect the deposit only after every check has
        // passed, so a transaction that fails verification never even
        // attempts the transfer.
        let zero = I256::from_i32(env, 0);
        if ext_data.ext_amount > zero {
            let this = env.current_contract_address();
            let amount = amounts::require_i128_nonneg::<Error>(env, &ext_data.ext_amount)?;
            let token = Self::get_token(env)?;
            TokenClient::new(env, &token).transfer(&sender, &this, &amount);
        }

        // EFFECTS: spend nullifiers, pay out withdrawals, insert commitments.
        Self::settle_transact(env, proof, ext_data)
    }

    /// Verify a private transaction without mutating any state
    ///
    /// Validates the proof and all public inputs. Split from the
    /// bookkeeping so `transact` can run every check (including the ZK
    /// proof) before its deposit transfer — checks first, effects after.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - Zero-knowledge proof and public inputs
    /// * `ext_data` - External transaction data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if any validation fails
    ///
    /// # Validation Steps
    ///
    /// 1. Verify Merkle root is in recent history
    /// 2. Verify no nullifiers have been spent
    /// 3. Verify external data hash matches
    /// 4. Verify public amount calculation
    /// 5. Verify zero-knowledge proof
    fn verify_transact(env: &Env, proof: &Proof, ext_data: &ExtData) -> Result<(), Error> {
        // 0. Deposit bound check. Pure check, run ahead of everything else
        // so the error precedence matches the pre-split behavior (the bound
        // was the first thing checked after authorization).
        let zero = I256::from_i32(env, 0);
        if ext_data.ext_amount > zero {
            let deposit_u = U256::from_be_bytes(env, &ext_data.ext_amount.to_be_bytes());
            let max = Self::get_maximum_deposit(env)?;
            if deposit_u > max {
                return Err(Error::WrongExtAmount);
            }
        }
        // 1. Merkle root check
        if !MerkleTreeWithHistory::is_known_root(env, &proof.root)? {
            return Err(Error::UnknownRoot);
        }
        // 2. Nullifier checks (prevent double-spending)
        for n in proof.input_nullifiers.iter() {
            if Self::is_spent(env, &n)? {
                return Err(Error::AlreadySpentNullifier);
            }
        }
        // 3. External data hash check, bound to this pool's address and its
        // own configured token, so a hash computed for another pool or token
        // cannot match here.
        let token = Self::get_token(env)?;
        let ext_hash = hash_ext_data(env, ext_data, &token);
        if ext_hash != proof.ext_data_hash {
            return Err(Error::WrongExtHash);
        }

        // 4. Public amount check
        let expected_public_amount =
            amounts::require_public_amount::<Error>(env, ext_data.ext_amount.clone())?;
        if proof.public_amount != expected_public_amount {
            return Err(Error::WrongExtAmount);
        }

        // ASP root validation
        let policy_flags = Self::load_policy_flags(env)?;
        if policy::requires_non_membership_proofs(policy_flags) {
            let non_member_root = Self::get_asp_non_membership_root(env)?;
            if non_member_root != proof.asp_non_membership_root {
                return Err(Error::InvalidProof);
            }
        }
        if policy::requires_membership_proofs(policy_flags) {
            let member_root = Self::get_asp_membership_root(env)?;
            if member_root != proof.asp_membership_root {
                return Err(Error::InvalidProof);
            }
        }

        // 5. ZK proof verification
        if !Self::verify_proof(env, proof)? {
            return Err(Error::InvalidProof);
        }

        Ok(())
    }

    /// Apply a verified private transaction
    ///
    /// Marks nullifiers as spent, processes withdrawals, and inserts new
    /// commitments into the Merkle tree. Runs only after `verify_transact`
    /// accepted the transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - Zero-knowledge proof and public inputs (already verified)
    /// * `ext_data` - External transaction data (already verified)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success
    fn settle_transact(env: &Env, proof: Proof, ext_data: ExtData) -> Result<(), Error> {
        // 1. Mark nullifiers as spent
        for n in proof.input_nullifiers.iter() {
            storage::persistent_set_unit(env, &DataKey::Nullifier(n.clone()));
            NewNullifierEvent { nullifier: n }.publish(env);
        }

        // 2. Process withdrawal if ext_amount < 0
        let token = Self::get_token(env)?;
        let token_client = TokenClient::new(env, &token);
        let this = env.current_contract_address();
        let zero = I256::from_i32(env, 0);

        if ext_data.ext_amount < zero {
            let abs = zero.sub(&ext_data.ext_amount);
            let amount: i128 = amounts::require_i128_nonneg::<Error>(env, &abs)?;
            token_client.transfer(&this, &ext_data.recipient, &amount);
        }

        // 3. Insert new commitments into Merkle tree
        let (idx_0, idx_1) = MerkleTreeWithHistory::insert_two_leaves(
            env,
            proof.output_commitment0.clone(),
            proof.output_commitment1.clone(),
        )?;

        // 4. Emit commitment events
        NewCommitmentEvent {
            commitment: proof.output_commitment0,
            index: idx_0,
            encrypted_output: ext_data.encrypted_output0.clone(),
        }
        .publish(env);

        NewCommitmentEvent {
            commitment: proof.output_commitment1,
            index: idx_1,
            encrypted_output: ext_data.encrypted_output1.clone(),
        }
        .publish(env);

        Ok(())
    }

    // ========== Storage Getters and Setters ==========

    /// Get the token contract address
    fn get_token(env: &Env) -> Result<Address, Error> {
        storage::instance_get(env, &DataKey::Token)
    }

    /// Get the maximum deposit amount
    fn get_maximum_deposit(env: &Env) -> Result<U256, Error> {
        storage::instance_get(env, &DataKey::MaximumDepositAmount)
    }

    /// Get the verifier contract address
    fn get_verifier(env: &Env) -> Result<Address, Error> {
        storage::instance_get(env, &DataKey::Verifier)
    }

    /// Get the admin address
    fn get_admin(env: &Env) -> Result<Address, Error> {
        storage::persistent_get(env, &DataKey::Admin)
    }

    /// Get the pool's ASP policy flags.
    pub fn get_policy_flags(env: &Env) -> Result<u32, Error> {
        Self::load_policy_flags(env)
    }

    fn load_policy_flags(env: &Env) -> Result<u32, Error> {
        storage::instance_get(env, &DataKey::PolicyFlags)
    }

    /// Get the latest root of the Merkle tree that defines the pool
    pub fn get_root(env: &Env) -> Result<U256, Error> {
        Ok(MerkleTreeWithHistory::get_last_root(env)?)
    }

    /// Check whether a pool Merkle root is still in the recent root history.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `root` - Pool Merkle root to check
    pub fn is_known_root(env: &Env, root: &U256) -> Result<bool, Error> {
        Ok(MerkleTreeWithHistory::is_known_root(env, root)?)
    }

    /// Check whether a nullifier has already been spent.
    ///
    /// Presence of the per-nullifier storage key is the spent flag.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `n` - The nullifier to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the nullifier has been spent, `false` otherwise
    pub fn is_spent(env: &Env, n: &U256) -> Result<bool, Error> {
        Ok(storage::persistent_has(env, &DataKey::Nullifier(n.clone())))
    }

    /// Update the contract administrator
    ///
    /// Transfers administrative control to a new address. Requires
    /// authorization from the current admin.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_admin` - New address that will have administrative permissions
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored.
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin)
            .map_err(|soroban_utils::AdminError::NotInitialized| Error::NotInitialized)
    }

    // ========== ASP Contract Functions ==========

    /// Get the ASP Membership contract address
    fn get_asp_membership(env: &Env) -> Result<Address, Error> {
        storage::instance_get(env, &DataKey::ASPMembership)
    }

    /// Get the ASP Non-Membership contract address
    fn get_asp_non_membership(env: &Env) -> Result<Address, Error> {
        storage::instance_get(env, &DataKey::ASPNonMembership)
    }

    /// Update the ASP Membership contract address
    ///
    /// Changes the ASP Membership contract address. Requires admin
    /// authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_asp_membership` - New ASP Membership contract address
    pub fn update_asp_membership(env: &Env, new_asp_membership: Address) -> Result<(), Error> {
        let admin = Self::get_admin(env)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::ASPMembership, &new_asp_membership);
        Ok(())
    }

    /// Update the ASP Non-Membership contract address
    ///
    /// Changes the ASP Non-Membership contract address. Requires admin
    /// authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_asp_non_membership` - New ASP Non-Membership contract address
    pub fn update_asp_non_membership(
        env: &Env,
        new_asp_non_membership: Address,
    ) -> Result<(), Error> {
        let admin = Self::get_admin(env)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::ASPNonMembership, &new_asp_non_membership);
        Ok(())
    }

    /// Get the current Merkle root from the ASP Membership contract
    ///
    /// Makes a cross-contract call to retrieve the current root of the
    /// membership Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// The current membership Merkle root as U256
    pub fn get_asp_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_membership(env)?;
        let client = ASPMembershipClient::new(env, &asp_address);
        Ok(client.get_root())
    }

    /// Get the current Merkle root from the ASP Non-Membership contract
    ///
    /// Makes a cross-contract call to retrieve the current root of the
    /// non-membership Sparse Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// The current non-membership Merkle root as U256
    pub fn get_asp_non_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_non_membership(env)?;
        let client = ASPNonMembershipClient::new(env, &asp_address);
        Ok(client.get_root())
    }
}
