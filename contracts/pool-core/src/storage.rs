//! Generic storage accessors shared by `pool` and `pool-gvk`.
//!
//! Each contract keeps its own `DataKey` enum (`pool-gvk`'s carries the
//! extra GVK variants), so — like `soroban_utils::update_admin` — every
//! helper here is generic over the caller's key type and maps failures onto
//! the caller's error domain through [`PoolError`].

use core::fmt::Debug;

use soroban_sdk::{Env, IntoVal, TryFromVal, Val};

use crate::error::PoolError;

/// Read a value from the contract's instance storage.
///
/// # Errors
///
/// Returns [`PoolError::not_initialized`] if the key is absent.
pub fn instance_get<K, V, E>(env: &Env, key: &K) -> Result<V, E>
where
    K: IntoVal<Env, Val>,
    V: TryFromVal<Env, Val>,
    V::Error: Debug,
    E: PoolError,
{
    env.storage()
        .instance()
        .get(key)
        .ok_or_else(E::not_initialized)
}

/// Read a value from the contract's persistent storage.
///
/// # Errors
///
/// Returns [`PoolError::not_initialized`] if the key is absent.
pub fn persistent_get<K, V, E>(env: &Env, key: &K) -> Result<V, E>
where
    K: IntoVal<Env, Val>,
    V: TryFromVal<Env, Val>,
    V::Error: Debug,
    E: PoolError,
{
    env.storage()
        .persistent()
        .get(key)
        .ok_or_else(E::not_initialized)
}

/// Whether a key is present in the contract's persistent storage.
pub fn persistent_has<K>(env: &Env, key: &K) -> bool
where
    K: IntoVal<Env, Val>,
{
    env.storage().persistent().has(key)
}

/// Set a presence-only flag in persistent storage: the key is the flag and
/// the unit value is unused. This is how a nullifier is marked spent.
pub fn persistent_set_unit<K>(env: &Env, key: &K)
where
    K: IntoVal<Env, Val>,
{
    env.storage().persistent().set(key, &());
}
