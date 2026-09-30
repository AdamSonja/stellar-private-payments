//! Async per-pool private payments API

use anyhow::Context;

use crate::{
    planner::{SpendableNote, Transact},
    types::{EncryptionPublicKey, NoteAmount, NotePublicKey, Sensitive, UserNoteSummary},
};

use crate::chain::{Limits, ReadXdr, StateFetcher, TransactionEnvelope, submit_tx};

use crate::{
    PreparedTransaction,
    chain::RpcClient,
    core::{PoolCore, pool_transact_input, transact_step_for_plan},
    correlation::correlation_id_or_new,
    disclosure::{
        DisclosureInputsRequest, DisclosureProveParams, DisclosureRequest,
        verify_disclosure_receipt_with_context,
    },
    error::{Error, PlanExecutionError},
    gvk::GvkAudit,
    handle::Handle,
    plan::PreparedTransactionPlan,
    prover::Prover,
    signer::Signer,
    sleep::sleep,
    storage::Storage,
    sync::{SyncHandle, confirm_tx},
    transact::transact_request_from_step,
    types::{
        AspMembershipSync, DisclosureContext, DisclosureReceipt, DisclosureVerificationReport,
        Estimate, ExpectedContext, Field, GvkMode, PrivatePoolConfig, SignedTransaction,
        TransactChainContext, TransactionResult, TransferRecipient,
    },
};

const POLL_INTERVAL_MS: u32 = 200;
const SYNC_MAX_RETRIES: u32 = 50;
const DISCLOSE_MAX_RETRIES: u32 = 50;

/// Main entry point for a single privacy pool.
///
/// Construct via [`crate::Account::pool`].
pub struct PrivatePool {
    rpc: RpcClient,
    config: PrivatePoolConfig,
    core: PoolCore,
    fetcher: StateFetcher,
    storage: Handle<dyn Storage>,
    prover: Handle<dyn Prover>,
    signer: Handle<dyn Signer>,
    sync: SyncHandle,
}

impl PrivatePool {
    pub(crate) fn init(
        rpc: RpcClient,
        config: PrivatePoolConfig,
        storage: Handle<dyn Storage>,
        signer: Handle<dyn Signer>,
        prover: Handle<dyn Prover>,
        sync: SyncHandle,
    ) -> Result<Self, Error> {
        config.validate()?;
        let fetcher = StateFetcher::new(rpc.clone(), config.contract_config.clone())
            .context("state fetcher")?;
        Ok(Self {
            rpc,
            core: PoolCore::new(config.clone())?,
            config,
            fetcher,
            storage,
            prover,
            signer,
            sync,
        })
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        &self.config
    }
}

impl PrivatePool {
    // high level methods

    pub async fn balance(&self) -> Result<NoteAmount, Error> {
        let wallet = self.spendable_notes().await?;
        wallet
            .iter()
            .map(|note| note.amount)
            .try_fold(NoteAmount::ZERO, |sum, amount| {
                sum.checked_add(amount)
                    .ok_or_else(|| Error::Other(anyhow::anyhow!("wallet balance overflow")))
            })
    }

    pub async fn notes(&self) -> Result<Vec<UserNoteSummary>, Error> {
        self.ensure_synced().await?;
        self.storage
            .notes(
                &self.config.pool_contract_id,
                self.config.user_address.as_str(),
            )
            .await
    }

    pub async fn estimate(&self, amount: NoteAmount) -> Result<Estimate, Error> {
        let wallet = self.spendable_notes().await?;
        self.core.estimate(&wallet, amount)
    }

    #[tracing::instrument(skip(self), fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(amount)))]
    pub async fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, Error> {
        tracing::info!(amount = ?Sensitive(amount), "deposit started");
        let mut plan = self.prepare_deposit(amount)?;
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("deposit produced no transaction")))
    }

    #[tracing::instrument(skip(self, recipient), fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(amount)))]
    pub async fn transfer(
        &self,
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, Error> {
        let recipient = recipient.into();
        tracing::info!(recipient = ?Sensitive(&recipient), amount = ?Sensitive(amount), "transfer started");
        let wallet = self.spendable_notes().await?;
        let mut plan = self.prepare_transfer(&wallet, recipient, amount).await?;
        self.execute(&mut plan).await
    }

    #[tracing::instrument(skip(self, recipient), fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(amount)))]
    pub async fn withdraw(
        &self,
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, Error> {
        let recipient = recipient.into();
        tracing::info!(amount = ?Sensitive(amount), recipient = ?Sensitive(&recipient), "withdraw started");
        let wallet = self.spendable_notes().await?;
        let mut plan = self.prepare_withdraw(&wallet, amount, recipient)?;
        self.execute(&mut plan).await
    }

    #[tracing::instrument(skip(self, step), fields(correlation_id = %correlation_id_or_new()))]
    pub async fn transact(&self, step: Transact) -> Result<TransactionResult, Error> {
        tracing::info!(step = ?Sensitive(&step), "transact started");
        let mut plan = self.prepare_transact(step);
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("transact produced no transaction")))
    }

    #[tracing::instrument(skip(self, req), fields(correlation_id = %correlation_id_or_new()))]
    pub async fn disclose(
        &self,
        req: DisclosureRequest,
    ) -> Result<Option<DisclosureReceipt>, Error> {
        tracing::info!(selected_commitments = ?Sensitive(&req.selected_commitments), "disclose started");
        if req.selected_commitments.is_empty() || req.selected_commitments.len() > 4 {
            return Err(Error::Other(anyhow::anyhow!(
                "selective disclosure requires 1..=4 selected commitments"
            )));
        }

        let selected_commitments = req.selected_commitments;
        let mut sync_waits = 0u32;
        loop {
            let data = self
                .fetcher
                .contracts_data_for_pool(&self.config.pool_contract_id)
                .await
                .context("fetch chain context")?;

            let pool = data.pools.into_iter().next().ok_or_else(|| {
                Error::Other(anyhow::anyhow!(
                    "pool {} not found in contract state",
                    self.config.pool_contract_id
                ))
            })?;
            let pool_root = pool
                .merkle_root
                .ok_or_else(|| Error::Other(anyhow::anyhow!("pool merkle_root not fetched")))?;
            let pool_next_index = pool
                .merkle_next_index
                .parse::<u32>()
                .context("invalid pool merkle_next_index")?;

            let inputs_req = DisclosureInputsRequest {
                user_address: self.config.user_address.as_str().to_string(),
                pool_address: self.config.pool_contract_id.clone(),
                selected_commitments: selected_commitments.clone(),
                pool_root: Some(pool_root),
                pool_next_index,
                tree_depth: pool.merkle_levels,
            };

            match self.storage.build_disclosure_inputs(&inputs_req).await {
                Ok(notes) => {
                    let context = DisclosureContext {
                        network: self.fetcher.contract_config().network.clone(),
                        pool_address: pool.contract_id,
                        authority_label: req.authority_label,
                        authority_identity_payload_hex: req.authority_identity_payload_hex,
                        purpose: req.purpose,
                        context_nonce: req.context_nonce,
                    };
                    let receipt = self
                        .prover
                        .prove_disclosure(DisclosureProveParams { notes, context })
                        .await?;
                    return Ok(Some(receipt));
                }
                Err(Error::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                    return Ok(None);
                }
                Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                    sync_waits = sync_waits.saturating_add(1);
                    if sync_waits > DISCLOSE_MAX_RETRIES {
                        return Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap)));
                    }
                    self.ensure_synced().await?;
                    sleep(POLL_INTERVAL_MS).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[tracing::instrument(skip(self, receipt, expected_vk_hash), fields(correlation_id = %correlation_id_or_new()))]
    pub async fn verify_disclosure(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<DisclosureVerificationReport, Error> {
        tracing::info!(expected_vk_hash = ?Sensitive(expected_vk_hash), "verify_disclosure started");
        let expected_context = ExpectedContext {
            network: self.fetcher.contract_config().network.clone(),
            pool_address: self.config.pool_contract_id.clone(),
            authority: None,
        };
        verify_disclosure_receipt_with_context(
            &self.fetcher,
            self.prover.as_ref(),
            receipt,
            expected_vk_hash,
            Some(&expected_context),
        )
        .await
    }

    pub async fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), Error> {
        let chain_config = self.core.config();
        prepared.soroban_tx = self
            .fetcher
            .prepare_pool_transact(
                &chain_config.pool_contract_id,
                &pool_transact_input(prepared),
                // The signing address becomes the contract's `sender`, the
                // sequence-number lookup and the envelope source.
                &chain_config.signer_address,
            )
            .await
            .context("simulate transaction")?;

        Ok(())
    }

    pub async fn audit(&self, global_view_private_key: Field) -> Result<GvkAudit, Error> {
        let pool = self
            .config
            .contract_config
            .pool(&self.config.pool_contract_id)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        if pool.gvk_mode == GvkMode::Off {
            return Err(Error::InvalidConfig(format!(
                "GVK audit requires a pool-gvk deployment; {} is configured with gvk_mode Off",
                self.config.pool_contract_id
            )));
        }
        crate::types::validate_gvk_authority_key(&global_view_private_key, pool)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        self.ensure_synced().await?;

        let storage = self.storage.fork()?;
        let pool_contract_id = self.config.pool_contract_id.clone();
        Ok(GvkAudit::new(
            storage,
            pool_contract_id,
            global_view_private_key,
        ))
    }

    // lower level methods

    pub async fn spendable_notes(&self) -> Result<Vec<SpendableNote>, Error> {
        self.ensure_synced().await?;
        self.storage
            .spendable_notes(
                &self.config.pool_contract_id,
                self.config.user_address.as_str(),
            )
            .await
    }

    pub fn prepare_deposit(&self, amount: NoteAmount) -> Result<PreparedTransactionPlan, Error> {
        self.core.prepare_deposit(amount)
    }

    pub async fn prepare_transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, Error> {
        let (note_public_key, encryption_public_key) =
            self.resolve_transfer_recipient(recipient.into()).await?;
        self.core
            .prepare_transfer(wallet, note_public_key, encryption_public_key, amount)
    }

    pub fn prepare_withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<PreparedTransactionPlan, Error> {
        self.core.prepare_withdraw(wallet, amount, recipient)
    }

    pub fn prepare_transact(&self, step: Transact) -> PreparedTransactionPlan {
        PreparedTransactionPlan::from_transact(step)
    }

    pub async fn prove_next(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, Error> {
        self.next_prepared_transaction(plan).await
    }

    pub async fn submit(&self, signed_tx: SignedTransaction) -> Result<String, Error> {
        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .context("invalid signed transaction xdr")?;

        submit_tx(&self.rpc, &envelope)
            .await
            .context("submit transaction")
            .map_err(Into::into)
    }

    pub async fn confirm(&self, hash: &str) -> Result<TransactionResult, Error> {
        confirm_tx(&self.rpc, hash).await
    }

    pub async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, Error> {
        self.signer.sign_transaction(prepared).await
    }

    // helpers

    async fn ensure_synced(&self) -> Result<(), Error> {
        self.sync
            .ensure_synced(
                &self.rpc,
                self.storage.as_ref(),
                &self.config.contract_config,
            )
            .await
    }

    async fn resolve_transfer_recipient(
        &self,
        recipient: TransferRecipient,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        match recipient {
            TransferRecipient::Keys {
                note_public_key,
                encryption_public_key,
            } => Ok((note_public_key, encryption_public_key)),
            TransferRecipient::Address(address) => {
                self.ensure_synced().await?;
                self.storage
                    .registered_privacy_keys(
                        &address,
                        &self.config.contract_config.public_key_registry,
                    )
                    .await
            }
        }
    }

    async fn next_prepared_transaction(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, Error> {
        if plan.is_complete() {
            return Err(Error::Other(anyhow::anyhow!(
                "transaction plan is complete"
            )));
        }
        self.ensure_synced().await?;

        let chain = self.fetch_transact_chain_context().await?;
        let step = if let Some(amount) = plan.deposit_amount() {
            self.deposit_transact_step(amount).await?
        } else if let Some(step) = plan.raw_transact_step() {
            step.clone()
        } else {
            transact_step_for_plan(plan)?
        };
        let req = transact_request_from_step(
            &step,
            self.config.user_address.as_str(),
            &self.config.pool_contract_id,
            &chain,
        );

        let params = self.storage.build_transact_params(&req).await?;
        let prepared = self.prover.prove_transact(params).await?;

        plan.finish_proved_tx(&prepared.prepared.output_commitments)?;
        Ok(prepared)
    }

    async fn fetch_transact_chain_context(&self) -> Result<TransactChainContext, Error> {
        let (note_pub, _) = self
            .storage
            .privacy_keys(self.config.user_address.as_str())
            .await?;
        self.fetcher
            .transact_chain_context(
                &self.config.pool_contract_id,
                &note_pub,
                self.config.user_address.as_str(),
            )
            .await
            .context("fetch chain context")
            .map_err(Into::into)
    }

    async fn execute(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<Vec<TransactionResult>, Error> {
        let mut results = Vec::new();
        while !plan.is_complete() {
            let step_index = results.len();
            tracing::info!(step_index, "execute plan step");
            let mut prepared = {
                let mut sync_waits = 0u32;
                loop {
                    match self.prove_next(plan).await {
                        Ok(prepared) => break prepared,
                        Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                            sync_waits = sync_waits.saturating_add(1);
                            if sync_waits > SYNC_MAX_RETRIES {
                                return Err(PlanExecutionError::into_error(
                                    results,
                                    Error::MembershipSync(AspMembershipSync::SyncRequired(gap)),
                                ));
                            }
                            if let Err(error) = self.ensure_synced().await {
                                return Err(PlanExecutionError::into_error(results, error));
                            }
                            sleep(POLL_INTERVAL_MS).await;
                        }
                        Err(error) => return Err(PlanExecutionError::into_error(results, error)),
                    }
                }
            };
            if let Err(error) = self.simulate(&mut prepared).await {
                return Err(PlanExecutionError::into_error(results, error));
            }
            let signed = match self.sign(&prepared).await {
                Ok(signed) => signed,
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            let hash = match self.submit(signed).await {
                Ok(hash) => {
                    tracing::info!(hash, "transaction submitted");
                    hash
                }
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            let result = match self.confirm(&hash).await {
                Ok(result) => {
                    tracing::info!(hash, "transaction confirmed");
                    result
                }
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            results.push(result);
        }
        Ok(results)
    }

    async fn deposit_transact_step(&self, amount: NoteAmount) -> Result<Transact, Error> {
        let (note_pub, enc_pub) = self
            .storage
            .privacy_keys(self.config.user_address.as_str())
            .await?;
        self.core.deposit_transact_step(note_pub, enc_pub, amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::LocalStorage,
        types::{
            AssetDescriptor, AuthorityStatus, ContextMismatchReason, DISCLOSURE_RECEIPT_VERSION,
            DisclosureCircuitMetadata, DisclosureContext, DisclosurePublicInputs, Field,
            KeyDerivationSignature, PoolConfigEntry, SELECTIVE_DISCLOSURE_1_CIRCUIT,
            SELECTIVE_DISCLOSURE_1_LEVELS, SELECTIVE_DISCLOSURE_1_N_NOTES, SignerAddress, U256,
        },
        zk::disclosure::{derive_ext_context_hash, validate_registered_receipt},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use stellar_xdr::{self as xdr, WriteXdr};
    use wiremock::{Mock, MockServer, Respond, ResponseTemplate, matchers::method};

    const VK_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const POOL_A: &str = "CCM5G4FCOV7PLKFMEJBCYM5R7JOTZVUXKWBDR3SWCW2IM2LKNNBO4TH5";
    const POOL_B: &str = "CAADTTZWMNAABQOOTGRYLPEKWGMQT746A4EF7JWMBY5TJTMUNQYB4UZ3";
    const USER_ADDRESS: &str = "GDZT6XVSNIGMTL34KS46RM3D26GPWM4POMCBYL7FUIQXRMSVUALSWRBE";

    struct TestProver;

    #[async_trait::async_trait(?Send)]
    impl Prover for TestProver {
        async fn prove_transact(
            &self,
            _params: crate::zk::flows::TransactParams,
        ) -> Result<crate::transact::PreparedProverTx, Error> {
            unreachable!()
        }

        async fn prove_disclosure(
            &self,
            _params: DisclosureProveParams,
        ) -> Result<DisclosureReceipt, Error> {
            unreachable!()
        }

        async fn verify_disclosure_proof(
            &self,
            receipt: &DisclosureReceipt,
            expected_vk_hash: &str,
        ) -> Result<bool, Error> {
            validate_registered_receipt(receipt, expected_vk_hash)
                .map_err(|e| Error::Other(anyhow::anyhow!(e)))?;
            Ok(true)
        }
    }

    struct TestSigner;

    #[async_trait::async_trait(?Send)]
    impl Signer for TestSigner {
        fn signer_address(&self) -> SignerAddress {
            SignerAddress::new(USER_ADDRESS)
        }

        async fn sign_transaction(
            &self,
            _prepared: &PreparedTransaction,
        ) -> Result<SignedTransaction, Error> {
            unreachable!()
        }

        async fn sign_message(&self, _message: &str) -> Result<KeyDerivationSignature, Error> {
            unreachable!()
        }
    }

    struct SimResponder;

    impl Respond for SimResponder {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let json: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let mut is_spent = false;
            let tx_b64 = json["params"]["transaction"]
                .as_str()
                .or_else(|| json["params"][0].as_str());
            if let Some(b64) = tx_b64
                && let Ok(xdr::TransactionEnvelope::Tx(tx)) =
                    xdr::TransactionEnvelope::from_xdr_base64(b64, xdr::Limits::none())
                && let Some(op) = tx.tx.operations.first()
                && let xdr::OperationBody::InvokeHostFunction(invoke) = &op.body
                && let xdr::HostFunction::InvokeContract(args) = &invoke.host_function
                && args.function_name.0.as_slice() == b"is_spent"
            {
                is_spent = true;
            }

            let retval = xdr::ScVal::Bool(!is_spent)
                .to_xdr_base64(xdr::Limits::none())
                .expect("xdr");

            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 1,
                    "results": [{
                        "retval": retval
                    }]
                }
            }))
        }
    }

    fn field(v: u64) -> Field {
        Field(U256::from(v))
    }

    fn valid_verified_receipt_for_pool(pool_address: &str) -> DisclosureReceipt {
        let mut receipt = DisclosureReceipt {
            version: DISCLOSURE_RECEIPT_VERSION,
            circuit: DisclosureCircuitMetadata {
                name: SELECTIVE_DISCLOSURE_1_CIRCUIT.to_string(),
                levels: SELECTIVE_DISCLOSURE_1_LEVELS,
                n_notes: SELECTIVE_DISCLOSURE_1_N_NOTES,
                vk_hash: VK_HASH.to_string(),
            },
            context: DisclosureContext {
                network: "testnet".to_string(),
                pool_address: pool_address.to_string(),
                authority_label: "Authority XYZ".to_string(),
                authority_identity_payload_hex: "0x617574686f72697479".to_string(),
                purpose: "kyc-review".to_string(),
                context_nonce: field(7),
            },
            public_inputs: DisclosurePublicInputs {
                roots: vec![field(1)],
                note_commitments: vec![field(2)],
                ext_context_hash: field(3),
                nullifiers: vec![field(4)],
                amounts: vec![field(5)],
            },
            proof_compressed_hex: format!("0x{}", "aa".repeat(128)),
            issued_at: "2026-05-19T14:00:00Z".to_string(),
        };
        receipt.public_inputs.ext_context_hash =
            derive_ext_context_hash(&receipt.context).expect("derive hash");
        receipt
    }

    use crate::{handle::Handle, storage::Storage};
    async fn create_test_pool(server: &MockServer) -> PrivatePool {
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "spp-pool-verify-test-{}-{}.sqlite",
            std::process::id(),
            RUN.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&db);
        let storage = LocalStorage::open(db.to_string_lossy().as_ref()).expect("open storage");

        let contract_config = crate::types::ContractConfig {
            network: "testnet".to_string(),
            deployer: USER_ADDRESS.to_string(),
            admin: String::new(),
            asp_membership: String::new(),
            asp_non_membership: String::new(),
            verifiers: Default::default(),
            public_key_registry: String::new(),
            pools: vec![PoolConfigEntry {
                pool_contract_id: POOL_A.to_string(),
                token_contract_id: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
                    .to_string(),
                deployment_ledger: 1,
                enabled: true,
                policy_flags: crate::types::PolicyFlags::EMPTY,
                asset: AssetDescriptor::Native,
                gvk_mode: crate::types::GvkMode::Off,
                gvk_authority_pub_key: None,
            }],
        };

        let config = PrivatePoolConfig {
            contract_config,
            pool_contract_id: POOL_A.to_string(),
            user_address: crate::types::NoteOwnerAddress::new(USER_ADDRESS),
            signer_address: SignerAddress::new(USER_ADDRESS),
        };

        let rpc = RpcClient::new(&server.uri()).expect("rpc client");
        let signer = Handle::from_box(Box::new(TestSigner) as Box<dyn Signer>);
        let prover = Handle::from_box(Box::new(TestProver) as Box<dyn Prover>);
        let sync = SyncHandle::inline(None);

        let storage: Handle<dyn Storage> = {
            let boxed: Box<dyn Storage> = Box::new(storage);
            Handle::from(boxed)
        };

        PrivatePool::init(rpc, config, storage, signer, prover, sync).expect("init pool")
    }

    #[tokio::test]
    async fn verify_disclosure_valid_receipt_for_configured_pool() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(SimResponder)
            .mount(&server)
            .await;

        let pool = create_test_pool(&server).await;
        let receipt = valid_verified_receipt_for_pool(POOL_A);

        let report = pool
            .verify_disclosure(&receipt, VK_HASH)
            .await
            .expect("verify disclosure");

        assert!(report.is_cryptographically_valid());
        assert_eq!(report.authority_status, AuthorityStatus::Unchecked);
        assert!(report.context_mismatches.is_empty());
        assert!(report.proof_verified);
        assert!(report.context_verified);
        assert!(report.known_root_status);
        assert!(report.nullifiers_unspent);
    }

    #[tokio::test]
    async fn verify_disclosure_receipt_for_different_pool_address() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(SimResponder)
            .mount(&server)
            .await;

        let pool = create_test_pool(&server).await;
        let receipt = valid_verified_receipt_for_pool(POOL_B);

        let report = pool
            .verify_disclosure(&receipt, VK_HASH)
            .await
            .expect("verify disclosure");

        assert!(!report.is_cryptographically_valid());
        assert_eq!(
            report.context_mismatches,
            vec![ContextMismatchReason::PoolMismatch]
        );
        assert_eq!(report.authority_status, AuthorityStatus::Unchecked);
        assert!(report.proof_verified);
        assert!(report.context_verified);
    }

    #[tokio::test]
    async fn verify_disclosure_malformed_pool_address_returns_mismatch() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(SimResponder)
            .mount(&server)
            .await;

        let pool = create_test_pool(&server).await;
        let receipt = valid_verified_receipt_for_pool("invalid-pool-address");

        let report = pool
            .verify_disclosure(&receipt, VK_HASH)
            .await
            .expect("verify disclosure");

        assert!(!report.is_cryptographically_valid());
        assert_eq!(
            report.context_mismatches,
            vec![ContextMismatchReason::PoolMismatch]
        );
        assert_eq!(report.authority_status, AuthorityStatus::Unchecked);
        assert!(report.proof_verified);
        assert!(report.context_verified);
    }
}
