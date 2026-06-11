//! Validator staking, unbonding, jailing, and slashing primitives for TruthLinked.
//!
//! The staking model keeps validator eligibility, active stake, unbonding queues,
//! and slash evidence explicit so consensus liveness and stake-weighted decisions
//! can be audited from state.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use truthlinked_core::constants::{
    JAIL_DURATION_BLOCKS, MAX_UNBONDING_ENTRIES, MAX_VALIDATOR_STAKE, MIN_VALIDATOR_STAKE,
    UNBONDING_TICKS,
};
use truthlinked_governance::params as gp;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlashReason {
    DoubleSign,
    InvalidStateRoot,
    Downtime,
    InvalidSnapshot,
    Censorship,
    /// Validator committed to an oracle response then revealed fabricated data.
    /// Cryptographically provable: reveal hash != commit hash stored on-chain.
    OracleLie,
    /// Validator committed to an oracle request but never revealed within the deadline.
    /// Liveness infraction. Evidence: request_id that expired unrevealed.
    OracleSilence {
        request_id: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator_pubkey: Vec<u8>,
    pub height: u64,
    pub batch_hash_1: [u8; 32],
    pub batch_hash_2: [u8; 32],
    pub signature_1: Vec<u8>,
    pub signature_2: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorStake {
    pub active_stake: u64,
    pub unbonding: Vec<UnbondingEntry>,
    pub jailed_until: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnbondingEntry {
    pub amount: u64,
    pub completion_tick: u64, // Time-based unbonding tick
}

impl ValidatorStake {
    pub fn new(stake: u64) -> Self {
        Self {
            active_stake: stake,
            unbonding: Vec::new(),
            jailed_until: None,
        }
    }

    pub fn total_stake(&self) -> u64 {
        self.active_stake + self.unbonding.iter().map(|e| e.amount).sum::<u64>()
    }

    pub fn is_active(&self, current_height: u64) -> bool {
        if let Some(jail_height) = self.jailed_until {
            if current_height < jail_height {
                return false;
            }
        }
        self.active_stake >= MIN_VALIDATOR_STAKE
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingState {
    pub validators: std::collections::BTreeMap<Vec<u8>, ValidatorStake>,
    pub current_height: u64,
    /// Treasury account that receives slashed tokens when no other validators are eligible.
    #[serde(default)]
    pub treasury_account_id: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct SlashOutcome {
    pub amount: u64,
    pub redistribution: Vec<(Vec<u8>, u64)>,
}

impl StakingState {
    pub fn new() -> Self {
        Self {
            validators: std::collections::BTreeMap::new(),
            current_height: 0,
            treasury_account_id: None,
        }
    }

    pub fn stake(&mut self, validator_pubkey: Vec<u8>, amount: u64) -> Result<(), String> {
        if amount < MIN_VALIDATOR_STAKE {
            return Err(format!(
                "Stake below minimum: {} < {}",
                amount, MIN_VALIDATOR_STAKE
            ));
        }

        let stake = self
            .validators
            .entry(validator_pubkey)
            .or_insert_with(|| ValidatorStake::new(0));

        let new_stake = stake
            .active_stake
            .checked_add(amount)
            .ok_or("Stake overflow")?;

        if new_stake > MAX_VALIDATOR_STAKE {
            return Err("Exceeds maximum validator stake".to_string());
        }

        stake.active_stake = new_stake;

        Ok(())
    }

    pub fn unstake(&mut self, validator_pubkey: &[u8], amount: u64) -> Result<(), String> {
        let stake = self
            .validators
            .get_mut(validator_pubkey)
            .ok_or("Validator not found")?;

        // CRITICAL FIX: Auto-withdraw mature entries if at limit
        if stake.unbonding.len() >= MAX_UNBONDING_ENTRIES {
            let mut auto_withdrawn = 0u64;
            stake.unbonding.retain(|entry| {
                if self.current_height >= entry.completion_tick {
                    auto_withdrawn += entry.amount;
                    false
                } else {
                    true
                }
            });

            if auto_withdrawn > 0 {
                tracing::info!(
                    "Auto-withdrew {} from {} mature unbonding entries",
                    auto_withdrawn,
                    MAX_UNBONDING_ENTRIES - stake.unbonding.len()
                );
            }

            if stake.unbonding.len() >= MAX_UNBONDING_ENTRIES {
                return Err("Too many unbonding entries, withdraw first".to_string());
            }
        }

        if amount > stake.active_stake {
            return Err("Insufficient active stake".to_string());
        }

        let remaining = stake.active_stake - amount;
        if remaining > 0 && remaining < MIN_VALIDATOR_STAKE {
            return Err("Unstaking would leave stake below minimum (must unstake all)".to_string());
        }

        stake.active_stake = remaining;
        stake.unbonding.push(UnbondingEntry {
            amount,
            completion_tick: self.current_height + UNBONDING_TICKS,
        });

        Ok(())
    }

    pub fn withdraw(&mut self, validator_pubkey: &[u8]) -> Result<u64, String> {
        let stake = self
            .validators
            .get_mut(validator_pubkey)
            .ok_or("Validator not found")?;

        let mut total_withdrawn = 0u64;
        stake.unbonding.retain(|entry| {
            if self.current_height >= entry.completion_tick {
                total_withdrawn += entry.amount;
                false
            } else {
                true
            }
        });

        if total_withdrawn == 0 {
            return Err("No unbonded stake available".to_string());
        }

        if stake.active_stake == 0 && stake.unbonding.is_empty() && stake.jailed_until.is_none() {
            self.validators.remove(validator_pubkey);
        }

        Ok(total_withdrawn)
    }

    pub fn get_active_validators(&self) -> HashMap<Vec<u8>, u64> {
        self.validators
            .iter()
            .filter(|(_, stake)| stake.is_active(self.current_height))
            .map(|(pk, stake)| (pk.clone(), stake.active_stake))
            .collect()
    }

    pub fn advance_height(&mut self) {
        self.current_height += 1;
    }

    pub fn compute_slash_outcome(
        &self,
        validator_pubkey: &[u8],
        reason: SlashReason,
        evidence: Option<DoubleSignEvidence>,
    ) -> Result<SlashOutcome, String> {
        if reason == SlashReason::DoubleSign {
            let ev = evidence.ok_or("Double-sign requires evidence")?;
            self.verify_double_sign_evidence(&ev)?;
        }

        let stake = self
            .validators
            .get(validator_pubkey)
            .ok_or("Validator not found")?;

        let percentage = match &reason {
            SlashReason::DoubleSign => gp::get_u64(gp::PARAM_SLASH_PERCENTAGE),
            SlashReason::InvalidStateRoot => gp::get_u64(gp::PARAM_SLASH_PERCENTAGE),
            SlashReason::InvalidSnapshot => gp::get_u64(gp::PARAM_SLASH_PERCENTAGE),
            SlashReason::Downtime => gp::get_u64(gp::PARAM_DOWNTIME_SLASH_PERCENTAGE),
            SlashReason::Censorship => gp::get_u64(gp::PARAM_CENSORSHIP_SLASH_PERCENTAGE),
            SlashReason::OracleLie => gp::get_u64(gp::PARAM_ORACLE_LIE_SLASH_PERCENTAGE),
            SlashReason::OracleSilence { .. } => {
                gp::get_u64(gp::PARAM_ORACLE_SILENCE_SLASH_PERCENTAGE)
            }
        };

        if stake.active_stake == 0 {
            return Err("No stake to slash".to_string());
        }
        let mut slash_amount = (stake.active_stake * percentage) / 100;
        if slash_amount == 0 {
            slash_amount = 1;
        }
        if slash_amount > stake.active_stake {
            slash_amount = stake.active_stake;
        }

        let redistribution = self.compute_redistribution(validator_pubkey, slash_amount)?;
        Ok(SlashOutcome {
            amount: slash_amount,
            redistribution,
        })
    }

    pub fn apply_slash_outcome(
        &mut self,
        validator_pubkey: &[u8],
        reason: SlashReason,
        outcome: &SlashOutcome,
        evidence: Option<DoubleSignEvidence>,
    ) -> Result<(), String> {
        if reason == SlashReason::DoubleSign {
            let ev = evidence.ok_or("Double-sign requires evidence")?;
            self.verify_double_sign_evidence(&ev)?;
        }
        let stake = self
            .validators
            .get_mut(validator_pubkey)
            .ok_or("Validator not found")?;
        if outcome.amount == 0 {
            return Err("No stake to slash".to_string());
        }
        if outcome.amount > stake.active_stake {
            return Err("Slash amount exceeds active stake".to_string());
        }
        stake.active_stake = stake.active_stake.saturating_sub(outcome.amount);
        stake.jailed_until = Some(self.current_height + JAIL_DURATION_BLOCKS);

        tracing::warn!(
            "Slashed validator {} for {:?}: {} tokens ({}%), jailed until height {}",
            hex::encode(&validator_pubkey[..8]),
            reason,
            outcome.amount,
            match &reason {
                SlashReason::DoubleSign => gp::get_u64(gp::PARAM_SLASH_PERCENTAGE),
                SlashReason::InvalidStateRoot => gp::get_u64(gp::PARAM_SLASH_PERCENTAGE),
                SlashReason::InvalidSnapshot => gp::get_u64(gp::PARAM_SLASH_PERCENTAGE),
                SlashReason::Downtime => gp::get_u64(gp::PARAM_DOWNTIME_SLASH_PERCENTAGE),
                SlashReason::Censorship => gp::get_u64(gp::PARAM_CENSORSHIP_SLASH_PERCENTAGE),
                SlashReason::OracleLie => gp::get_u64(gp::PARAM_ORACLE_LIE_SLASH_PERCENTAGE),
                SlashReason::OracleSilence { .. } =>
                    gp::get_u64(gp::PARAM_ORACLE_SILENCE_SLASH_PERCENTAGE),
            },
            self.current_height + JAIL_DURATION_BLOCKS
        );

        self.apply_redistribution(&outcome.redistribution);
        Ok(())
    }

    pub fn slash_validator(
        &mut self,
        validator_pubkey: &[u8],
        reason: SlashReason,
        evidence: Option<DoubleSignEvidence>,
    ) -> Result<SlashOutcome, String> {
        let outcome =
            self.compute_slash_outcome(validator_pubkey, reason.clone(), evidence.clone())?;
        self.apply_slash_outcome(validator_pubkey, reason, &outcome, evidence)?;
        Ok(outcome)
    }

    fn verify_double_sign_evidence(&self, evidence: &DoubleSignEvidence) -> Result<(), String> {
        use fips204::ml_dsa_65;
        use fips204::traits::{SerDes, Verifier};

        // Must be different batches at same height
        if evidence.batch_hash_1 == evidence.batch_hash_2 {
            return Err("Evidence must show two different batches".to_string());
        }

        // Reconstruct attestation messages
        let msg1 = Self::attestation_message(evidence.height, &evidence.batch_hash_1);
        let msg2 = Self::attestation_message(evidence.height, &evidence.batch_hash_2);

        // Verify both signatures with validator's pubkey
        let pk_bytes: [u8; 1952] = evidence
            .validator_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid pubkey length")?;
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|_| "Invalid pubkey")?;

        let sig1: [u8; 3309] = evidence
            .signature_1
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature 1 length")?;
        let sig2: [u8; 3309] = evidence
            .signature_2
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature 2 length")?;

        if !pk.verify(&msg1, &sig1, b"truthlinked-attestation-v1") {
            return Err("Signature 1 verification failed".to_string());
        }
        if !pk.verify(&msg2, &sig2, b"truthlinked-attestation-v1") {
            return Err("Signature 2 verification failed".to_string());
        }

        Ok(())
    }

    fn attestation_message(height: u64, batch_hash: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&height.to_le_bytes());
        msg.extend_from_slice(batch_hash);
        msg
    }

    fn compute_redistribution(
        &self,
        slashed_validator: &[u8],
        total_slashed: u64,
    ) -> Result<Vec<(Vec<u8>, u64)>, String> {
        let current_height = self.current_height;

        // Collect all eligible recipients sorted deterministically by pubkey so every
        // validator node computes the same dust distribution.
        let mut active_validators: Vec<_> = self
            .validators
            .iter()
            .filter(|(pk, stake)| {
                pk.as_slice() != slashed_validator && stake.is_active(current_height)
            })
            .map(|(pk, stake)| (pk.clone(), stake.active_stake))
            .collect();

        if active_validators.is_empty() {
            if let Some(treasury_id) = self.treasury_account_id {
                tracing::info!(
                    "  No active validators to redistribute slashed stake - sending to treasury"
                );
                return Ok(vec![(treasury_id.to_vec(), total_slashed)]);
            }
            tracing::warn!("  No active validators to redistribute slashed stake - tokens burned");
            return Ok(Vec::new());
        }

        // Sort deterministically so dust assignment is reproducible across all nodes.
        active_validators.sort_by(|(a, _), (b, _)| a.cmp(b));

        let total_active_stake: u64 = active_validators.iter().map(|(_, s)| *s).sum();
        if total_active_stake == 0 {
            return Ok(Vec::new());
        }

        // Phase 1: proportional distribution (floor of each share).
        let mut shares: Vec<(Vec<u8>, u64)> = active_validators
            .iter()
            .map(|(pk, validator_stake)| {
                let share = ((total_slashed as u128 * *validator_stake as u128)
                    / total_active_stake as u128) as u64;
                (pk.clone(), share)
            })
            .collect();

        let allocated: u64 = shares.iter().map(|(_, s)| s).sum();
        let mut dust = total_slashed.saturating_sub(allocated);

        // Phase 2: distribute dust one token at a time round-robin by stake descending
        // (largest stake holders get the first dust tokens - maximally fair because
        //  they hold the most proportional entitlement that was truncated by floor division).
        if dust > 0 {
            // Sort by stake descending for dust allocation.
            let mut dust_order: Vec<usize> = (0..shares.len()).collect();
            dust_order.sort_by(|&a, &b| active_validators[b].1.cmp(&active_validators[a].1));
            let mut idx = 0;
            while dust > 0 {
                let slot = dust_order[idx % dust_order.len()];
                shares[slot].1 = shares[slot].1.saturating_add(1);
                dust -= 1;
                idx += 1;
            }
        }

        // Phase 3: apply all shares.
        Ok(shares)
    }

    fn apply_redistribution(&mut self, shares: &[(Vec<u8>, u64)]) {
        for (pk, share) in shares {
            if *share == 0 {
                continue;
            }
            if let Some(stake) = self.validators.get_mut(pk) {
                stake.active_stake = stake.active_stake.saturating_add(*share);
                tracing::info!(
                    " Redistributed {} slashed tokens to validator {}",
                    share,
                    hex::encode(&pk[..8.min(pk.len())])
                );
            }
        }
    }

    /// Slash a validator who committed to an oracle request then revealed fabricated data.
    /// Cryptographic proof: the stored commit_hash != blake3(validator_pk || request_id || revealed_body).
    /// This is called from apply_diff when a reveal fails hash verification.
    pub fn slash_for_oracle_lie(&mut self, validator_pubkey: &[u8]) -> Result<u64, String> {
        let outcome = self.slash_validator(validator_pubkey, SlashReason::OracleLie, None)?;
        Ok(outcome.amount)
    }

    /// Slash every validator that committed to `request_id` but never revealed within
    /// `ORACLE_REVEAL_DEADLINE_BLOCKS` blocks. Called from apply_diff when a request expires.
    /// Returns a Vec of (validator_pubkey, amount_slashed).
    pub fn slash_silent_oracle_validators(
        &mut self,
        request_id: [u8; 32],
        committed_validators: &[Vec<u8>],
        revealed_validators: &[Vec<u8>],
    ) -> Vec<(Vec<u8>, u64)> {
        let revealed: HashSet<Vec<u8>> = revealed_validators.iter().cloned().collect();
        let mut silent: Vec<Vec<u8>> = committed_validators
            .iter()
            .filter(|pk| !revealed.contains(*pk))
            .cloned()
            .collect();
        silent.sort();
        silent.dedup();

        let mut results = Vec::new();

        for pk in silent {
            match self.slash_validator(&pk, SlashReason::OracleSilence { request_id }, None) {
                Ok(outcome) => {
                    results.push((pk, outcome.amount));
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to slash silent oracle validator {}: {}",
                        hex::encode(&pk[..8.min(pk.len())]),
                        e
                    );
                }
            }
        }

        results
    }

    pub fn unjail(&mut self, validator_pubkey: &[u8]) -> Result<(), String> {
        let stake = self
            .validators
            .get_mut(validator_pubkey)
            .ok_or("Validator not found")?;

        if let Some(jail_height) = stake.jailed_until {
            if self.current_height < jail_height {
                return Err(format!("Still jailed until height {}", jail_height));
            }
        }

        if stake.active_stake < MIN_VALIDATOR_STAKE {
            return Err("Insufficient stake to unjail".to_string());
        }

        stake.jailed_until = None;

        tracing::info!(
            " Validator {} unjailed at height {}",
            hex::encode(&validator_pubkey[..8]),
            self.current_height
        );

        Ok(())
    }
}
