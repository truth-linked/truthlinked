//! Tendermint-style BFT round state.
//!
//! Each height goes through rounds until 2/3+ precommits are collected.
//! Safety invariant: a validator only precommits if it saw 2/3+ prevotes
//! for the same block_hash. It locks on that hash and carries the lock
//! into future rounds - preventing two honest nodes from ever committing
//! different blocks at the same height.

use std::collections::HashMap;

/// Which phase of the round we are in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Committed,
}

/// A single vote (prevote or precommit).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    /// None = nil vote (no valid proposal seen / timeout).
    pub block_hash: Option<[u8; 32]>,
    pub validator_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Per-height BFT round state.
pub struct RoundState {
    pub height: u64,
    pub round: u32,
    pub step: Step,

    /// The proposed block hash for this round (set when leader's header arrives).
    pub proposal: Option<[u8; 32]>,

    /// prevotes[round][validator_pk] = Vote
    pub prevotes: HashMap<u32, HashMap<Vec<u8>, Vote>>,
    /// precommits[round][validator_pk] = Vote
    pub precommits: HashMap<u32, HashMap<Vec<u8>, Vote>>,

    /// The block_hash we are locked on (set when we precommit a non-nil block).
    pub locked_block: Option<[u8; 32]>,
    /// The round in which we locked (-1 = no lock).
    pub locked_round: i64,
}

impl RoundState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            proposal: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            locked_block: None,
            locked_round: -1,
        }
    }

    /// Advance to the next round (view-change on timeout).
    pub fn next_round(&mut self) {
        self.round += 1;
        self.step = Step::Propose;
        self.proposal = None;
        // Lock is carried forward - must not clear locked_block / locked_round.
    }

    /// Record a prevote. Returns true if it was new (not a duplicate).
    pub fn add_prevote(&mut self, vote: Vote) -> bool {
        let by_val = self.prevotes.entry(vote.round).or_default();
        if by_val.contains_key(&vote.validator_pubkey) {
            return false; // duplicate
        }
        by_val.insert(vote.validator_pubkey.clone(), vote);
        true
    }

    /// Record a precommit. Returns true if it was new.
    pub fn add_precommit(&mut self, vote: Vote) -> bool {
        let by_val = self.precommits.entry(vote.round).or_default();
        if by_val.contains_key(&vote.validator_pubkey) {
            return false;
        }
        by_val.insert(vote.validator_pubkey.clone(), vote);
        true
    }

    /// Total stake prevoting for `block_hash` in `round` (None = count nil votes).
    pub fn prevote_stake(
        &self,
        round: u32,
        block_hash: Option<[u8; 32]>,
        stake_map: &HashMap<Vec<u8>, u64>,
    ) -> u64 {
        self.prevotes
            .get(&round)
            .map(|by_val| {
                by_val
                    .values()
                    .filter(|v| v.block_hash == block_hash)
                    .filter_map(|v| stake_map.get(&v.validator_pubkey))
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Total stake precommitting for `block_hash` in `round`.
    pub fn precommit_stake(
        &self,
        round: u32,
        block_hash: Option<[u8; 32]>,
        stake_map: &HashMap<Vec<u8>, u64>,
    ) -> u64 {
        self.precommits
            .get(&round)
            .map(|by_val| {
                by_val
                    .values()
                    .filter(|v| v.block_hash == block_hash)
                    .filter_map(|v| stake_map.get(&v.validator_pubkey))
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Returns the block_hash that has 2/3+ prevote stake in `round`, if any.
    pub fn prevote_quorum(
        &self,
        round: u32,
        threshold: u64,
        stake_map: &HashMap<Vec<u8>, u64>,
    ) -> Option<[u8; 32]> {
        let by_val = self.prevotes.get(&round)?;
        // Tally per block_hash
        let mut tally: HashMap<[u8; 32], u64> = HashMap::new();
        for vote in by_val.values() {
            if let Some(h) = vote.block_hash {
                if let Some(s) = stake_map.get(&vote.validator_pubkey) {
                    *tally.entry(h).or_insert(0) += s;
                }
            }
        }
        tally
            .into_iter()
            .find(|(_, s)| *s >= threshold)
            .map(|(h, _)| h)
    }

    /// Returns the block_hash that has 2/3+ precommit stake in `round`, if any.
    pub fn precommit_quorum(
        &self,
        round: u32,
        threshold: u64,
        stake_map: &HashMap<Vec<u8>, u64>,
    ) -> Option<[u8; 32]> {
        let by_val = self.precommits.get(&round)?;
        let mut tally: HashMap<[u8; 32], u64> = HashMap::new();
        for vote in by_val.values() {
            if let Some(h) = vote.block_hash {
                if let Some(s) = stake_map.get(&vote.validator_pubkey) {
                    *tally.entry(h).or_insert(0) += s;
                }
            }
        }
        tally
            .into_iter()
            .find(|(_, s)| *s >= threshold)
            .map(|(h, _)| h)
    }

    /// Lock rule: should we prevote for `proposal_hash`?
    /// Yes if: we have no lock, OR the proposal matches our lock,
    /// OR we saw 2/3+ prevotes for the proposal in a later round than our lock.
    pub fn should_prevote(
        &self,
        proposal_hash: [u8; 32],
        threshold: u64,
        stake_map: &HashMap<Vec<u8>, u64>,
    ) -> bool {
        match self.locked_block {
            None => true,
            Some(locked) if locked == proposal_hash => true,
            Some(_) => {
                // Unlock condition: 2/3+ prevotes for proposal in a round > locked_round
                for (&r, _) in &self.prevotes {
                    if r as i64 > self.locked_round {
                        if self.prevote_stake(r, Some(proposal_hash), stake_map) >= threshold {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }
}
