//! Optional host-change vote. A world owner switches it on; then an eligible, clearly stronger machine can propose to take
//! over, the other recent guests vote, and a majority makes that machine's takeover immediate. Nothing here forces a
//! host out without the normal handover: an approved candidate still bids with `takeover` and goes through the usual
//! MIGRATE flow, so the host gets the same warning and the world gets the same final commit.

use super::*;

pub(crate) const VOTE_MARGIN: f64 = 1.15;
const VOTE_MIN_HOLD_MS: u64 = 60_000;
const GUEST_WINDOW_MS: u64 = 30 * 60_000;
const ROUND_TTL_MS: u64 = 5 * 60_000;
const APPROVAL_TTL_MS: u64 = 5 * 60_000;
const COOLDOWN_MS: u64 = 10 * 60_000;
const MIN_YES: usize = 2;

pub(crate) struct Round {
    candidate: String,
    candidate_player: String,
    score: f64,
    opened: u64,
    yes: HashSet<String>,
    no: HashSet<String>,
    approved_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoundView {
    pub candidate_name: String,
    pub candidate_device: String,
    pub improvement_pct: i64,
    pub yes: usize,
    pub no: usize,
    pub needed: usize,
    pub my_vote: Option<bool>,
    pub approved: bool,
    pub expires_in_s: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteError {
    Disabled,
    NoLiveHost,
    NotGuest,
    NotBetter,
    TooEarly,
    RoundOpen,
    Cooldown,
    NoRound,
}

impl Gateway {
    pub fn vote_enabled(&self, world: &str) -> bool {
        self.db.query_row("SELECT handover_vote FROM world_policy WHERE world_id=?", params![world], |r| r.get::<_, bool>(0)).unwrap_or(false)
    }

    pub fn set_vote_enabled(&mut self, world: &str, on: bool) -> Result<()> {
        self.db.execute(
            "INSERT INTO world_policy(world_id, handover_vote) VALUES(?,?) ON CONFLICT(world_id) DO UPDATE SET handover_vote=excluded.handover_vote",
            params![world, on],
        )?;
        if !on {
            self.rounds.remove(world);
        }
        Ok(())
    }

    /// Remembers that this player is playing in the world as a guest; only those can vote or propose.
    pub(super) fn note_guest(&mut self, world: &str, device: &str, now: u64) {
        if let Ok(Some((uuid, _))) = self.device_player(device) {
            self.guests_seen.insert((world.to_string(), uuid), now);
        }
    }

    fn active_guests(&self, world: &str, now: u64) -> usize {
        self.guests_seen.iter().filter(|((w, _), at)| w == world && now.saturating_sub(**at) <= GUEST_WINDOW_MS).count()
    }

    fn needed(&self, world: &str, now: u64) -> usize {
        (self.active_guests(world, now) / 2 + 1).max(MIN_YES)
    }

    fn is_recent_guest(&self, world: &str, uuid: &str, now: u64) -> bool {
        self.guests_seen.get(&(world.to_string(), uuid.to_string())).is_some_and(|at| now.saturating_sub(*at) <= GUEST_WINDOW_MS)
    }

    /// Drops a round that ran out of time or can no longer reach a majority, starting the cooldown for its candidate.
    fn settle_round(&mut self, world: &str, now: u64) {
        let needed = self.needed(world, now);
        let active = self.active_guests(world, now);
        let verdict = self.rounds.get(world).map(|r| {
            let expired = r.approved_at.map_or(now.saturating_sub(r.opened) > ROUND_TTL_MS, |a| now.saturating_sub(a) > APPROVAL_TTL_MS);
            let lost = r.approved_at.is_none() && r.no.len() > active.saturating_sub(needed);
            (expired, lost, r.candidate.clone())
        });
        if let Some((expired, lost, candidate)) = verdict {
            if expired || lost {
                self.rounds.remove(world);
                if lost {
                    self.vote_cool.insert((world.to_string(), candidate), now);
                }
            }
        }
    }

    fn view(&self, world: &str, round: &Round, viewer_uuid: &str, host_score: f64, now: u64) -> RoundView {
        let name = self.db.query_row("SELECT name FROM players WHERE uuid=?", params![round.candidate_player], |r| r.get::<_, String>(0)).unwrap_or_default();
        let ttl = round.approved_at.map_or(ROUND_TTL_MS.saturating_sub(now.saturating_sub(round.opened)), |a| APPROVAL_TTL_MS.saturating_sub(now.saturating_sub(a)));
        RoundView {
            candidate_name: name,
            candidate_device: round.candidate.clone(),
            improvement_pct: if host_score > 0.0 { ((round.score / host_score - 1.0) * 100.0).round() as i64 } else { 0 },
            yes: round.yes.len(),
            no: round.no.len(),
            needed: self.needed(world, now),
            my_vote: round.yes.contains(viewer_uuid).then_some(true).or_else(|| round.no.contains(viewer_uuid).then_some(false)),
            approved: round.approved_at.is_some(),
            expires_in_s: ttl.div_ceil(1000),
        }
    }

    /// The open round of a world as `device` sees it, or None.
    pub fn handover_round(&mut self, world: &str, device: &str, now: u64) -> Result<Option<RoundView>> {
        self.settle_round(world, now);
        let Some(round) = self.rounds.get(world) else { return Ok(None) };
        let uuid = self.device_player(device)?.map(|p| p.0).unwrap_or_default();
        let host_score = self.active_lease(world)?.and_then(|(lid, ..)| self.timers.get(&lid).map(|t| t.score)).unwrap_or(0.0);
        Ok(Some(self.view(world, round, &uuid, host_score, now)))
    }

    /// An eligible guest with clearly stronger hardware asks to take the world over.
    pub fn propose_handover(&mut self, world: &str, device: &str, tier: u8, score: f64, now: u64) -> Result<std::result::Result<RoundView, VoteError>> {
        use std::result::Result::{Err as No, Ok as Yes};
        if !self.vote_enabled(world) {
            return Ok(No(VoteError::Disabled));
        }
        if !self.role(world, device)?.can_host() {
            return Ok(No(VoteError::NotGuest));
        }
        let Some((lid, host_dev, _, host_tier)) = self.active_lease(world)? else { return Ok(No(VoteError::NoLiveHost)) };
        if host_dev == device || self.world_state(world)?.0 != "LOCKED" {
            return Ok(No(VoteError::NoLiveHost));
        }
        let (uuid, _) = self.device_player(device)?.ok_or(Error::NotMember)?;
        if !self.is_recent_guest(world, &uuid, now) {
            return Ok(No(VoteError::NotGuest));
        }
        self.settle_round(world, now);
        if self.rounds.contains_key(world) {
            return Ok(No(VoteError::RoundOpen));
        }
        if self.vote_cool.get(&(world.to_string(), device.to_string())).is_some_and(|at| now.saturating_sub(*at) < COOLDOWN_MS) {
            return Ok(No(VoteError::Cooldown));
        }
        let t = self.timers.get(&lid).ok_or(Error::StaleEpoch)?;
        if now.saturating_sub(t.granted) < VOTE_MIN_HOLD_MS {
            return Ok(No(VoteError::TooEarly));
        }
        let host_score = t.score;
        if !Self::better_with(&Cand { tier, score, seen: now }, host_tier, host_score, VOTE_MARGIN) || self.anchor_blocked(device, &lid) {
            return Ok(No(VoteError::NotBetter));
        }
        // the proposer stays a fresh candidate so the election can see it when the host hands over
        self.cands.insert((world.to_string(), device.to_string()), Cand { tier, score, seen: now });
        let mut round = Round { candidate: device.to_string(), candidate_player: uuid.clone(), score, opened: now, yes: HashSet::new(), no: HashSet::new(), approved_at: None };
        round.yes.insert(uuid.clone());
        self.rounds.insert(world.to_string(), round);
        self.approve_if_majority(world, now);
        let round = self.rounds.get(world).expect("just inserted");
        Ok(Yes(self.view(world, round, &uuid, host_score, now)))
    }

    fn approve_if_majority(&mut self, world: &str, now: u64) {
        let needed = self.needed(world, now);
        if let Some(r) = self.rounds.get_mut(world) {
            if r.approved_at.is_none() && r.yes.len() >= needed {
                r.approved_at = Some(now);
            }
        }
    }

    pub fn cast_handover_vote(&mut self, world: &str, device: &str, yes: bool, now: u64) -> Result<std::result::Result<RoundView, VoteError>> {
        use std::result::Result::{Err as No, Ok as Yes};
        self.settle_round(world, now);
        let (uuid, _) = self.device_player(device)?.ok_or(Error::NotMember)?;
        if !self.rounds.contains_key(world) {
            return Ok(No(VoteError::NoRound));
        }
        // the host's own player never decides who hosts
        let is_host = self.active_lease(world)?.is_some_and(|(_, d, ..)| d == device);
        if is_host || !self.is_recent_guest(world, &uuid, now) {
            return Ok(No(VoteError::NotGuest));
        }
        let r = self.rounds.get_mut(world).expect("checked above");
        r.yes.remove(&uuid);
        r.no.remove(&uuid);
        if yes {
            r.yes.insert(uuid.clone());
        } else {
            r.no.insert(uuid.clone());
        }
        self.approve_if_majority(world, now);
        self.settle_round(world, now);
        let host_score = self.active_lease(world)?.and_then(|(lid, ..)| self.timers.get(&lid).map(|t| t.score)).unwrap_or(0.0);
        match self.rounds.get(world) {
            Some(round) => Ok(Yes(self.view(world, round, &uuid, host_score, now))),
            None => Ok(No(VoteError::NoRound)),
        }
    }

    /// True while this device holds an approved round for the world: its takeover bid skips margin and hold time.
    pub(super) fn vote_approved(&mut self, world: &str, device: &str, now: u64) -> bool {
        self.settle_round(world, now);
        self.rounds.get(world).is_some_and(|r| r.candidate == device && r.approved_at.is_some())
    }

    /// Read-only check for listings: an approved round for this device that has not run out yet.
    pub(super) fn vote_approved_now(&self, world: &str, device: &str, now: u64) -> bool {
        self.rounds.get(world).is_some_and(|r| r.candidate == device && r.approved_at.is_some_and(|a| now.saturating_sub(a) <= APPROVAL_TTL_MS))
    }

    pub(super) fn vote_consumed(&mut self, world: &str) {
        self.rounds.remove(world);
    }
}
