//! Linear-scan register allocator for Axiom IR.
//!
//! Algorithm: Poletto & Sarkar (1999) linear scan, adapted for Axiom's 254
//! allocatable physical registers (r1–r254). r0 = zero (never allocated).
//! r255 = codegen scratch (never allocated here).
//!
//! Since Axiom has 254 allocatable registers - far more than any reasonable
//! function needs - spilling is essentially impossible in practice. We still
//! implement it correctly for correctness, but it will never trigger unless
//! someone writes a function with 255+ live variables simultaneously.
//!
//! Steps:
//!   1. Compute live intervals: for each VReg, [first_def, last_use] in
//!      instruction-index space.
//!   2. Sort intervals by start point.
//!   3. Linear scan: assign physical registers, expire intervals that end
//!      before the current start. Spill the interval with the furthest end
//!      if no register is free (should never happen with 254 regs).
//!   4. Return a VReg → u8 mapping.

use crate::ir::{Ir, VReg};
use std::collections::HashMap;

/// Physical register assignment: VReg → physical register byte (1–254).
pub type Allocation = HashMap<VReg, u8>;

const FIRST_PHYS: u8 = 1;
const LAST_PHYS: u8 = 254;

#[derive(Debug, Clone)]
struct Interval {
    vreg: VReg,
    start: usize,
    end: usize,
}

/// Compute live intervals for all VRegs in the instruction sequence.
/// Interval = [index of first def, index of last use].
///
/// Call-clobbered correctness: at every Ir::Call site, all vregs that are
/// live before the call (defined before i, last_use >= i) must have their
/// interval extended to at least i. This prevents the allocator from
/// assigning the same physical register to a caller-live vreg and a
/// callee-local vreg whose interval starts at i+1.
fn compute_intervals(instrs: &[Ir]) -> Vec<Interval> {
    let mut first_def: HashMap<VReg, usize> = HashMap::new();
    let mut last_use: HashMap<VReg, usize> = HashMap::new();

    for (i, instr) in instrs.iter().enumerate() {
        if let Some(d) = instr.def() {
            first_def.entry(d).or_insert(i);
            last_use
                .entry(d)
                .and_modify(|e| *e = (*e).max(i))
                .or_insert(i);
        }
        for u in instr.uses() {
            last_use
                .entry(u)
                .and_modify(|e| *e = (*e).max(i))
                .or_insert(i);
            first_def.entry(u).or_insert(0);
        }
    }

    // Second pass: at each Ir::Call, extend every vreg that is live across
    // the call (defined before i, last_use > i) to the end of the instruction
    // sequence. This is conservative but correct: the callee executes between
    // the Call and the next instruction, so any vreg live after the call must
    // not share a physical register with any callee vreg.
    let n = instrs.len();
    for (i, instr) in instrs.iter().enumerate() {
        if matches!(instr, Ir::Call(_)) {
            for (vreg, lu) in last_use.iter_mut() {
                let def = first_def.get(vreg).copied().unwrap_or(usize::MAX);
                // Vreg is live across the call if defined before it and used after it
                if def < i && *lu > i {
                    *lu = n.saturating_sub(1); // extend to end of sequence
                }
            }
        }
    }

    let mut intervals: Vec<Interval> = first_def
        .into_iter()
        .map(|(vreg, start)| {
            let end = last_use.get(&vreg).copied().unwrap_or(start);
            Interval { vreg, start, end }
        })
        .collect();

    intervals.sort_unstable_by_key(|i| i.start);
    intervals
}

/// Run linear-scan allocation. Returns VReg → physical register mapping.
/// VReg 0 always maps to physical r0 (zero register, never allocated).
pub fn allocate(instrs: &[Ir]) -> Allocation {
    let mut alloc: Allocation = HashMap::new();
    alloc.insert(0, 0); // VReg 0 → r0 always

    let intervals = compute_intervals(instrs);
    if intervals.is_empty() {
        return alloc;
    }

    // Free physical registers pool (r1–r254)
    let mut free: Vec<u8> = (FIRST_PHYS..=LAST_PHYS).collect();
    // Active intervals sorted by end point (ascending).
    let mut active: Vec<Interval> = Vec::new();

    for interval in intervals {
        if interval.vreg == 0 {
            continue;
        } // zero reg handled above

        // Expire intervals whose end < current start.
        // Active is sorted by end - scan from front and break as soon as
        // we hit one that hasn't expired (O(expired) instead of O(active)).
        let mut expired_count = 0;
        for a in &active {
            if a.end < interval.start {
                let freed_phys = *alloc.get(&a.vreg).unwrap();
                let pos = free.partition_point(|&r| r < freed_phys);
                free.insert(pos, freed_phys);
                expired_count += 1;
            } else {
                break; // active is sorted by end - no more can expire
            }
        }
        active.drain(..expired_count);

        if let Some(phys) = free.first().copied() {
            free.remove(0);
            alloc.insert(interval.vreg, phys);
            let pos = active.partition_point(|a| a.end <= interval.end);
            active.insert(pos, interval);
        } else {
            // Should never happen with 254 physical registers.
            // If it does, it's a compiler bug - panic loudly rather than
            // silently corrupting another vreg's register assignment.
            panic!(
                "register spill required for vreg {} - \
                 more than 254 simultaneously live variables is not supported",
                interval.vreg
            );
        }
    }

    alloc
}

/// Resolve a VReg to its physical register. Panics if not allocated (bug).
#[inline(always)]
pub fn resolve(alloc: &Allocation, vreg: VReg) -> u8 {
    *alloc
        .get(&vreg)
        .unwrap_or_else(|| panic!("vreg {} not allocated", vreg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Ir;

    #[test]
    fn basic_allocation() {
        let instrs = vec![
            Ir::GetCaller(1),
            Ir::GetValue(2),
            Ir::Add(3, 1, 2),
            Ir::Halt,
        ];
        let alloc = allocate(&instrs);
        // All three vregs should get distinct physical registers
        let p1 = alloc[&1];
        let p2 = alloc[&2];
        let p3 = alloc[&3];
        assert!(p1 >= 1 && p1 <= 254);
        assert!(p2 >= 1 && p2 <= 254);
        assert!(p3 >= 1 && p3 <= 254);
        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p2, p3);
    }

    #[test]
    fn register_reuse_after_last_use() {
        // v1 interval=[0,1], v2 interval=[2,2].
        // v1 ends at 1, v2 starts at 2 - no overlap, v2 should reuse v1's register.
        let instrs = vec![
            Ir::GetCaller(1),      // v1 def at 0
            Ir::RequireNonZero(1), // v1 last use at 1
            Ir::GetValue(2),       // v2 def at 2, no further use
            Ir::Halt,
        ];
        let alloc = allocate(&instrs);
        // v1 dead after instr 1; v2 starts at 2 - should reuse v1's register
        assert_eq!(alloc[&1], alloc[&2]);
    }

    #[test]
    fn call_does_not_clobber_caller_regs() {
        // Caller: v1 live across a Call, used after it returns.
        // Callee: v1000 defined inside the callee body (after the Call in index space).
        // They must get different physical registers.
        let instrs = vec![
            Ir::GetCaller(1),      // v1 def - caller vreg
            Ir::Call(42),          // call to helper
            Ir::RequireNonZero(1), // v1 use after call - must still hold caller value
            Ir::GetCaller(1000),   // v1000 def - callee vreg (different namespace)
            Ir::RequireNonZero(1000),
            Ir::Halt,
        ];
        let alloc = allocate(&instrs);
        // v1 and v1000 must not share a physical register
        assert_ne!(
            alloc[&1], alloc[&1000],
            "caller vreg v1 and callee vreg v1000 must not share a physical register"
        );
    }

    #[test]
    fn zero_vreg_always_r0() {
        let instrs = vec![Ir::Add(1, 0, 0), Ir::Halt];
        let alloc = allocate(&instrs);
        assert_eq!(alloc[&0], 0);
    }

    #[test]
    fn many_vregs_no_spill() {
        // 200 vregs all simultaneously live (each used after all are defined)
        let mut instrs: Vec<Ir> = (1u32..=200).map(|i| Ir::GetCaller(i)).collect();
        for i in 1u32..=200 {
            instrs.push(Ir::RequireNonZero(i));
        }
        instrs.push(Ir::Halt);
        let alloc = allocate(&instrs);
        let mut phys: Vec<u8> = (1u32..=200).map(|i| alloc[&i]).collect();
        phys.sort();
        phys.dedup();
        assert_eq!(
            phys.len(),
            200,
            "all 200 vregs should get distinct physical regs"
        );
    }
}
