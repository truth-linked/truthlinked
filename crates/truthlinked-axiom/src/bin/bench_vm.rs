//! Axiom VM benchmark - measures raw interpreter throughput.
//! Run with: cargo bench -p truthlinked-axiom

use std::collections::HashMap;
use std::time::Instant;
use truthlinked_axiom::bytecode::MAGIC;
use truthlinked_axiom::error::AxiomError;
use truthlinked_axiom::host::{CellLog, CrossCellResult, Host, NameOp, StakingOp};
use truthlinked_axiom::opcode::tag;
use truthlinked_axiom::{CellBytecode, Vm};

// ── Minimal host ─────────────────────────────────────────────────────────────

struct BenchHost {
    storage: HashMap<[u8; 32], [u8; 32]>,
    caller: [u8; 32],
    owner: [u8; 32],
    calldata: Vec<u8>,
    return_data: Vec<u8>,
}

impl BenchHost {
    fn new() -> Self {
        Self {
            storage: HashMap::new(),
            caller: [1u8; 32],
            owner: [2u8; 32],
            calldata: vec![0u8; 64],
            return_data: vec![],
        }
    }
}

impl Host for BenchHost {
    fn storage_read(&self, key: &[u8; 32]) -> Result<[u8; 32], AxiomError> {
        Ok(self.storage.get(key).copied().unwrap_or([0u8; 32]))
    }
    fn storage_write(&mut self, key: &[u8; 32], val: &[u8; 32]) -> Result<(), AxiomError> {
        self.storage.insert(*key, *val);
        Ok(())
    }
    fn storage_delete(&mut self, key: &[u8; 32]) -> Result<(), AxiomError> {
        self.storage.remove(key);
        Ok(())
    }
    fn caller(&self) -> [u8; 32] {
        self.caller
    }
    fn owner(&self) -> [u8; 32] {
        self.owner
    }
    fn cell_id(&self) -> [u8; 32] {
        [3u8; 32]
    }
    fn height(&self) -> u64 {
        1000
    }
    fn timestamp(&self) -> u64 {
        1_700_000_000
    }
    fn value(&self) -> u128 {
        0
    }
    fn calldata(&self) -> &[u8] {
        &self.calldata
    }
    fn set_return_data(&mut self, d: Vec<u8>) -> Result<(), AxiomError> {
        self.return_data = d;
        Ok(())
    }
    fn emit_log(&mut self, _: CellLog) -> Result<(), AxiomError> {
        Ok(())
    }
    fn call_cell(
        &mut self,
        _: &[u8; 32],
        _: &[u8],
        _: u128,
        _: u64,
    ) -> Result<CrossCellResult, AxiomError> {
        Err(AxiomError::CrossCellFailed("bench".into()))
    }
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        input.hash(&mut h);
        let v = h.finish();
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&v.to_le_bytes());
        out
    }
}

// ── Bytecode builders ─────────────────────────────────────────────────────────

fn build_cell(code: Vec<u8>, const_pool: Vec<Vec<u8>>) -> Vec<u8> {
    let cell = CellBytecode { const_pool, code };
    cell.encode()
}

/// 1000 iterations of: LoadImm64 r1=i, Add r2=r2+r1, loop via JumpIfNot
/// Tests: tight arithmetic loop throughput
fn bench_arithmetic_loop(iters: u64) -> Vec<u8> {
    // r1 = counter, r2 = accumulator, r3 = limit
    // LoadImm64 r3, iters
    // LoadImm8  r2, 0       ; acc = 0
    // LoadImm8  r1, 1       ; step = 1
    // [loop_start @ offset 22]:
    //   Add r2, r2, r1      ; acc += step
    //   Sub r3, r3, r1      ; counter--
    //   JumpIf r3, loop_start
    // Halt
    let mut code = vec![];
    // LoadImm64 r3, iters  (1 + 1 + 8 = 10 bytes)
    code.push(tag::LOAD_IMM64);
    code.push(3);
    code.extend_from_slice(&iters.to_le_bytes());
    // LoadImm8 r2, 0  (3 bytes)
    code.push(tag::LOAD_IMM8);
    code.push(2);
    code.push(0);
    // LoadImm8 r1, 1  (3 bytes)
    code.push(tag::LOAD_IMM8);
    code.push(1);
    code.push(1);
    // loop_start = 16
    let loop_start = code.len() as u32;
    // Add r2, r2, r1  (4 bytes)
    code.push(tag::ADD);
    code.push(2);
    code.push(2);
    code.push(1);
    // Sub r3, r3, r1  (4 bytes)
    code.push(tag::SUB);
    code.push(3);
    code.push(3);
    code.push(1);
    // JumpIf r3, loop_start  (6 bytes)
    code.push(tag::JUMP_IF);
    code.push(3);
    code.extend_from_slice(&loop_start.to_le_bytes());
    // Halt
    code.push(tag::HALT);
    build_cell(code, vec![])
}

/// Storage read/write loop - N iterations of SStore then SLoad
fn bench_storage_loop(iters: u32) -> Vec<u8> {
    // r1 = key (stays [1;32]), r2 = value counter
    // LoadImm8 r1, 1   ; key
    // LoadImm8 r2, 0   ; value
    // LoadImm64 r3, iters
    // LoadImm8 r4, 1   ; step
    // [loop]:
    //   SStore r1, r2
    //   SLoad  r2, r1
    //   Sub r3, r3, r4
    //   JumpIf r3, loop
    // Halt
    let mut code = vec![];
    code.push(tag::LOAD_IMM8);
    code.push(1);
    code.push(1);
    code.push(tag::LOAD_IMM8);
    code.push(2);
    code.push(0);
    code.push(tag::LOAD_IMM64);
    code.push(3);
    code.extend_from_slice(&(iters as u64).to_le_bytes());
    code.push(tag::LOAD_IMM8);
    code.push(4);
    code.push(1);
    let loop_start = code.len() as u32;
    code.push(tag::SSTORE);
    code.push(1);
    code.push(2);
    code.push(tag::SLOAD);
    code.push(2);
    code.push(1);
    code.push(tag::SUB);
    code.push(3);
    code.push(3);
    code.push(4);
    code.push(tag::JUMP_IF);
    code.push(3);
    code.extend_from_slice(&loop_start.to_le_bytes());
    code.push(tag::HALT);
    build_cell(code, vec![])
}

/// SHA-256 loop - N hash ops
fn bench_hash_loop(iters: u32) -> Vec<u8> {
    // r1 = input (stays [1;32]), r2 = output, r3 = counter, r4 = step
    let mut code = vec![];
    code.push(tag::LOAD_IMM8);
    code.push(1);
    code.push(0xAB);
    code.push(tag::LOAD_IMM64);
    code.push(3);
    code.extend_from_slice(&(iters as u64).to_le_bytes());
    code.push(tag::LOAD_IMM8);
    code.push(4);
    code.push(1);
    let loop_start = code.len() as u32;
    code.push(tag::HASH32);
    code.push(2);
    code.push(1);
    code.push(tag::MOVE);
    code.push(1);
    code.push(2); // chain: hash of hash
    code.push(tag::SUB);
    code.push(3);
    code.push(3);
    code.push(4);
    code.push(tag::JUMP_IF);
    code.push(3);
    code.extend_from_slice(&loop_start.to_le_bytes());
    code.push(tag::HALT);
    build_cell(code, vec![])
}

// ── Runner ────────────────────────────────────────────────────────────────────

fn run(name: &str, bytecode: &[u8], gas: u64, runs: u32) {
    let cell = CellBytecode::decode(bytecode).expect("decode failed");
    // warmup
    for _ in 0..3 {
        let mut host = BenchHost::new();
        let mut vm = Vm::new(&mut host, gas, 0);
        let _ = vm.execute(&cell);
    }
    let t = Instant::now();
    for _ in 0..runs {
        let mut host = BenchHost::new();
        let mut vm = Vm::new(&mut host, gas, 0);
        let r = vm.execute(&cell);
        assert!(r.success, "bench failed: {:?}", r.error);
    }
    let elapsed = t.elapsed();
    let per_run = elapsed / runs;
    println!("{name:30} runs={runs:5}  total={elapsed:?}  per_run={per_run:?}");
}

fn main() {
    println!("\n=== Axiom VM Benchmark ===\n");

    // Arithmetic: 10k, 100k, 1M iterations
    run(
        "arith_loop_10k",
        &bench_arithmetic_loop(10_000),
        10_000_000,
        1000,
    );
    run(
        "arith_loop_100k",
        &bench_arithmetic_loop(100_000),
        100_000_000,
        100,
    );
    run(
        "arith_loop_1m",
        &bench_arithmetic_loop(1_000_000),
        1_000_000_000,
        10,
    );

    // Storage: 100, 1000 iterations (expensive ops)
    run("storage_loop_100", &bench_storage_loop(100), 500_000, 1000);
    run(
        "storage_loop_1000",
        &bench_storage_loop(1000),
        5_000_000,
        100,
    );

    // Hash: 100, 1000 iterations
    run("hash_loop_100", &bench_hash_loop(100), 100_000, 1000);
    run("hash_loop_1000", &bench_hash_loop(1000), 1_000_000, 100);

    println!("\nDone.");
}
