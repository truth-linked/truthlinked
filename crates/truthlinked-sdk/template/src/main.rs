//! Axiom Cell template - build with: cargo build --release
//! Deploy with: axiom deploy-cell --cell-id <hex> --bytecode-file <path>

use truthlinked_sdk::CellBuilder;
use truthlinked_sdk::abi;

fn main() {
    let bytecode = build_cell();
    std::fs::write("cell.axiom", &bytecode).expect("write failed");
    println!("Built {} bytes -> cell.axiom", bytecode.len());
}

fn build_cell() -> Vec<u8> {
    let mut b = CellBuilder::new();
    // Read 4-byte selector from calldata
    b.load_imm8(10, 0)          // r10 = offset 0
     .get_calldata(1, 10)       // r1 = calldata[0..32]
     .halt();
    b.build()
}
