# TruthLinked Cell SDK (Rust)

This SDK gives cell authors a stable, high-level interface over the TruthLinked Axiom VM.

## Location

- SDK workspace: `sdk/`
- SDK crate: `sdk/truthlinked-sdk`
- Macro crate: `sdk/truthlinked-sdk-macros`
- Starter template: `sdk/templates/rust-cell`

For external cell projects, depend on the published crates rather than repo-local paths:

```toml
[dependencies]
truthlinked-sdk = "0.1.1"
```

## What It Includes

- Context API: caller, owner, cell id, height, timestamp, value, calldata
- Deterministic storage API: `Slot` plus derived-slot helpers (`namespace`, `slot_for`, `slot_for_parts`)
- Storage collections: `StorageMap<V>`, `StorageVec<V>`, `StorageBlob`
- Serialization helpers: `Codec32`, `BytesCodec`, `Encoder`, `Decoder`
- Derive macros: `#[derive(Event)]`, `#[derive(Manifest)]`, `#[derive(Codec32)]`, `#[derive(BytesCodec)]`
- Return-data API: `set_return_data`
- Structured event API: `Event`, `EventTopic`, `EventData`, `emit_event`
- Event decode helpers: `event_topics_match`, `indexed_topics`, `decode_event_data`
- Cell ergonomics macros: `#[error_code]`, `#[require]`
- Cross-cell calls: legacy + value-forwarding v2
- Oracle API: deterministic `http_call` wrapper
- ABI helpers: selector hashing and typed calldata decoding
- Manifest tooling: `CellManifest` + `ManifestBuilder` + `StorageKeySpec`
- Test infrastructure (feature `testing`): `MemoryStorage` and `StorageHarness`
- Fuzzing scaffold: `sdk/truthlinked-sdk/fuzz` with harness-based property fuzz target
- Entrypoint macro: `cell_entry!(handler)`

## Quick Start

1. Copy the template:

```bash
axiom sdk-new --path my-cell
```

2. Build cell bytecode:

```bash
axiom sdk-build --path my-cell
```

Equivalent raw Cargo build:

```bash
cd my-cell
cargo axiom build
```

3. Deploy with CLI:

```bash
axiom sdk-deploy --from <keys.json> --cell-id <hex32> --path my-cell
```

Manifests are required for deployment. The SDK build embeds the manifest into the Axiom bytecode automatically.

## Deterministic Storage (No Blind Slots)

Use human labels and keys to derive 32-byte slots consistently:

```rust
use truthlinked_sdk::prelude::*;

fn counter_slot() -> Slot {
    let ns = storage::namespace("my.cell.counter");
    storage::slot_for(&ns, b"value")
}
```

## Collections

`StorageMap<V>` stores typed 32-byte values with deterministic per-key slots.

```rust
use truthlinked_sdk::prelude::*;

fn balances() -> StorageMap<u64> {
    let ns = storage::namespace("my.cell.balances");
    StorageMap::new(Namespace::new(ns))
}

fn credit(account: [u8; 32], amount: u64) -> Result<()> {
    let current = balances().get_typed_key(&account)?.unwrap_or(0);
    balances().insert_typed_key(&account, &current.saturating_add(amount))
}
```

`StorageVec<V>` stores indexed 32-byte values with persisted length.

`StorageBlob` stores variable-length bytes or typed values via `BytesCodec`.

## Serialization Helpers

- Use `Codec32` for fixed-size slot values (`u64`, `u128`, signed ints, `bool`, `[u8; 32]`)
- Use `BytesCodec` for variable-length payloads (`Vec<u8>`, `String`, `Option<T>`, arrays)
- Use `Encoder`/`Decoder` for custom binary layout

```rust
use truthlinked_sdk::prelude::*;

let mut enc = Encoder::new();
enc.push_u64(42);
enc.push_string("hello");
let bytes = enc.into_vec();

let mut dec = Decoder::new(&bytes);
let n = dec.read_u64()?;
let s = dec.read_string()?;
dec.finish()?;
```

### Serialization Derives

```rust
use truthlinked_sdk::prelude::*;

#[derive(BytesCodec, Codec32, PartialEq, Debug)]
struct Position {
    id: u16,
    active: bool,
}
```

`derive(Codec32)` stores a length-prefixed `BytesCodec` payload into one 32-byte slot (max payload: 31 bytes).

## Manifest Builder

Use SDK manifest helpers to produce complete manifest JSON and deterministic manifest hash.

```rust
use truthlinked_sdk::prelude::*;

let users = StorageMap::<u64>::new(Namespace::new(storage::namespace("my.cell.users")));
let manifest = ManifestBuilder::new()
    .read_map_get(&users, b"alice")
    .write_map_set(&users, b"alice")
    .storage_key_spec(4, 32)
    .build();

let manifest_json = manifest.to_json_pretty();
let manifest_hash = manifest.manifest_hash(&bytecode);
```

## Derive Macros

Use derive macros when you want static, declarative metadata instead of manual builder wiring.

```rust
use truthlinked_sdk::prelude::*;

#[derive(Manifest)]
#[manifest(
    read_derived(namespace = "my.cell.counter", key = "value"),
    write_derived(namespace = "my.cell.counter", key = "value"),
    key_spec(offset = 4, len = 32)
)]
struct CounterManifest;

let manifest = <CounterManifest as Manifest>::manifest();
```

`#[derive(Manifest)]` supports:

- `read_slot = "0x...64hex"`
- `write_slot = "0x...64hex"`
- `commutative_slot = "0x...64hex"`
- `read_slot_expr = "path::TO_CONST_SLOT"`
- `write_slot_expr = "path::TO_CONST_SLOT"`
- `commutative_slot_expr = "path::TO_CONST_SLOT"`
- `read_label = "label"`
- `write_label = "label"`
- `commutative_label = "label"`
- `read_derived(namespace = \"...\", key = \"...\")`
- `write_derived(namespace = \"...\", key = \"...\")`
- `commutative_derived(namespace = \"...\", key = \"...\")`
- `read_map(namespace = \"...\", key = \"...\")`
- `write_map(namespace = \"...\", key = \"...\")`
- `read_vec_len(namespace = \"...\")`
- `write_vec_len(namespace = \"...\")`
- `read_vec_index(namespace = \"...\", index = N)`
- `write_vec_index(namespace = \"...\", index = N)`
- `read_blob_chunk(namespace = \"...\", chunk = N)`
- `write_blob_chunk(namespace = \"...\", chunk = N)`
- `key_spec(offset = N, len = M)`

For dynamic key patterns, keep using `ManifestBuilder` at compile/build time to fill known slots/specs.

## Structured Events

```rust
use truthlinked_sdk::prelude::*;

#[derive(Event)]
#[event(name = "Transfer")]
struct TransferEvent {
    #[topic]
    from: [u8; 32],
    #[topic]
    to: [u8; 32],
    amount: u64,
}

fn emit_transfer(from: [u8; 32], to: [u8; 32], amount: u64) -> Result<()> {
    log::emit_event(&TransferEvent { from, to, amount })
}
```

Rules:

- Signature topic (`topic0`) is auto-hashed from the event signature.
- Fields marked `#[topic]` become indexed topics.
- Other fields are encoded into event data using SDK codecs.
- Advanced field options are available:
  - `#[event(topic)]` (alias for `#[topic]`)
  - `#[event(skip)]`
  - `#[event(type = \"uint256\")]` for explicit signature type text
  - `#[event(with_topic = \"path::fn\")]` where `fn(&T) -> [u8; 32]`
  - `#[event(with_data = \"path::fn\")]` where `fn(&T, &mut Encoder)`
- Struct options:
  - `#[event(name = \"...\")]`
  - `#[event(signature = \"Custom(Type,...)\")]`
  - `#[event(anonymous)]` (omits signature topic)

Decode helpers:

- `log::event_topics_match::<MyEvent>(&topics)`
- `log::indexed_topics::<MyEvent>(&topics)`
- `log::decode_event_data::<T>(&data)`

## Error + Require Macros

```rust
use truthlinked_sdk::prelude::*;

#[error_code(base = 7000)]
enum CellError {
    NotOwner,
    Overflow,
}

#[require(caller == owner, CellError::NotOwner)]
fn guarded(caller: [u8; 32], owner: [u8; 32]) -> Result<()> {
    Ok(())
}
```

`#[error_code]` generates `code()` and conversions into `truthlinked_sdk::Error`.  
`#[require]` injects a guard at function entry and returns an error when the condition is false.

## Cell Pattern

- Parse calldata selector (`abi::selector` / `abi::selector_of`)
- Route to function handlers
- Read/write typed slot state and collections
- Optionally emit logs and set return data
- Return `Result<()>` from handler and map to `execute()` via `cell_entry!`

## Testing Infrastructure

Enable feature `testing` in dev/test builds and use in-memory storage harness:

```rust
use truthlinked_sdk::prelude::*;

let mut harness = StorageHarness::new();
{
    let mut map = harness.map::<u64>(Namespace::new(storage::namespace("tests.map")));
    map.insert(b"alice", &7)?;
    assert_eq!(map.get(b"alice")?, Some(7));
}
```

## Fuzzing

SDK ships a fuzz package at `sdk/truthlinked-sdk/fuzz` wired to `StorageHarness`.

```bash
cd sdk/truthlinked-sdk/fuzz
cargo fuzz run storage_collections
```

Target `storage_collections` stress-tests map/vector behavior against a model to catch panics and state divergence.

## Host ABI Notes

The SDK is aligned with runtime host functions currently exported from `env`:

- `storage_read`, `storage_write`
- `get_caller`, `get_owner`, `get_cell_id`
- `get_height`, `get_timestamp`, `get_value`, `get_calldata`
- `set_return_data`, `emit_log`
- `call_cell`, `call_cell_v2`
- `http_call`

## Compatibility

- `no_std` + `alloc`
- Designed for the Axiom VM register machine`wasm32-unknown-unknown`
