#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    let seed = common::seed_dir(common::SeedKind::Wal);
    let Some(tmp) = common::copy_seed_to_temp(&seed) else {
        return;
    };
    common::mutate_file(&tmp.path().join("donadb.wal"), data);
    common::recover_and_exercise(tmp.path(), b"wal");
});
