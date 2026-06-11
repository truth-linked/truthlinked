#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    let seed = common::seed_dir(common::SeedKind::Sst);
    let Some(tmp) = common::copy_seed_to_temp(&seed) else {
        return;
    };
    let files = common::list_sst_files(tmp.path());
    if !files.is_empty() {
        let idx = data.first().copied().unwrap_or(0) as usize % files.len();
        common::mutate_file(&files[idx], data);
    }
    common::recover_and_exercise(tmp.path(), b"sst");
});
