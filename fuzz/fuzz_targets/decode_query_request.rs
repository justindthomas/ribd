#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the QueryRequest decoder. QueryRequest comes from operator
// tooling (`imp show ip route`, `imp show ip route candidates`,
// readiness probes from impd). The control-plane attacker model is
// narrower than ClientMsg's (only root-equivalent on the appliance
// can connect), but a panic here is still a DoS on operator visibility.
fuzz_target!(|data: &[u8]| {
    let _ = ribd_proto::decode::<ribd_proto::QueryRequest>(data);
});
