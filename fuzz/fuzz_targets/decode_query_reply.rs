#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the QueryReply decoder — what operator tooling parses when
// ribd answers a query. Same defensive-fuzzing logic as
// decode_server_msg: the producer side (impd, the `imp` CLI) trusts
// ribd, but compromised ribd can return arbitrary bytes. Reachability
// is correspondingly narrow, but the parser surface is large
// (Vec<InstalledRoute>, Vec<PrefixCandidates>, each with nested
// Vec<NextHop> + Option<ResolvedNextHop>) and worth coverage.
fuzz_target!(|data: &[u8]| {
    let _ = ribd_proto::decode::<ribd_proto::QueryReply>(data);
});
