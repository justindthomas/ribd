#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the ribd ServerMsg decoder — what producer daemons (ospfd,
// bgpd, dhcpd, dnsd) parse when ribd replies. The trust boundary is
// reversed from decode_client_msg: producers nominally trust ribd,
// but ribd is itself an attack target, so any compromise of ribd can
// feed forged ServerMsg bytes back to every connected producer.
// Defensive fuzzing here protects the producer side.
fuzz_target!(|data: &[u8]| {
    let _ = ribd_proto::decode::<ribd_proto::ServerMsg>(data);
});
