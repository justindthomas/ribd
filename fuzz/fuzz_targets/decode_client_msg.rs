#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the ribd ClientMsg decoder. ClientMsg is what *peers* send to
// ribd over /run/ribd.sock — Hello, Bulk, Update, etc. — so this is
// the most adversarial surface in the workspace: any compromised or
// buggy producer (ospfd, bgpd, dhcpd, dnsd, or anything else that
// connects to the socket) can feed arbitrary postcard bytes here.
//
// ribd's session loop already enforces the 4-byte length prefix +
// MAX_FRAME_LEN cap before invoking the decoder, so fuzz at the
// post-framing layer where the actual postcard parsing happens.
fuzz_target!(|data: &[u8]| {
    let _ = ribd_proto::decode::<ribd_proto::ClientMsg>(data);
});
