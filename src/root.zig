//! Deterministic Ruijie authentication engine.

/// Protocol types and codecs shared by clients and tests.
pub const protocol = @import("protocol/root.zig");

/// Deterministic target-profile EAP-MD5 session orchestration.
pub const session = @import("session/session.zig");

test {
    _ = protocol;
    _ = session;
    _ = @import("session/target_test.zig");

    // Research machines for protocol branches outside the target deployment
    // remain compiled and tested, but are not part of the public surface.
    _ = @import("research/session.zig");
    _ = @import("research/session_test.zig");
    _ = @import("research/session_eap_md5_test.zig");
    _ = @import("research/session_peap_test.zig");
}

test "session is exposed from the package root" {
    _ = session.Session;
    _ = session.Generation;
}
