//! Deterministic Ruijie authentication and direct-communication engine.

/// Protocol types and codecs shared by clients and tests.
pub const protocol = @import("protocol/root.zig");

/// Deterministic protocol session orchestration.
pub const session = @import("session/session.zig");

test {
    _ = protocol;
    _ = session;
    _ = @import("session/session_test.zig");
    _ = @import("session/session_eap_md5_test.zig");
}

test "session is exposed from the package root" {
    _ = session.Session;
    _ = session.Generation;
}
