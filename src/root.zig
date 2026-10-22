//! By convention, root.zig is the root source file when making a package.
const std = @import("std");
const Io = std.Io;

/// Protocol types and codecs shared by clients and tests.
pub const protocol = @import("protocol/root.zig");

/// Deterministic protocol session orchestration.
pub const session = @import("session/session.zig");

/// This is a documentation comment to explain the `printAnotherMessage` function below.
///
/// Accepting an `Io.Writer` instance is a handy way to write reusable code.
pub fn printAnotherMessage(writer: *Io.Writer) Io.Writer.Error!void {
    try writer.print("Run `zig build test` to run the tests.\n", .{});
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

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

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}
