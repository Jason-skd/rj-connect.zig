const std = @import("std");
const session = @import("session.zig");

test "Session starts idle and deinit is idempotent" {
    var value = try session.Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });

    try std.testing.expectEqual(session.ActivePhase.idle, value.phase());
    value.deinit();
    value.deinit();
}

test "Session deinit releases an active protocol machine" {
    var value = try session.Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var started = try value.step(.fromNanoseconds(0), .start);
    defer started.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        session.ActivePhase{ .eap_md5 = .connecting },
        value.phase(),
    );
    value.deinit();
    value.deinit();
    try std.testing.expectEqual(session.ActivePhase.idle, value.phase());
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), value.nextDeadline());
}
