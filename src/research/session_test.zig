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

test "Session rejects direct_session before EAP authentication" {
    var value = try session.Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    defer value.deinit();

    try std.testing.expectError(error.InvalidState, value.step(.fromNanoseconds(0), .{
        .direct_session = .{
            .mode = .{ .sam = .{
                .session_parameter = .{ 1, 2, 3, 4 },
                .endpoint_parameter = .{ 5, 6, 7, 8, 9, 10 },
            } },
            .peer_mac = .{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb },
            .peer_ipv4 = .{ 192, 0, 2, 1 },
            .peer_udp_port = 5678,
            .local_udp_port = 1234,
            .session_id = 0x1122_3344,
            .des_key = @splat(0),
            .initial_iv = @splat(1),
            .timestamp = .{ .monotonic = 100 },
            .username_gbk = "alice",
            .network = .{
                .ipv4 = .{ 192, 0, 2, 10 },
                .netmask = .{ 255, 255, 255, 0 },
                .gateway = .{ 192, 0, 2, 1 },
                .dns = .{ 203, 0, 113, 53 },
                .mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            },
        },
    }));
    try std.testing.expectEqual(session.ActivePhase.idle, value.phase());
}
