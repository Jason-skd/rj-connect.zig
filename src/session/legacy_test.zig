const std = @import("std");
const eapol = @import("../protocol/eapol.zig");
const legacy = @import("legacy_session.zig");

const client_mac = [6]u8{ 0x8c, 0x53, 0xc3, 0x9d, 0x42, 0x19 };
const server_mac = [6]u8{ 0x00, 0x1a, 0xa9, 0x17, 0xff, 0xff };
const challenge = [16]u8{
    0x10, 0x4c, 0xf0, 0xea, 0xd9, 0xd2, 0xb1, 0xc4,
    0x9f, 0x2a, 0xee, 0x50, 0x45, 0xcc, 0xc3, 0x00,
};
const expected_tail = @embedFile("../protocol/mh031_tail_prefix.bin");

fn config() legacy.Config {
    return .{
        .source_mac = client_mac,
        .credentials = .{ .username = "testuser123", .password = "secret" },
    };
}

fn serverFrame(
    allocator: std.mem.Allocator,
    code: eapol.EapCode,
    identifier: u8,
    eap_type: ?eapol.EapType,
    data: []const u8,
) ![]u8 {
    var buffer: [700]u8 = undefined;
    const encoded = try eapol.encodeEap(
        client_mac,
        server_mac,
        code,
        identifier,
        eap_type,
        data,
        &buffer,
    );
    return allocator.dupe(u8, encoded);
}

fn frameInput(value: *const legacy.Session, bytes: []const u8) legacy.Input {
    return .{ .frame = .{
        .generation = value.currentGeneration(),
        .bytes = bytes,
    } };
}

fn prepare(value: *legacy.Session) !void {
    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const identity = try serverFrame(std.testing.allocator, .request, 1, .identity, &.{});
    defer std.testing.allocator.free(identity);
    var acquired = try value.step(.fromNanoseconds(1), frameInput(value, identity));
    acquired.deinit(std.testing.allocator);

    var challenge_data: [17]u8 = undefined;
    challenge_data[0] = 16;
    @memcpy(challenge_data[1..], &challenge);
    const md5 = try serverFrame(
        std.testing.allocator,
        .request,
        2,
        .md5_challenge,
        &challenge_data,
    );
    defer std.testing.allocator.free(md5);
    var response = try value.step(.fromNanoseconds(2), frameInput(value, md5));
    response.deinit(std.testing.allocator);
}

test "legacy Start uses the fixed compatibility tail" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var outcome = try value.step(.fromNanoseconds(0), .start);
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(legacy.Phase.connecting, outcome.phase);
    try std.testing.expectEqual(@as(usize, 1), outcome.actions.len);
    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 1000), frame.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }, frame[0..6]);
    try std.testing.expectEqualSlices(
        u8,
        expected_tail,
        frame[18..][0..expected_tail.len],
    );
}

test "legacy Identity and MD5 response preserve the target proof shape" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();
    try prepare(&value);

    try std.testing.expectEqual(legacy.Phase.authenticating, value.phase());
}

test "legacy response uses value_size 16 and the password proof" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const identity = try serverFrame(std.testing.allocator, .request, 1, .identity, &.{});
    defer std.testing.allocator.free(identity);
    var acquired = try value.step(.fromNanoseconds(1), frameInput(&value, identity));
    acquired.deinit(std.testing.allocator);

    var challenge_data: [17]u8 = undefined;
    challenge_data[0] = 16;
    @memcpy(challenge_data[1..], &challenge);
    const md5 = try serverFrame(
        std.testing.allocator,
        .request,
        2,
        .md5_challenge,
        &challenge_data,
    );
    defer std.testing.allocator.free(md5);
    var outcome = try value.step(.fromNanoseconds(2), frameInput(&value, md5));
    defer outcome.deinit(std.testing.allocator);

    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 1000), frame.len);
    try std.testing.expectEqual(@as(u8, 2), frame[18]);
    try std.testing.expectEqual(@as(u8, 2), frame[19]);
    try std.testing.expectEqual(@as(u8, 4), frame[22]);
    try std.testing.expectEqual(@as(u8, 16), frame[23]);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x35, 0xa4, 0x23, 0x65, 0x09, 0xd5, 0xe1, 0xee, 0x71, 0xc9, 0xb5, 0x01, 0x7d, 0xc4, 0xa7, 0xcc },
        frame[24..40],
    );
    try std.testing.expectEqualSlices(u8, "testuser123", frame[40..51]);
    try std.testing.expectEqualSlices(u8, expected_tail, frame[51..][0..expected_tail.len]);
    try std.testing.expectEqual(@as(u16, 33), std.mem.readInt(u16, frame[16..18], .big));
    try std.testing.expectEqual(@as(u16, 33), std.mem.readInt(u16, frame[20..22], .big));
}

test "legacy Success authenticates and Failure enters held" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();
    try prepare(&value);

    const success = try serverFrame(std.testing.allocator, .success, 2, null, &.{});
    defer std.testing.allocator.free(success);
    var done = try value.step(.fromNanoseconds(3), frameInput(&value, success));
    defer done.deinit(std.testing.allocator);
    try std.testing.expectEqual(legacy.Phase.authenticated, done.phase);

    var failed = try legacy.Session.init(std.testing.allocator, config());
    defer failed.deinit();
    try prepare(&failed);
    const failure = try serverFrame(std.testing.allocator, .failure, 2, null, &.{});
    defer std.testing.allocator.free(failure);
    var held = try failed.step(.fromNanoseconds(3), frameInput(&failed, failure));
    defer held.deinit(std.testing.allocator);
    try std.testing.expectEqual(legacy.Phase.held, held.phase);
    try std.testing.expectEqual(legacy.FailureReason.server_failure, held.failure.?);
}

test "legacy Failure with a mismatched identifier is a terminal protocol error" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();
    try prepare(&value);

    const failure = try serverFrame(std.testing.allocator, .failure, 1, null, &.{});
    defer std.testing.allocator.free(failure);
    try std.testing.expectError(
        error.StaleTerminalIdentifier,
        value.step(.fromNanoseconds(3), frameInput(&value, failure)),
    );
}

test "public session facade selects the legacy profile explicitly" {
    const session = @import("session.zig");
    var value = try session.Session.initLegacy(std.testing.allocator, config());
    defer value.deinit();

    try std.testing.expectEqual(session.Profile.mentohust_0_3_1_wired, value.profile());
    var outcome = try value.step(.fromNanoseconds(0), .start);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1000), outcome.actions[0].send_frame.len);
}

test "legacy identity and response match captured declared lengths" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const identity = try serverFrame(std.testing.allocator, .request, 1, .identity, &.{});
    defer std.testing.allocator.free(identity);
    var acquired = try value.step(.fromNanoseconds(1), frameInput(&value, identity));
    defer acquired.deinit(std.testing.allocator);
    const identity_frame = acquired.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 1000), identity_frame.len);
    try std.testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, identity_frame[16..18], .big));
    try std.testing.expectEqualSlices(u8, "testuser123", identity_frame[23..34]);
    try std.testing.expectEqualSlices(u8, expected_tail, identity_frame[34..][0..expected_tail.len]);

    var challenge_data: [17]u8 = undefined;
    challenge_data[0] = 16;
    @memcpy(challenge_data[1..], &challenge);
    const md5 = try serverFrame(std.testing.allocator, .request, 2, .md5_challenge, &challenge_data);
    defer std.testing.allocator.free(md5);
    var response = try value.step(.fromNanoseconds(2), frameInput(&value, md5));
    defer response.deinit(std.testing.allocator);
    const response_frame = response.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 1000), response_frame.len);
    try std.testing.expectEqual(@as(u16, 33), std.mem.readInt(u16, response_frame[16..18], .big));
    try std.testing.expectEqualSlices(u8, expected_tail, response_frame[51..][0..expected_tail.len]);
}

test "legacy retry and logoff keep the fixed frame shape" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);
    const generation = value.currentGeneration();

    var retry = try value.step(.fromNanoseconds(30 * std.time.ns_per_s), .{ .timer = generation });
    defer retry.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), retry.actions.len);
    try std.testing.expectEqual(@as(usize, 1000), retry.actions[0].send_frame.len);
    try std.testing.expectEqual(@as(u8, 1), retry.actions[0].send_frame[15]);

    var canceled = try value.step(.fromNanoseconds(31 * std.time.ns_per_s), .cancel);
    defer canceled.deinit(std.testing.allocator);
    try std.testing.expectEqual(legacy.Phase.idle, canceled.phase);
    try std.testing.expectEqual(@as(usize, 1), canceled.actions.len);
    try std.testing.expectEqual(@as(usize, 1000), canceled.actions[0].send_frame.len);
    try std.testing.expectEqual(@as(u8, 2), canceled.actions[0].send_frame[15]);
}

test "legacy Failure before a response enters held without a terminal identifier" {
    var value = try legacy.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);
    const failure = try serverFrame(std.testing.allocator, .failure, 7, null, &.{});
    defer std.testing.allocator.free(failure);
    var held = try value.step(.fromNanoseconds(1), frameInput(&value, failure));
    defer held.deinit(std.testing.allocator);
    try std.testing.expectEqual(legacy.Phase.held, held.phase);
    try std.testing.expectEqual(legacy.FailureReason.server_failure, held.failure.?);
}
