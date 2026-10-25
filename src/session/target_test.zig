const std = @import("std");
const crypto = @import("../protocol/crypto.zig");
const eapol = @import("../protocol/eapol.zig");
const ruijie = @import("../protocol/ruijie_eap_md5.zig");
const session = @import("session.zig");

const client_mac = [6]u8{ 0x00, 0xe0, 0x4c, 0x5f, 0x63, 0x98 };
const server_mac = [6]u8{ 0x00, 0x1a, 0xa9, 0x17, 0xff, 0xff };
const challenge = [16]u8{
    0xef, 0x88, 0x56, 0x45, 0x9d, 0x2e, 0x42, 0x10,
    0x7b, 0x57, 0xbc, 0x25, 0xe4, 0x0f, 0x88, 0x79,
};
const v3_text = "5562e31ad473d66ad197870cd134e5984c94ef3ed83e0cda412322ac94c41d7c" ++
    "8ea82238aa6bf1dba586162cf9a39bee952fcedc566a8a462c51f4913bb77299";
const zero_iv_chain = [16]u8{
    0x44, 0xbc, 0x4e, 0x8f, 0x73, 0x1e, 0x1a, 0x4b,
    0x42, 0x87, 0x74, 0xcc, 0x66, 0x6e, 0x17, 0x89,
};
const challenge_chain = [16]u8{
    0xef, 0x5a, 0x98, 0x0a, 0x53, 0xc5, 0xa5, 0xf7,
    0xf3, 0xf7, 0x3e, 0x1d, 0x91, 0x21, 0x30, 0x19,
};

fn facts() session.Facts {
    return .{
        .source_mac = client_mac,
        .service_name = "students",
        .disk_serial = "",
        .lease = .{
            .dhcp_enabled = true,
            .ip = .{ 10, 252, 135, 58 },
            .netmask = .{ 255, 255, 240, 0 },
            .gateway = .{ 10, 252, 128, 1 },
            .dns = .{ 222, 200, 129, 134 },
        },
        .alternate_dns_text = "202.116.32.254",
        .os_bits = 0x40,
    };
}

fn config() session.Config {
    return .{
        .facts = facts(),
        .credentials = .{ .username = "alice", .password = "secret" },
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

fn frameInput(value: *const session.Session, bytes: []const u8) session.Input {
    return .{ .frame = .{
        .generation = value.currentGeneration(),
        .bytes = bytes,
    } };
}

fn attribute(frame: []const u8, tail_start: usize, code: u8) ?[]const u8 {
    var offset = tail_start + ruijie.prefix_len;
    while (offset + 2 <= frame.len) {
        if (frame[offset] != 0x1a) return null;
        const total: usize = frame[offset + 1];
        if (total < 8 or offset + total > frame.len) return null;
        if (frame[offset + 6] == code) {
            const value_len: usize = frame[offset + 7] - 2;
            return frame[offset + 8 .. offset + 8 + value_len];
        }
        offset += total;
    }
    return null;
}

test "start emits the target Start frame with the zero-IV tail" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var outcome = try value.step(.fromNanoseconds(0), .start);
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(session.Phase.connecting, outcome.phase);
    try std.testing.expectEqual(@as(usize, 1), outcome.actions.len);
    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 584), frame.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 }, frame[0..6]);
    try std.testing.expectEqualSlices(u8, &client_mac, frame[6..12]);
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x8e, 0x01, 0x01, 0x00, 0x00 }, frame[12..18]);
    try std.testing.expectEqual(@as(usize, 566), frame.len - eapol.header_size);
    try std.testing.expectEqualSlices(u8, &zero_iv_chain, attribute(frame, 18, 0x2f).?);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0x02, 0x02 }, frame[18 + 59 .. 18 + 63]);
    try std.testing.expectEqual(@as(u8, 0x00), frame[18 + 63]);
}

test "identity request produces a response carrying the username and tail" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const request = try serverFrame(std.testing.allocator, .request, 7, .identity, &.{});
    defer std.testing.allocator.free(request);
    var outcome = try value.step(.fromNanoseconds(1), frameInput(&value, request));
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(session.Phase.acquired, outcome.phase);
    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 594), frame.len);
    try std.testing.expectEqualSlices(u8, &server_mac, frame[0..6]);
    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x07, 0x00, 0x0a, 0x01 }, frame[18..23]);
    try std.testing.expectEqualSlices(u8, "alice", frame[23..28]);
    try std.testing.expectEqualSlices(u8, &zero_iv_chain, attribute(frame, 28, 0x2f).?);
    try std.testing.expectEqual(@as(u8, 0x00), attribute(frame, 28, 0x62).?[0]);
    try std.testing.expectEqual(@as(usize, 128), attribute(frame, 28, 0x4d).?.len);
    try std.testing.expectEqual(@as(u8, 0), attribute(frame, 28, 0x35).?[0]);
}

test "MD5 challenge updates the chain and V3 digest before Success" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const identity = try serverFrame(std.testing.allocator, .request, 7, .identity, &.{});
    defer std.testing.allocator.free(identity);
    var identity_outcome = try value.step(.fromNanoseconds(1), frameInput(&value, identity));
    identity_outcome.deinit(std.testing.allocator);

    var challenge_data: [19]u8 = undefined;
    challenge_data[0] = 16;
    @memcpy(challenge_data[1..17], &challenge);
    @memcpy(challenge_data[17..19], "rj");
    const request = try serverFrame(
        std.testing.allocator,
        .request,
        8,
        .md5_challenge,
        &challenge_data,
    );
    defer std.testing.allocator.free(request);
    var outcome = try value.step(.fromNanoseconds(2), frameInput(&value, request));
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(session.Phase.authenticating, outcome.phase);
    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 611), frame.len);
    try std.testing.expectEqual(@as(u8, 16), frame[23]);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xcc, 0x1a, 0x78, 0xd6, 0xad, 0xc6, 0xc0, 0x2b, 0x9f, 0xdf, 0xb4, 0xf2, 0x04, 0xd9, 0xf3, 0xea },
        frame[24..40],
    );
    try std.testing.expectEqualSlices(u8, "alice", frame[40..45]);
    try std.testing.expectEqualSlices(u8, &challenge_chain, attribute(frame, 45, 0x2f).?);
    try std.testing.expectEqualSlices(u8, v3_text, attribute(frame, 45, 0x4d).?);
    try std.testing.expectEqual(@as(u8, 1), attribute(frame, 45, 0x62).?[0]);

    const success_data = [_]u8{ 0x00, 0x00, 0x13, 0x11, 0x00, 0x02, 'o', 'k' };
    const success = try serverFrame(
        std.testing.allocator,
        .success,
        8,
        null,
        &success_data,
    );
    defer std.testing.allocator.free(success);
    var done = try value.step(.fromNanoseconds(3), frameInput(&value, success));
    defer done.deinit(std.testing.allocator);

    try std.testing.expectEqual(session.Phase.authenticated, done.phase);
    try std.testing.expectEqual(@as(usize, 0), done.actions.len);
    try std.testing.expectEqual(session.TerminalKind.success, done.terminal.?.kind);
    try std.testing.expectEqualSlices(u8, "ok", done.terminal.?.notification);
}

test "facts updates change IPv6 slots on later frames only" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const link_local = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const global = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    var updated = facts();
    updated.ipv6_state = 5;
    updated.ipv6_link_local = link_local;
    updated.ipv6_global = global;
    var facts_outcome = try value.step(.fromNanoseconds(1), .{ .facts = updated });
    facts_outcome.deinit(std.testing.allocator);

    const request = try serverFrame(std.testing.allocator, .request, 7, .identity, &.{});
    defer std.testing.allocator.free(request);
    var outcome = try value.step(.fromNanoseconds(2), frameInput(&value, request));
    defer outcome.deinit(std.testing.allocator);

    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(u8, 5), attribute(frame, 28, 0x35).?[0]);
    try std.testing.expectEqualSlices(u8, &link_local, attribute(frame, 28, 0x38).?);
    try std.testing.expectEqualSlices(u8, &global, attribute(frame, 28, 0x4e).?);
}

test "Failure enters held and exposes the private notification" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);
    const identity = try serverFrame(std.testing.allocator, .request, 7, .identity, &.{});
    defer std.testing.allocator.free(identity);
    var identity_outcome = try value.step(.fromNanoseconds(1), frameInput(&value, identity));
    identity_outcome.deinit(std.testing.allocator);

    const failure_data = [_]u8{
        0x00, 0x00, 0x13, 0x11, 0x00, 0x03, 'b', 'a', 'd',
    };
    const failure = try serverFrame(
        std.testing.allocator,
        .failure,
        7,
        null,
        &failure_data,
    );
    defer std.testing.allocator.free(failure);
    var outcome = try value.step(.fromNanoseconds(2), frameInput(&value, failure));
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(session.Phase.held, outcome.phase);
    try std.testing.expectEqual(session.FailureReason.server_failure, outcome.failure.?);
    try std.testing.expectEqualSlices(u8, "bad", outcome.terminal.?.notification);
}

test "connecting timer retries Start and advances the generation" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);
    const first_generation = value.currentGeneration();

    var outcome = try value.step(.fromNanoseconds(30 * std.time.ns_per_s), .{ .timer = first_generation });
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), outcome.actions.len);
    try std.testing.expectEqual(@as(usize, 584), outcome.actions[0].send_frame.len);
    try std.testing.expect(!outcome.generation.eql(first_generation));

    const identity = try serverFrame(std.testing.allocator, .request, 9, .identity, &.{});
    defer std.testing.allocator.free(identity);
    try std.testing.expectError(
        error.StaleGeneration,
        value.step(.fromNanoseconds(31 * std.time.ns_per_s), .{ .frame = .{
            .generation = first_generation,
            .bytes = identity,
        } }),
    );
}

test "cancel sends a tailed Logoff" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    var outcome = try value.step(.fromNanoseconds(1), .cancel);
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(session.Phase.idle, outcome.phase);
    try std.testing.expectEqual(session.FailureReason.canceled, outcome.failure.?);
    const frame = outcome.actions[0].send_frame;
    try std.testing.expectEqual(@as(usize, 584), frame.len);
    try std.testing.expectEqual(@as(u8, 2), frame[15]);
    try std.testing.expectEqual(@as(u8, 0x01), frame[18 + 63]);
    try std.testing.expectEqualSlices(u8, &zero_iv_chain, attribute(frame, 18, 0x2f).?);
}

test "unsupported methods and malformed flows fail explicitly" {
    var value = try session.Session.init(std.testing.allocator, config());
    defer value.deinit();

    var started = try value.step(.fromNanoseconds(0), .start);
    started.deinit(std.testing.allocator);

    const peap = try serverFrame(std.testing.allocator, .request, 7, .peap, &.{});
    defer std.testing.allocator.free(peap);
    try std.testing.expectError(
        error.UnsupportedEapMethod,
        value.step(.fromNanoseconds(1), frameInput(&value, peap)),
    );

    const identity = try serverFrame(std.testing.allocator, .request, 7, .identity, &.{});
    defer std.testing.allocator.free(identity);
    var outcome = try value.step(.fromNanoseconds(2), frameInput(&value, identity));
    outcome.deinit(std.testing.allocator);

    try std.testing.expectError(
        error.DuplicateFrame,
        value.step(.fromNanoseconds(3), frameInput(&value, identity)),
    );
    try std.testing.expectError(
        error.TimerNotDue,
        value.step(.fromNanoseconds(3), .{ .timer = value.currentGeneration() }),
    );
}

test "init validates credentials and facts" {
    var bad_username = config();
    bad_username.credentials.username = "";
    try std.testing.expectError(
        error.InvalidCredentials,
        session.Session.init(std.testing.allocator, bad_username),
    );

    var bad_facts = config();
    bad_facts.facts.os_bits = 0x10;
    try std.testing.expectError(
        error.InvalidFacts,
        session.Session.init(std.testing.allocator, bad_facts),
    );

    var bad_timeout = config();
    bad_timeout.auth_timeout = .fromSeconds(0);
    try std.testing.expectError(
        error.InvalidConfig,
        session.Session.init(std.testing.allocator, bad_timeout),
    );
}

test "challenge chain matches the independent crypto primitive" {
    var chain: [ruijie.max_chain_len]u8 = undefined;
    const len = try crypto.encryptPassword("alice", challenge, "secret", &chain);
    try std.testing.expectEqualSlices(u8, &challenge_chain, chain[0..len]);
}
