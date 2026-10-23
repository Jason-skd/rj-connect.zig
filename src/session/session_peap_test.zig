const std = @import("std");
const eapol = @import("../protocol/eapol.zig");
const session_api = @import("session.zig");

const ActivePhase = session_api.ActivePhase;
const Input = session_api.Input;
const PeapConfig = session_api.PeapConfig;
const Session = session_api.Session;

fn timestamp(nanoseconds: i96) std.Io.Timestamp {
    return .fromNanoseconds(nanoseconds);
}

fn frameInput(value: *const Session, bytes: []const u8) Input {
    return .{ .frame = .{
        .generation = value.currentGeneration(),
        .bytes = bytes,
    } };
}

fn eapolHeader(packet_type: eapol.PacketType, body_len: u16) [eapol.header_size]u8 {
    return .{
        0x01, 0x80, 0xc2, 0x00,                     0x00,                    0x03,
        0xaa, 0xbb, 0xcc, 0xdd,                     0xee,                    0xff,
        0x88, 0x8e, 0x01, @backingInt(packet_type), @intCast(body_len >> 8), @intCast(body_len),
    };
}

fn identityRequest(identifier: u8) [eapol.header_size + 5]u8 {
    var frame: [eapol.header_size + 5]u8 = undefined;
    @memcpy(frame[0..eapol.header_size], &eapolHeader(.eap, 5));
    frame[eapol.header_size..].* = .{ 1, identifier, 0, 5, 1 };
    return frame;
}

fn peapRequest(identifier: u8) [eapol.header_size + 6]u8 {
    var frame: [eapol.header_size + 6]u8 = undefined;
    @memcpy(frame[0..eapol.header_size], &eapolHeader(.eap, 6));
    frame[eapol.header_size..].* = .{ 1, identifier, 0, 6, 25, 0x20 };
    return frame;
}

fn peapConfig() PeapConfig {
    return .{
        .v3_application_data = "app-data",
        .v3_dll_data = "dll-data",
    };
}

fn preparePeapSelection(session: *Session) !void {
    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(session, &identity));
    acquired.deinit(std.testing.allocator);

    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    identified.deinit(std.testing.allocator);
}

test "server-selected PEAP enters a new generation and phase" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = true, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();

    try preparePeapSelection(&session);
    const previous_generation = session.currentGeneration();
    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    defer selected.deinit(std.testing.allocator);

    try std.testing.expectEqual(ActivePhase{ .eap_md5 = .acquired }, selected.previous_phase);
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, selected.phase);
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, session.phase());
    try std.testing.expect(!previous_generation.eql(selected.generation));
    try std.testing.expectEqual(@as(usize, 0), selected.actions.len);

    try std.testing.expectError(
        error.StaleGeneration,
        session.step(timestamp(4 * std.time.ns_per_s), .{ .timer = previous_generation }),
    );
}

test "PEAP request without a PEAP configuration reports a missing dependency" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = true, .peap = true },
    });
    defer session.deinit();

    try preparePeapSelection(&session);
    const request = peapRequest(0x17);
    try std.testing.expectError(
        error.MissingDependency,
        session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request)),
    );
    try std.testing.expectEqual(ActivePhase{ .eap_md5 = .acquired }, session.phase());
}

test "PEAP request is unsupported when PEAP is not allowed" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    defer session.deinit();

    try preparePeapSelection(&session);
    const request = peapRequest(0x17);
    try std.testing.expectError(
        error.UnsupportedEapMethod,
        session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request)),
    );
    try std.testing.expectEqual(ActivePhase{ .eap_md5 = .acquired }, session.phase());
}
