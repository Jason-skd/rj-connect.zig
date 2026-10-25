const std = @import("std");
const crypto = @import("../protocol/crypto.zig");
const des = @import("../protocol/des.zig");
const direct = @import("../protocol/direct.zig");
const eap = @import("../protocol/eap.zig");
const eapol = @import("../protocol/eapol.zig");
const vendor = @import("../protocol/vendor.zig");
const session_api = @import("session.zig");

const Action = session_api.Action;
const ActivePhase = session_api.ActivePhase;
const CredentialPurpose = session_api.CredentialPurpose;
const ExternalResult = session_api.ExternalResult;
const Input = session_api.Input;
const PeapConfig = session_api.PeapConfig;
const Session = session_api.Session;
const TunnelOperation = session_api.TunnelOperation;
const TunnelStatus = session_api.TunnelStatus;

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

fn terminalRequest(identifier: u8) [eapol.header_size + 4]u8 {
    var frame: [eapol.header_size + 4]u8 = undefined;
    @memcpy(frame[0..eapol.header_size], &eapolHeader(.eap, 4));
    frame[eapol.header_size..].* = .{ 3, identifier, 0, 4 };
    return frame;
}

fn innerRequest(
    output: []u8,
    identifier: u8,
    eap_type: eap.Type,
    data: []const u8,
) []const u8 {
    return eap.encode(.request, identifier, eap_type, data, output) catch unreachable;
}

fn peapFrame(
    output: []u8,
    identifier: u8,
    payload: []const u8,
) []const u8 {
    const eap_len = 5 + payload.len;
    @memcpy(output[0..eapol.header_size], &eapolHeader(.eap, @intCast(eap_len)));
    output[eapol.header_size] = 1;
    output[eapol.header_size + 1] = identifier;
    std.mem.writeInt(u16, output[eapol.header_size + 2 ..][0..2], @intCast(eap_len), .big);
    output[eapol.header_size + 4] = @backingInt(eap.Type.peap);
    @memcpy(output[eapol.header_size + 5 ..][0..payload.len], payload);
    return output[0 .. eapol.header_size + eap_len];
}

fn peapConfig() PeapConfig {
    return .{
        .v3_application_data = "app-data",
        .v3_dll_data = "dll-data",
    };
}

fn directPeapConfig() PeapConfig {
    return .{
        .v3_application_data = "app-data",
        .v3_dll_data = "dll-data",
        .direct_session_id = 0x11223344,
        .local_udp_port = 20000,
        .sam = .{
            .session_parameter = .{ 1, 2, 3, 4 },
            .endpoint_parameter = .{ 1, 2, 3, 4, 5, 6 },
        },
    };
}

fn serverFields(output: []u8, include_radius: bool, heartbeat_seconds: [4]u8) ![]const u8 {
    var offset: usize = 0;
    const fields = [_]vendor.Field{
        .{ .code = 0x56, .value = &.{ 0, 0, 0, 30 } },
        .{ .code = 0x59, .value = &heartbeat_seconds },
        .{ .code = 0x5a, .value = &.{ 0, 0, 0x1f, 0x90 } },
        .{ .code = 0x5b, .value = &.{ 192, 0, 2, 1 } },
        .{ .code = 0x5c, .value = "key-key!" },
        .{ .code = 0x5d, .value = "iv-iv-iv" },
        .{ .code = 0x5e, .value = &.{ 0, 0, 0, 0, 0, 0, 0, 100 } },
        .{ .code = 0x6e, .value = &.{ 0, 0, 0x4e, 0x20 } },
    };
    for (fields) |field| {
        offset += try vendor.writeCompact(output[offset..], field);
    }
    if (include_radius) {
        offset += try vendor.writeCompact(output[offset..], .{ .code = 0x61, .value = &.{9} });
    }
    return output[0..offset];
}

fn encodeDirectAck(
    output: []u8,
    id: u32,
    session_id: u32,
    direct_timestamp: u64,
    sender: direct.Endpoint,
    receiver: direct.Endpoint,
    key: [8]u8,
    iv: [8]u8,
) ![]const u8 {
    const encoded = try direct.encodeFrame(.{
        .version = 1,
        .code = 2,
        .id = id,
        .packet_len = direct.header_size,
        .authenticator = @splat(0),
        .session_id = session_id,
        .timestamp = direct_timestamp,
        .message_type = 1,
        .flags = 0,
        .total_len = 0,
    }, &.{}, sender, receiver, output);
    try direct.setAuthenticator(encoded, key, iv);
    return encoded;
}

fn encodeDirectData(
    output: []u8,
    id: u32,
    session_id: u32,
    direct_timestamp: u64,
    encrypted: []const u8,
    sender: direct.Endpoint,
    receiver: direct.Endpoint,
    key: [8]u8,
    iv: [8]u8,
) ![]u8 {
    const encoded = try direct.encodeFrame(.{
        .version = 1,
        .code = 1,
        .id = id,
        .packet_len = @intCast(direct.header_size + encrypted.len),
        .authenticator = @splat(0),
        .session_id = session_id,
        .timestamp = direct_timestamp,
        .message_type = 1,
        .flags = 1,
        .total_len = @intCast(encrypted.len),
    }, encrypted, sender, receiver, output);
    try direct.setAuthenticator(encoded, key, iv);
    return encoded;
}

fn drivePeapToWaitingDhcp(allocator: std.mem.Allocator, session: *Session, info: []const u8) !void {
    var started = try session.step(timestamp(0), .start);
    started.deinit(allocator);
    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(session, &identity));
    acquired.deinit(allocator);
    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    identified.deinit(allocator);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(session, &request));
    selected.deinit(allocator);

    var identity_buffer: [16]u8 = undefined;
    const inner_identity = innerRequest(&identity_buffer, 1, .identity, &.{});
    var identity_batch = try session.step(timestamp(4 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "client-hello",
                .plaintext = inner_identity,
            },
        },
    });
    identity_batch.deinit(allocator);

    var protected_identity = try session.step(timestamp(5 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    protected_identity.deinit(allocator);

    var challenge_buffer: [32]u8 = undefined;
    const challenge = innerRequest(&challenge_buffer, 2, .mschapv2, &.{ 1, 0x11 });
    var challenge_batch = try session.step(timestamp(6 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "client-identity",
                .plaintext = challenge,
            },
        },
    });
    challenge_batch.deinit(allocator);

    var response = try session.step(timestamp(7 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = session.currentGeneration(),
            .result = .{ .mschapv2_response = .{
                .credentials = .{ .username = "alice", .password = "secret" },
                .response_data = &.{ 2, 0x22 },
            } },
        },
    });
    response.deinit(allocator);

    var success_buffer: [32]u8 = undefined;
    const success_request = innerRequest(&success_buffer, 3, .mschapv2, &.{ 3, 0 });
    var success_batch = try session.step(timestamp(8 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "client-response",
                .plaintext = success_request,
            },
        },
    });
    success_batch.deinit(allocator);

    var verified = try session.step(timestamp(9 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = session.currentGeneration(),
            .result = .{ .mschapv2_success = .{
                .verified = true,
                .response_data = &.{3},
            } },
        },
    });
    verified.deinit(allocator);

    var server_info_batch = try session.step(timestamp(10 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "client-final",
                .plaintext = info,
            },
        },
    });
    server_info_batch.deinit(allocator);

    const success = terminalRequest(0x17);
    var complete = try session.step(timestamp(11 * std.time.ns_per_s), frameInput(session, &success));
    defer complete.deinit(allocator);
    try std.testing.expectEqual(ActivePhase{ .peap = .waiting_dhcp }, complete.phase);
    const deadline = session.nextDeadline().?;
    try std.testing.expectError(
        error.DuplicateFrame,
        session.step(timestamp(12 * std.time.ns_per_s), frameInput(session, &success)),
    );
    try std.testing.expectEqual(deadline, session.nextDeadline().?);
    try std.testing.expectEqual(ActivePhase{ .peap = .waiting_dhcp }, session.phase());
}

fn preparePeapSelection(allocator: std.mem.Allocator, session: *Session) !void {
    var started = try session.step(timestamp(0), .start);
    started.deinit(allocator);

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(session, &identity));
    acquired.deinit(allocator);

    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    identified.deinit(allocator);
}

test "server-selected PEAP enters a new generation and phase" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = true, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();

    try preparePeapSelection(std.testing.allocator, &session);
    const previous_generation = session.currentGeneration();
    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    defer selected.deinit(std.testing.allocator);

    try std.testing.expectEqual(ActivePhase{ .eap_md5 = .acquired }, selected.previous_phase);
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, selected.phase);
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, session.phase());
    try std.testing.expect(!previous_generation.eql(selected.generation));
    try std.testing.expectEqual(@as(usize, 1), selected.actions.len);
    try std.testing.expectEqual(TunnelOperation.process_server_tls, selected.actions[0].tunnel_input.operation);
    try std.testing.expectEqual(@as(usize, 0), selected.actions[0].tunnel_input.bytes.len);

    try std.testing.expectError(
        error.StaleGeneration,
        session.step(timestamp(4 * std.time.ns_per_s), .{ .timer = previous_generation }),
    );
}

test "PEAP tunnel drives TLS, inner EAP, MSCHAPv2, and DHCP waiting" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();

    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);
    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(&session, &identity));
    acquired.deinit(std.testing.allocator);
    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    identified.deinit(std.testing.allocator);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    defer selected.deinit(std.testing.allocator);
    try std.testing.expectEqual(TunnelOperation.process_server_tls, selected.actions[0].tunnel_input.operation);
    try std.testing.expectEqual(@as(usize, 0), selected.actions[0].tunnel_input.bytes.len);

    var inner_identity_buffer: [16]u8 = undefined;
    const inner_identity = innerRequest(&inner_identity_buffer, 1, .identity, &.{});
    var identity_batch = try session.step(timestamp(4 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "tls-client-hello",
                .plaintext = inner_identity,
            },
        },
    });
    defer identity_batch.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), identity_batch.actions.len);
    try std.testing.expectEqual(Action.send_frame, std.meta.activeTag(identity_batch.actions[0]));
    try std.testing.expectEqual(
        CredentialPurpose.peap_identity,
        identity_batch.actions[1].request_credentials,
    );

    var protected_identity = try session.step(timestamp(5 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    defer protected_identity.deinit(std.testing.allocator);
    try std.testing.expectEqual(TunnelOperation.protect_inner_eap, protected_identity.actions[0].tunnel_input.operation);
    const inner_response = try eap.decodePrefix(protected_identity.actions[0].tunnel_input.bytes);
    try std.testing.expectEqual(eap.Type.identity, inner_response.type.?);
    try std.testing.expectEqualSlices(u8, "alice", inner_response.data);

    var challenge_buffer: [32]u8 = undefined;
    const challenge = innerRequest(&challenge_buffer, 2, .mschapv2, &.{ 1, 0x11 });
    var challenge_batch = try session.step(timestamp(6 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "tls-identity",
                .plaintext = challenge,
            },
        },
    });
    defer challenge_batch.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), challenge_batch.actions.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 0x11 },
        challenge_batch.actions[1].authenticate_mschapv2.request_data,
    );

    var mschap_response = try session.step(timestamp(7 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = session.currentGeneration(),
            .result = .{ .mschapv2_response = .{
                .credentials = .{ .username = "alice", .password = "secret" },
                .response_data = &.{ 2, 0x22 },
            } },
        },
    });
    defer mschap_response.deinit(std.testing.allocator);
    const protected_response = mschap_response.actions[0].tunnel_input;
    try std.testing.expectEqual(TunnelOperation.protect_inner_eap, protected_response.operation);
    const parsed_response = try eap.decodePrefix(protected_response.bytes);
    try std.testing.expectEqual(eap.Type.mschapv2, parsed_response.type.?);
    try std.testing.expect(parsed_response.data.len > 2);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0x22 }, parsed_response.data[0..2]);

    var success_request_buffer: [32]u8 = undefined;
    const success_request = innerRequest(&success_request_buffer, 3, .mschapv2, &.{ 3, 0 });
    var success_batch = try session.step(timestamp(8 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "tls-response",
                .plaintext = success_request,
            },
        },
    });
    defer success_batch.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), success_batch.actions.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 3, 0 },
        success_batch.actions[1].verify_mschapv2.request_data,
    );

    var verified = try session.step(timestamp(9 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = session.currentGeneration(),
            .result = .{ .mschapv2_success = .{
                .verified = true,
                .response_data = &.{3},
            } },
        },
    });
    defer verified.deinit(std.testing.allocator);
    try std.testing.expectEqual(TunnelOperation.protect_inner_eap, verified.actions[0].tunnel_input.operation);

    var final_protect = try session.step(timestamp(10 * std.time.ns_per_s), .{
        .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .established,
                .outbound_tls = "tls-success",
            },
        },
    });
    defer final_protect.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), final_protect.actions.len);
    try std.testing.expectEqual(ActivePhase{ .peap = .authenticating }, final_protect.phase);

    const success = terminalRequest(0x17);
    var complete = try session.step(timestamp(11 * std.time.ns_per_s), frameInput(&session, &success));
    defer complete.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase{ .peap = .waiting_dhcp }, complete.phase);
    try std.testing.expectEqual(Action.poll_dhcp, complete.actions[0]);
    try std.testing.expectEqual(@as(u8, 1), session.dhcpPollAttempts());

    var repoll = try session.step(timestamp(13 * std.time.ns_per_s), .{
        .timer = session.currentGeneration(),
    });
    defer repoll.deinit(std.testing.allocator);
    try std.testing.expectEqual(Action.poll_dhcp, repoll.actions[0]);
    try std.testing.expectEqual(@as(u8, 2), session.dhcpPollAttempts());
}

test "PEAP request without a PEAP configuration reports a missing dependency" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = true, .peap = true },
    });
    defer session.deinit();

    try preparePeapSelection(std.testing.allocator, &session);
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

    try preparePeapSelection(std.testing.allocator, &session);
    const request = peapRequest(0x17);
    try std.testing.expectError(
        error.UnsupportedEapMethod,
        session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request)),
    );
    try std.testing.expectEqual(ActivePhase{ .eap_md5 = .acquired }, session.phase());
}

test "PEAP reassembles server TLS fragments before invoking the adapter" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);

    const first = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &first));
    selected.deinit(std.testing.allocator);

    var payload: [9]u8 = undefined;
    _ = try @import("../protocol/peap.zig").encode(
        .{ .more = true, .length_included = true },
        5,
        "abc",
        &payload,
    );
    var frame_buffer: [64]u8 = undefined;
    const first_fragment = peapFrame(&frame_buffer, 0x18, payload[0..8]);
    var waiting = try session.step(timestamp(4 * std.time.ns_per_s), frameInput(&session, first_fragment));
    defer waiting.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), waiting.actions.len);
    try std.testing.expectError(
        error.DuplicateFrame,
        session.step(timestamp(4 * std.time.ns_per_s), frameInput(&session, first_fragment)),
    );

    _ = try @import("../protocol/peap.zig").encode(.{}, null, "de", &payload);
    const second_fragment = peapFrame(&frame_buffer, 0x19, payload[0..3]);
    var delivered = try session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, second_fragment));
    defer delivered.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), delivered.actions.len);
    try std.testing.expectEqualSlices(u8, "abcde", delivered.actions[0].tunnel_input.bytes);
}

test "PEAP rejects a final TLS fragment that disagrees with its declared length" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);

    var payload: [9]u8 = undefined;
    _ = try @import("../protocol/peap.zig").encode(
        .{ .more = true, .length_included = true },
        5,
        "abc",
        &payload,
    );
    var frame_buffer: [64]u8 = undefined;
    const first_fragment = peapFrame(&frame_buffer, 0x18, payload[0..8]);
    var waiting = try session.step(timestamp(4 * std.time.ns_per_s), frameInput(&session, first_fragment));
    waiting.deinit(std.testing.allocator);

    _ = try @import("../protocol/peap.zig").encode(.{}, null, "d", &payload);
    const short_fragment = peapFrame(&frame_buffer, 0x19, payload[0..2]);
    try std.testing.expectError(
        error.InvalidTunnelInput,
        session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, short_fragment)),
    );

    _ = try @import("../protocol/peap.zig").encode(.{}, null, "de", &payload);
    const final_fragment = peapFrame(&frame_buffer, 0x19, payload[0..3]);
    var delivered = try session.step(timestamp(6 * std.time.ns_per_s), frameInput(&session, final_fragment));
    defer delivered.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, "abcde", delivered.actions[0].tunnel_input.bytes);
}

test "PEAP rejects out-of-order fragments and conflicting declared lengths" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);

    var payload: [16]u8 = undefined;
    _ = try @import("../protocol/peap.zig").encode(
        .{ .more = true, .length_included = true },
        5,
        "abc",
        &payload,
    );
    var frame_buffer: [64]u8 = undefined;
    const first_fragment = peapFrame(&frame_buffer, 0x18, payload[0..8]);
    var waiting = try session.step(timestamp(4 * std.time.ns_per_s), frameInput(&session, first_fragment));
    waiting.deinit(std.testing.allocator);

    const old_fragment = peapFrame(&frame_buffer, 0x17, payload[0..1]);
    try std.testing.expectError(
        error.StaleIdentifier,
        session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, old_fragment)),
    );

    _ = try @import("../protocol/peap.zig").encode(
        .{ .more = true, .length_included = true },
        6,
        "d",
        &payload,
    );
    const conflicting_fragment = peapFrame(&frame_buffer, 0x19, payload[0..6]);
    try std.testing.expectError(
        error.InvalidTunnelInput,
        session.step(timestamp(6 * std.time.ns_per_s), frameInput(&session, conflicting_fragment)),
    );

    _ = try @import("../protocol/peap.zig").encode(.{}, null, "de", &payload);
    const final_fragment = peapFrame(&frame_buffer, 0x19, payload[0..3]);
    var delivered = try session.step(timestamp(7 * std.time.ns_per_s), frameInput(&session, final_fragment));
    defer delivered.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, "abcde", delivered.actions[0].tunnel_input.bytes);

    _ = try @import("../protocol/peap.zig").encode(
        .{ .more = true, .length_included = true },
        64 * 1024 + 1,
        "x",
        &payload,
    );
    const oversized_fragment = peapFrame(&frame_buffer, 0x1a, payload[0..6]);
    try std.testing.expectError(
        error.InvalidTunnelInput,
        session.step(timestamp(8 * std.time.ns_per_s), frameInput(&session, oversized_fragment)),
    );
}

test "PEAP TLS failure and unsupported modes do not advance the session" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);

    try std.testing.expectError(
        error.UnsupportedPeapMode,
        session.step(timestamp(4 * std.time.ns_per_s), .{ .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{ .version = 1, .status = .established },
        } }),
    );
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, session.phase());

    var failed = try session.step(timestamp(5 * std.time.ns_per_s), .{ .tunnel_output = .{
        .generation = session.currentGeneration(),
        .output = .{ .status = .failed },
    } });
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase.idle, failed.phase);
    try std.testing.expectEqual(session_api.FailureReason.tls_failed, failed.failure.?);
    try std.testing.expectEqual(ActivePhase.idle, session.phase());
}

test "PEAP rejects plaintext before TLS establishment" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);

    var identity_buffer: [16]u8 = undefined;
    const inner_identity = innerRequest(&identity_buffer, 1, .identity, &.{});
    try std.testing.expectError(
        error.InvalidTunnelInput,
        session.step(timestamp(4 * std.time.ns_per_s), .{ .tunnel_output = .{
            .generation = session.currentGeneration(),
            .output = .{
                .status = .more_data,
                .plaintext = inner_identity,
            },
        } }),
    );
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, session.phase());
}

test "PEAP cancellation sends one logoff and reaches idle" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);
    var canceled = try session.step(timestamp(4 * std.time.ns_per_s), .cancel);
    defer canceled.deinit(std.testing.allocator);

    try std.testing.expectEqual(ActivePhase.idle, canceled.phase);
    try std.testing.expectEqual(@as(usize, 1), canceled.actions.len);
    const logoff = try eapol.decode(canceled.actions[0].send_frame);
    try std.testing.expectEqual(eapol.PacketType.logoff, logoff.packet_type);
}

test "PEAP rejects stale tunnel output and times out without leaking" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
        .auth_timeout = .fromSeconds(5),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);
    const old_generation = session.currentGeneration();
    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);

    try std.testing.expectError(
        error.StaleGeneration,
        session.step(timestamp(4 * std.time.ns_per_s), .{ .tunnel_output = .{
            .generation = old_generation,
            .output = .{ .status = .established },
        } }),
    );
    try std.testing.expectEqual(ActivePhase{ .peap = .handshake }, session.phase());

    var timed_out = try session.step(timestamp(8 * std.time.ns_per_s), .{
        .timer = session.currentGeneration(),
    });
    defer timed_out.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase.idle, timed_out.phase);
    try std.testing.expectEqual(session_api.FailureReason.auth_timeout, timed_out.failure.?);
}

test "PEAP remote logoff ends the session without sending another frame" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(std.testing.allocator, &session);
    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(std.testing.allocator);

    var logoff_frame: [eapol.header_size]u8 = undefined;
    eapol.encodeLogoff(
        .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        &logoff_frame,
    );
    var ended = try session.step(timestamp(4 * std.time.ns_per_s), frameInput(&session, &logoff_frame));
    defer ended.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase.idle, ended.phase);
    try std.testing.expectEqual(@as(usize, 0), ended.actions.len);
    try std.testing.expectEqual(session_api.FailureReason.server_logoff, ended.failure.?);
}

test "PEAP configuration allocation failure does not leak" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        Session.init(failing.allocator(), .{
            .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
            .allowed_methods = .{ .md5_challenge = false, .peap = true },
            .peap = peapConfig(),
        }),
    );
}

test "PEAP TLS reassembly allocation failure preserves the queued fragment" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var session = try Session.init(failing.allocator(), .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(failing.allocator(), &session);

    const request = peapRequest(0x17);
    var selected = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &request));
    selected.deinit(failing.allocator());

    var payload: [9]u8 = undefined;
    _ = try @import("../protocol/peap.zig").encode(
        .{ .more = true, .length_included = true },
        5,
        "abc",
        &payload,
    );
    var frame_buffer: [64]u8 = undefined;
    const first_fragment = peapFrame(&frame_buffer, 0x18, payload[0..8]);

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        session.step(timestamp(4 * std.time.ns_per_s), frameInput(&session, first_fragment)),
    );
    failing.fail_index = std.math.maxInt(usize);

    var waiting = try session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, first_fragment));
    defer waiting.deinit(failing.allocator());
    try std.testing.expectEqual(@as(usize, 0), waiting.actions.len);
}

fn peapTunnelAllocationScenario(allocator: std.mem.Allocator) !void {
    var session = try Session.init(allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();

    var info_buffer: [128]u8 = undefined;
    const info = try serverFields(&info_buffer, true, .{ 0, 0, 0, 10 });
    try drivePeapToWaitingDhcp(allocator, &session, info);
}

fn peapDirectAllocationScenario(allocator: std.mem.Allocator) !void {
    var session = try Session.init(allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = directPeapConfig(),
    });
    defer session.deinit();

    var info_buffer: [128]u8 = undefined;
    const info = try serverFields(&info_buffer, true, .{ 0, 0, 0, 10 });
    try drivePeapToWaitingDhcp(allocator, &session, info);
    var direct_outcome = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = session.currentGeneration(),
            .result = .{ .dhcp_lease = .{
                .ip = .{ 192, 0, 2, 10 },
                .netmask = .{ 255, 255, 255, 0 },
                .gateway = .{ 192, 0, 2, 1 },
                .dns = .{ 203, 0, 113, 53 },
            } },
        },
    });
    direct_outcome.deinit(allocator);
}

test "PEAP tunnel and Direct handoff clean up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        peapTunnelAllocationScenario,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        peapDirectAllocationScenario,
        .{},
    );
}

test "complete PEAP DHCP lease starts Direct in the same lifecycle" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = directPeapConfig(),
    });
    defer session.deinit();

    var info_buffer: [128]u8 = undefined;
    const info = try serverFields(&info_buffer, true, .{ 0, 0, 0, 10 });
    try drivePeapToWaitingDhcp(std.testing.allocator, &session, info);
    const peap_generation = session.currentGeneration();

    var direct_outcome = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = peap_generation,
            .result = .{ .dhcp_lease = .{
                .ip = .{ 192, 0, 2, 10 },
                .netmask = .{ 255, 255, 255, 0 },
                .gateway = .{ 192, 0, 2, 1 },
                .dns = .{ 203, 0, 113, 53 },
            } },
        },
    });
    defer direct_outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(ActivePhase{ .direct = .initializing }, direct_outcome.phase);
    try std.testing.expectEqual(ActivePhase{ .direct = .initializing }, session.phase());
    try std.testing.expect(!peap_generation.eql(session.currentGeneration()));
    try std.testing.expectEqual(@as(usize, 1), direct_outcome.actions.len);
    _ = try direct.decodeFrame(direct_outcome.actions[0].send_frame);
}

test "PEAP Direct reauthentication returns idle and permits explicit restart" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = directPeapConfig(),
    });
    defer session.deinit();

    var info_buffer: [128]u8 = undefined;
    const info = try serverFields(&info_buffer, true, .{ 0, 0, 0, 0 });
    try drivePeapToWaitingDhcp(std.testing.allocator, &session, info);

    var started = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .external_result = .{
            .generation = session.currentGeneration(),
            .result = .{ .dhcp_lease = .{
                .ip = .{ 192, 0, 2, 10 },
                .netmask = .{ 255, 255, 255, 0 },
                .gateway = .{ 192, 0, 2, 1 },
                .dns = .{ 203, 0, 113, 53 },
            } },
        },
    });
    const handshake = try direct.decodeFrame(started.actions[0].send_frame);
    started.deinit(std.testing.allocator);

    var des_key: [8]u8 = undefined;
    _ = try crypto.applyRc4("com.ruijie.www", "key-key!", &des_key);
    var initial_iv: [8]u8 = undefined;
    _ = try crypto.applyRc4("com.ruijie.www", "iv-iv-iv", &initial_iv);

    var ack_buffer: [256]u8 = undefined;
    const handshake_ack = try encodeDirectAck(
        &ack_buffer,
        handshake.header.id,
        handshake.header.session_id,
        handshake.header.timestamp,
        handshake.destination,
        handshake.source,
        des_key,
        initial_iv,
    );
    var acknowledged = try session.step(
        timestamp(13 * std.time.ns_per_s),
        frameInput(&session, handshake_ack),
    );
    const user_info = try direct.decodeFrame(acknowledged.actions[0].send_frame);
    acknowledged.deinit(std.testing.allocator);

    var user_ack_buffer: [256]u8 = undefined;
    const user_ack = try encodeDirectAck(
        &user_ack_buffer,
        user_info.header.id,
        user_info.header.session_id,
        user_info.header.timestamp,
        user_info.destination,
        user_info.source,
        des_key,
        initial_iv,
    );
    var awaiting_result = try session.step(
        timestamp(14 * std.time.ns_per_s),
        frameInput(&session, user_ack),
    );
    awaiting_result.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase{ .direct = .awaiting_result }, session.phase());

    var result_payload: [16]u8 = @splat(0);
    result_payload[0..13].* = .{
        1,    1,   12,
        0x09, 8,   0x02,
        2,    'o', 'k',
        0x13, 1,   1,
        0,
    };
    var result_encrypted: [16]u8 = undefined;
    _ = try des.encryptCbc(des_key, initial_iv, &result_payload, &result_encrypted);
    var result_buffer: [256]u8 = undefined;
    const result_frame = try encodeDirectData(
        &result_buffer,
        77,
        user_info.header.session_id,
        user_info.header.timestamp + 1,
        &result_encrypted,
        user_info.destination,
        user_info.source,
        des_key,
        initial_iv,
    );
    var active = try session.step(
        timestamp(15 * std.time.ns_per_s),
        frameInput(&session, result_frame),
    );
    active.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase{ .direct = .active }, session.phase());

    var reauth = try session.step(timestamp(45 * std.time.ns_per_s), .{
        .timer = session.currentGeneration(),
    });
    defer reauth.deinit(std.testing.allocator);
    try std.testing.expectEqual(Action.reauth_required, reauth.actions[0]);
    try std.testing.expectEqual(ActivePhase.idle, reauth.phase);

    var restarted = try session.step(timestamp(46 * std.time.ns_per_s), .start);
    defer restarted.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase{ .eap_md5 = .connecting }, restarted.phase);
    try std.testing.expectEqual(@as(usize, 1), restarted.actions.len);
}

test "missing PEAP Direct parameters fail without leaving the waiting state" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = directPeapConfig(),
    });
    defer session.deinit();

    var info_buffer: [128]u8 = undefined;
    const info = try serverFields(&info_buffer, false, .{ 0, 0, 0, 10 });
    try drivePeapToWaitingDhcp(std.testing.allocator, &session, info);
    const generation = session.currentGeneration();

    try std.testing.expectError(
        error.MissingDirectParameters,
        session.step(timestamp(12 * std.time.ns_per_s), .{
            .external_result = .{
                .generation = generation,
                .result = .{ .dhcp_lease = .{
                    .ip = .{ 192, 0, 2, 10 },
                    .netmask = .{ 255, 255, 255, 0 },
                    .gateway = .{ 192, 0, 2, 1 },
                    .dns = .{ 203, 0, 113, 53 },
                } },
            },
        }),
    );
    try std.testing.expectEqual(ActivePhase{ .peap = .waiting_dhcp }, session.phase());
}
