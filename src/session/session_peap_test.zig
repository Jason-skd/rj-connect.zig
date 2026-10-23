const std = @import("std");
const eap = @import("../protocol/eap.zig");
const eapol = @import("../protocol/eapol.zig");
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

test "PEAP reassembles server TLS fragments before invoking the adapter" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(&session);

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

    _ = try @import("../protocol/peap.zig").encode(.{}, null, "de", &payload);
    const second_fragment = peapFrame(&frame_buffer, 0x19, payload[0..3]);
    var delivered = try session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, second_fragment));
    defer delivered.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), delivered.actions.len);
    try std.testing.expectEqualSlices(u8, "abcde", delivered.actions[0].tunnel_input.bytes);
}

test "PEAP TLS failure and unsupported modes do not advance the session" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(&session);

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

test "PEAP cancellation sends one logoff and reaches idle" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .allowed_methods = .{ .md5_challenge = false, .peap = true },
        .peap = peapConfig(),
    });
    defer session.deinit();
    try preparePeapSelection(&session);

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
