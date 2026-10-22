const std = @import("std");
const eapol = @import("../protocol/eapol.zig");
const direct = @import("../protocol/direct.zig");
const session_api = @import("session.zig");

const Action = session_api.Action;
const ActivePhase = session_api.ActivePhase;
const CredentialPurpose = session_api.CredentialPurpose;
const DhcpStep = session_api.DhcpStep;
const ExternalResult = session_api.ExternalResult;
const FailureReason = session_api.FailureReason;
const Input = session_api.Input;
const Session = session_api.Session;

const Phase = struct {
    const disconnected: ActivePhase = .idle;
    const connecting: ActivePhase = .{ .eap_md5 = .connecting };
    const acquired: ActivePhase = .{ .eap_md5 = .acquired };
    const authenticating: ActivePhase = .{ .eap_md5 = .authenticating };
    const authenticated: ActivePhase = .{ .eap_md5 = .authenticated };
    const held: ActivePhase = .{ .eap_md5 = .held };
    const logoff: ActivePhase = .idle;
};

fn timestamp(nanoseconds: i96) std.Io.Timestamp {
    return .fromNanoseconds(nanoseconds);
}

fn frameInput(value: *const Session, bytes: []const u8) Input {
    return .{ .frame = .{
        .generation = value.currentGeneration(),
        .bytes = bytes,
    } };
}

fn timerInput(value: *const Session) Input {
    return .{ .timer = value.currentGeneration() };
}

fn externalResultInput(value: *const Session, result: ExternalResult) Input {
    return .{ .external_result = .{
        .generation = value.currentGeneration(),
        .result = result,
    } };
}

test "Session start enters connecting and emits EAPOL Start" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var outcome = try session.step(timestamp(0), .start);
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expectEqual(Phase.disconnected, outcome.previous_phase);
    try std.testing.expectEqual(Phase.connecting, outcome.phase);
    try std.testing.expectEqual(Phase.connecting, session.phase());
    try std.testing.expectEqual(@as(usize, 1), outcome.actions.len);
    try std.testing.expectEqualSlices(u8, &.{
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x88, 0x8e, 0x01, 0x00, 0x00, 0x00,
    }, outcome.actions[0].send_frame);
    try std.testing.expectEqual(timestamp(std.time.ns_per_s * 30), outcome.next_deadline.?);
}

test "Session accepts the caller's initial timestamp without assuming an epoch" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    const initial = timestamp(-5 * std.time.ns_per_s);
    var outcome = try session.step(initial, .start);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        timestamp(25 * std.time.ns_per_s),
        outcome.next_deadline.?,
    );
}

test "Session rejects frames and timers from a previous connection attempt" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .start_timeout = .fromSeconds(10),
        .max_start_attempts = 2,
    });
    var started = try session.step(timestamp(0), .start);
    const previous_generation = started.generation;
    started.deinit(std.testing.allocator);

    var retried = try session.step(
        timestamp(10 * std.time.ns_per_s),
        .{ .timer = previous_generation },
    );
    const current_generation = retried.generation;
    retried.deinit(std.testing.allocator);
    try std.testing.expect(!previous_generation.eql(current_generation));

    const identity = identityRequest(0x16);
    try std.testing.expectError(
        error.StaleGeneration,
        session.step(timestamp(11 * std.time.ns_per_s), .{ .frame = .{
            .generation = previous_generation,
            .bytes = &identity,
        } }),
    );
    try std.testing.expectError(
        error.StaleGeneration,
        session.step(timestamp(11 * std.time.ns_per_s), .{ .timer = previous_generation }),
    );

    var acquired = try session.step(timestamp(11 * std.time.ns_per_s), .{ .frame = .{
        .generation = current_generation,
        .bytes = &identity,
    } });
    defer acquired.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.acquired, acquired.phase);
}

fn eapolHeader(
    packet_type: eapol.PacketType,
    body_len: u16,
) [eapol.header_size]u8 {
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

fn md5ChallengeRequest(identifier: u8) [eapol.header_size + 22]u8 {
    var frame: [eapol.header_size + 22]u8 = undefined;
    @memcpy(frame[0..eapol.header_size], &eapolHeader(.eap, 22));
    frame[eapol.header_size..][0..5].* = .{ 1, identifier, 0, 22, 4 };
    frame[eapol.header_size + 5] = 16;
    for (0..16) |index| frame[eapol.header_size + 6 + index] = @intCast(index);
    return frame;
}

fn terminalRequest(code: eapol.EapCode, identifier: u8) [eapol.header_size + 4]u8 {
    var frame: [eapol.header_size + 4]u8 = undefined;
    @memcpy(frame[0..eapol.header_size], &eapolHeader(.eap, 4));
    frame[eapol.header_size..].* = .{ @backingInt(code), identifier, 0, 4 };
    return frame;
}

fn prepareChallengeSession(session: *Session) !void {
    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(session, &identity));
    acquired.deinit(std.testing.allocator);

    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    identified.deinit(std.testing.allocator);

    const challenge = md5ChallengeRequest(0x17);
    var challenged = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(session, &challenge));
    challenged.deinit(std.testing.allocator);

    var answered = try session.step(timestamp(4 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    answered.deinit(std.testing.allocator);
}

test "Session drives EAP-MD5 from start to authenticated" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });

    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(&session, &identity));
    defer acquired.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.acquired, acquired.phase);
    try std.testing.expectEqual(CredentialPurpose.identity, acquired.actions[0].request_credentials);

    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    defer identified.deinit(std.testing.allocator);
    const identity_response = try eapol.decode(identified.actions[0].send_frame);
    try std.testing.expectEqual(eapol.EapCode.response, identity_response.eap.?.code);
    try std.testing.expectEqual(@as(u8, 0x16), identity_response.eap.?.identifier);
    try std.testing.expectEqual(@as(?eapol.EapType, .identity), identity_response.eap.?.type);
    try std.testing.expectEqualSlices(u8, "alice", identity_response.eap.?.data);

    const challenge = md5ChallengeRequest(0x17);
    var challenged = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &challenge));
    defer challenged.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, challenged.phase);
    try std.testing.expectEqual(CredentialPurpose.md5_challenge, challenged.actions[0].request_credentials);

    var answered = try session.step(timestamp(4 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    defer answered.deinit(std.testing.allocator);
    const md5_response = try eapol.decode(answered.actions[0].send_frame);
    try std.testing.expectEqual(@as(u8, 0x17), md5_response.eap.?.identifier);
    try std.testing.expectEqual(@as(?eapol.EapType, .md5_challenge), md5_response.eap.?.type);
    try std.testing.expectEqual(@as(u8, 32), md5_response.eap.?.data[0]);
    try std.testing.expectEqualSlices(
        u8,
        "274e6550014566df49bb07457d33ca38alice",
        md5_response.eap.?.data[1..],
    );

    const success = terminalRequest(.success, 0x17);
    var authenticated = try session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, &success));
    defer authenticated.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, authenticated.previous_phase);
    try std.testing.expectEqual(Phase.authenticated, authenticated.phase);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), authenticated.next_deadline);
    try std.testing.expectEqual(@as(usize, 0), authenticated.actions.len);
}

test "Session holds server failures and logs off after the retry limit" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .max_auth_failures = 1,
    });
    try prepareChallengeSession(&session);

    const failure = terminalRequest(.failure, 0x17);
    var held = try session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, &failure));
    defer held.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, held.previous_phase);
    try std.testing.expectEqual(Phase.held, held.phase);
    try std.testing.expectEqual(FailureReason.server_failure, held.failure.?);
    try std.testing.expectEqual(timestamp(35 * std.time.ns_per_s), held.next_deadline.?);

    try std.testing.expectError(
        error.TimerNotDue,
        session.step(timestamp(34 * std.time.ns_per_s), timerInput(&session)),
    );
    try std.testing.expectEqual(Phase.held, session.phase());
    try std.testing.expectEqual(FailureReason.server_failure, session.failure().?);

    var logged_off = try session.step(timestamp(35 * std.time.ns_per_s), timerInput(&session));
    defer logged_off.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.logoff, logged_off.phase);
    try std.testing.expectEqual(FailureReason.server_failure, logged_off.failure.?);
    try std.testing.expectEqual(@as(usize, 1), logged_off.actions.len);
    const logoff = try eapol.decode(logged_off.actions[0].send_frame);
    try std.testing.expectEqual(eapol.PacketType.logoff, logoff.packet_type);
}

test "Session counts authentication failures across reconnects" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .max_auth_failures = 2,
        .held_timeout = .fromSeconds(5),
    });
    try prepareChallengeSession(&session);

    const first_failure = terminalRequest(.failure, 0x17);
    var first_held = try session.step(
        timestamp(5 * std.time.ns_per_s),
        frameInput(&session, &first_failure),
    );
    try std.testing.expectEqual(FailureReason.server_failure, first_held.failure.?);
    first_held.deinit(std.testing.allocator);

    var retry = try session.step(timestamp(10 * std.time.ns_per_s), timerInput(&session));
    retry.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, session.phase());

    const second_identity = identityRequest(0x18);
    var acquired = try session.step(
        timestamp(11 * std.time.ns_per_s),
        frameInput(&session, &second_identity),
    );
    acquired.deinit(std.testing.allocator);

    var identified = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    identified.deinit(std.testing.allocator);

    const second_challenge = md5ChallengeRequest(0x19);
    var challenged = try session.step(
        timestamp(13 * std.time.ns_per_s),
        frameInput(&session, &second_challenge),
    );
    challenged.deinit(std.testing.allocator);

    var answered = try session.step(timestamp(14 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    answered.deinit(std.testing.allocator);

    const second_failure = terminalRequest(.failure, 0x19);
    var second_held = try session.step(
        timestamp(15 * std.time.ns_per_s),
        frameInput(&session, &second_failure),
    );
    try std.testing.expectEqual(Phase.held, session.phase());
    second_held.deinit(std.testing.allocator);

    var logged_off = try session.step(timestamp(20 * std.time.ns_per_s), timerInput(&session));
    defer logged_off.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.logoff, logged_off.phase);
    try std.testing.expectEqual(FailureReason.server_failure, logged_off.failure.?);
}

test "Session distinguishes authentication timeout and retries connecting" {
    var auth_session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .max_auth_failures = 2,
        .held_timeout = .fromSeconds(5),
    });
    try prepareChallengeSession(&auth_session);

    var auth_held = try auth_session.step(timestamp(35 * std.time.ns_per_s), timerInput(&auth_session));
    defer auth_held.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.held, auth_held.phase);
    try std.testing.expectEqual(FailureReason.auth_timeout, auth_held.failure.?);

    var retried = try auth_session.step(timestamp(40 * std.time.ns_per_s), timerInput(&auth_session));
    defer retried.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, retried.phase);
    try std.testing.expectEqual(@as(?FailureReason, null), retried.failure);
    try std.testing.expectEqual(@as(usize, 1), retried.actions.len);

    var start_session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .start_timeout = .fromSeconds(10),
        .max_start_attempts = 2,
    });
    var started = try start_session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);
    var start_retry = try start_session.step(timestamp(10 * std.time.ns_per_s), timerInput(&start_session));
    start_retry.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, start_session.phase());

    var start_held = try start_session.step(timestamp(20 * std.time.ns_per_s), timerInput(&start_session));
    defer start_held.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.held, start_held.phase);
    try std.testing.expectEqual(FailureReason.start_timeout, start_held.failure.?);
}

test "Session cancellation and server Logoff terminate without duplicate cleanup" {
    var canceled_session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var started = try canceled_session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    var canceled = try canceled_session.step(timestamp(std.time.ns_per_s), .cancel);
    defer canceled.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, canceled.previous_phase);
    try std.testing.expectEqual(Phase.logoff, canceled.phase);
    try std.testing.expectEqual(FailureReason.canceled, canceled.failure.?);
    try std.testing.expectEqual(@as(usize, 1), canceled.actions.len);

    var restarted = try canceled_session.step(timestamp(2 * std.time.ns_per_s), .start);
    restarted.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, canceled_session.phase());
    try std.testing.expectEqual(@as(?FailureReason, null), canceled_session.failure());

    var remote_logoff_frame: [eapol.header_size]u8 = undefined;
    eapol.encodeLogoff(
        .{ 1, 0x80, 0xc2, 0, 0, 3 },
        .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        &remote_logoff_frame,
    );
    var remote_logoff = try canceled_session.step(
        timestamp(3 * std.time.ns_per_s),
        frameInput(&canceled_session, &remote_logoff_frame),
    );
    defer remote_logoff.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.logoff, remote_logoff.phase);
    try std.testing.expectEqual(FailureReason.server_logoff, remote_logoff.failure.?);
    try std.testing.expectEqual(@as(usize, 0), remote_logoff.actions.len);
}

test "Session becomes disconnected after logoff cleanup" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    var canceled = try session.step(timestamp(std.time.ns_per_s), .cancel);
    try std.testing.expectEqual(Phase.logoff, canceled.phase);
    canceled.deinit(std.testing.allocator);

    try std.testing.expectEqual(Phase.disconnected, session.phase());
    try std.testing.expectEqual(FailureReason.canceled, session.failure().?);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), session.nextDeadline());
}

test "Session rejects stale and duplicate frames without changing state" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    var peap_frame: [eapol.header_size + 5]u8 = undefined;
    @memcpy(peap_frame[0..eapol.header_size], &eapolHeader(.eap, 5));
    peap_frame[eapol.header_size..].* = .{ 1, 0x16, 0, 5, 25 };
    try std.testing.expectError(
        error.UnsupportedEapMethod,
        session.step(timestamp(std.time.ns_per_s), frameInput(&session, &peap_frame)),
    );
    try std.testing.expectEqual(Phase.connecting, session.phase());

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(&session, &identity));
    acquired.deinit(std.testing.allocator);
    const deadline = session.nextDeadline();

    try std.testing.expectError(
        error.DuplicateFrame,
        session.step(timestamp(2 * std.time.ns_per_s), frameInput(&session, &identity)),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());
    try std.testing.expectEqual(deadline, session.nextDeadline());

    const old_identity = identityRequest(0x15);
    try std.testing.expectError(
        error.StaleIdentifier,
        session.step(timestamp(2 * std.time.ns_per_s), frameInput(&session, &old_identity)),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());

    const success = terminalRequest(.success, 0x16);
    try std.testing.expectError(
        error.InvalidState,
        session.step(timestamp(2 * std.time.ns_per_s), frameInput(&session, &success)),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());

    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    identified.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidInput,
        session.step(timestamp(2 * std.time.ns_per_s), .{
            .credentials = .{ .username = "alice", .password = "" },
        }),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());

    try std.testing.expectError(
        error.TimeWentBackwards,
        session.step(timestamp(0), timerInput(&session)),
    );
}

test "Session performs DHCP second authentication before reporting success" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .dhcp_second_auth = true,
    });
    try prepareChallengeSession(&session);
    try std.testing.expectEqual(DhcpStep.first, session.dhcpStep());

    const first_success = terminalRequest(.success, 0x17);
    var waiting_for_dhcp = try session.step(
        timestamp(5 * std.time.ns_per_s),
        frameInput(&session, &first_success),
    );
    defer waiting_for_dhcp.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, waiting_for_dhcp.phase);
    try std.testing.expectEqual(Action.poll_dhcp, waiting_for_dhcp.actions[0]);
    try std.testing.expectEqual(timestamp(7 * std.time.ns_per_s), waiting_for_dhcp.next_deadline.?);

    try std.testing.expectError(
        error.DuplicateFrame,
        session.step(timestamp(6 * std.time.ns_per_s), frameInput(&session, &first_success)),
    );
    try std.testing.expectEqual(Phase.authenticating, session.phase());
    try std.testing.expectEqual(timestamp(7 * std.time.ns_per_s), session.nextDeadline().?);

    var incomplete_lease = try session.step(timestamp(6 * std.time.ns_per_s), externalResultInput(
        &session,
        .{ .dhcp_lease = .{ .ip = .{ 192, 0, 2, 10 } } },
    ));
    defer incomplete_lease.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, incomplete_lease.phase);
    try std.testing.expectEqual(@as(usize, 0), incomplete_lease.actions.len);

    var polled_again = try session.step(timestamp(7 * std.time.ns_per_s), timerInput(&session));
    defer polled_again.deinit(std.testing.allocator);
    try std.testing.expectEqual(Action.poll_dhcp, polled_again.actions[0]);

    const first_cycle_generation = session.currentGeneration();
    var second_cycle = try session.step(timestamp(8 * std.time.ns_per_s), externalResultInput(
        &session,
        .{ .dhcp_lease = .{
            .ip = .{ 192, 0, 2, 10 },
            .gateway = .{ 192, 0, 2, 1 },
        } },
    ));
    defer second_cycle.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, second_cycle.phase);
    try std.testing.expectEqual(DhcpStep.second, session.dhcpStep());
    try std.testing.expectEqual(@as(usize, 1), second_cycle.actions.len);

    const second_identity = identityRequest(0x18);
    try std.testing.expectError(
        error.StaleGeneration,
        session.step(timestamp(9 * std.time.ns_per_s), .{ .external_result = .{
            .generation = first_cycle_generation,
            .result = .{ .dhcp_lease = .{
                .ip = .{ 198, 51, 100, 20 },
                .gateway = .{ 198, 51, 100, 1 },
            } },
        } }),
    );
    var acquired = try session.step(timestamp(9 * std.time.ns_per_s), frameInput(&session, &second_identity));
    acquired.deinit(std.testing.allocator);
    var identified = try session.step(timestamp(10 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    identified.deinit(std.testing.allocator);
    const second_challenge = md5ChallengeRequest(0x19);
    var challenged = try session.step(timestamp(11 * std.time.ns_per_s), frameInput(&session, &second_challenge));
    challenged.deinit(std.testing.allocator);
    var answered = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    answered.deinit(std.testing.allocator);

    const second_success = terminalRequest(.success, 0x19);
    var authenticated = try session.step(timestamp(13 * std.time.ns_per_s), frameInput(&session, &second_success));
    defer authenticated.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticated, authenticated.phase);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), authenticated.next_deadline);
}

test "Session terminates with a distinct DHCP timeout after 21 polls" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .dhcp_second_auth = true,
    });
    try prepareChallengeSession(&session);

    const success = terminalRequest(.success, 0x17);
    var first_poll = try session.step(timestamp(5 * std.time.ns_per_s), frameInput(&session, &success));
    first_poll.deinit(std.testing.allocator);

    var now: i96 = 7 * std.time.ns_per_s;
    for (2..22) |attempt| {
        var poll = try session.step(timestamp(now), timerInput(&session));
        poll.deinit(std.testing.allocator);
        try std.testing.expectEqual(Phase.authenticating, session.phase());
        try std.testing.expectEqual(@as(u8, @intCast(attempt)), session.dhcpPollAttempts());
        now += 2 * std.time.ns_per_s;
    }

    var timed_out = try session.step(timestamp(now), timerInput(&session));
    defer timed_out.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.logoff, timed_out.phase);
    try std.testing.expectEqual(FailureReason.dhcp_timeout, timed_out.failure.?);
    try std.testing.expectEqual(@as(usize, 1), timed_out.actions.len);
}

test "Session allocation failures do not commit partial authentication state" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var session = try Session.init(failing.allocator(), .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var started = try session.step(timestamp(0), .start);
    started.deinit(failing.allocator());

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), frameInput(&session, &identity));
    acquired.deinit(failing.allocator());
    const deadline = session.nextDeadline();

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        session.step(timestamp(2 * std.time.ns_per_s), .{
            .credentials = .{ .username = "alice", .password = "" },
        }),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());
    try std.testing.expectEqual(deadline, session.nextDeadline());

    failing.fail_index = std.math.maxInt(usize);
    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    identified.deinit(failing.allocator());
    try std.testing.expectEqual(Phase.acquired, session.phase());

    const challenge = md5ChallengeRequest(0x17);
    var challenged = try session.step(timestamp(3 * std.time.ns_per_s), frameInput(&session, &challenge));
    challenged.deinit(failing.allocator());
    const challenge_deadline = session.nextDeadline();

    failing.fail_index = failing.alloc_index + 1;
    try std.testing.expectError(
        error.OutOfMemory,
        session.step(timestamp(4 * std.time.ns_per_s), .{
            .credentials = .{ .username = "alice", .password = "" },
        }),
    );
    try std.testing.expectEqual(Phase.authenticating, session.phase());
    try std.testing.expectEqual(challenge_deadline, session.nextDeadline());

    failing.fail_index = std.math.maxInt(usize);
    var answered = try session.step(timestamp(4 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    answered.deinit(failing.allocator());
    try std.testing.expectEqual(Phase.authenticating, session.phase());
}

test "Session acknowledges Notification and responds to Credential requests" {
    var session = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    var started = try session.step(timestamp(0), .start);
    started.deinit(std.testing.allocator);

    var notification_frame: [eapol.header_size + 5]u8 = undefined;
    @memcpy(notification_frame[0..eapol.header_size], &eapolHeader(.eap, 5));
    notification_frame[eapol.header_size..].* = .{ 1, 0x16, 0, 5, 2 };
    var notified = try session.step(timestamp(std.time.ns_per_s), frameInput(&session, &notification_frame));
    defer notified.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, notified.phase);
    const notification_response = try eapol.decode(notified.actions[0].send_frame);
    try std.testing.expectEqual(eapol.EapCode.response, notification_response.eap.?.code);
    try std.testing.expectEqual(@as(?eapol.EapType, .notification), notification_response.eap.?.type);
    try std.testing.expectEqual(@as(usize, 0), notification_response.eap.?.data.len);

    var credential_frame: [eapol.header_size + 5]u8 = undefined;
    @memcpy(credential_frame[0..eapol.header_size], &eapolHeader(.eap, 5));
    credential_frame[eapol.header_size..].* = .{ 1, 0x17, 0, 5, 7 };
    var credential_request = try session.step(timestamp(2 * std.time.ns_per_s), frameInput(&session, &credential_frame));
    defer credential_request.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, credential_request.phase);
    try std.testing.expectEqual(
        CredentialPurpose.credential_request,
        credential_request.actions[0].request_credentials,
    );

    var credential_response = try session.step(timestamp(3 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    defer credential_response.deinit(std.testing.allocator);
    const decoded = try eapol.decode(credential_response.actions[0].send_frame);
    try std.testing.expectEqual(@as(?eapol.EapType, .credential), decoded.eap.?.type);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 5, 'a', 'l', 'i', 'c', 'e', 's', 'e', 'c', 'r', 'e', 't' },
        decoded.eap.?.data,
    );
}

test "Session starts SAM direct communication and accepts its ACK" {
    const des_key = [8]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const initial_iv = [8]u8{ 8, 9, 10, 11, 12, 13, 14, 15 };
    var value = try Session.init(std.testing.allocator, .{
        .source_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    });
    defer value.deinit();
    try prepareChallengeSession(&value);

    const success = terminalRequest(.success, 0x17);
    var authenticated = try value.step(timestamp(5 * std.time.ns_per_s), frameInput(&value, &success));
    authenticated.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticated, value.phase());

    var started = try value.step(timestamp(6 * std.time.ns_per_s), .{
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
            .des_key = des_key,
            .initial_iv = initial_iv,
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
    });
    defer started.deinit(std.testing.allocator);

    try std.testing.expectEqual(Phase.authenticated, started.previous_phase);
    try std.testing.expectEqual(
        ActivePhase{ .direct = .initializing },
        started.phase,
    );
    try std.testing.expectEqual(timestamp(9 * std.time.ns_per_s), started.next_deadline.?);
    try std.testing.expectEqual(@as(usize, 1), started.actions.len);

    const frame = try direct.decodeFrame(started.actions[0].send_frame);
    try std.testing.expectEqual(@as(u8, 1), frame.header.code);
    try std.testing.expectEqual(@as(u8, 1), frame.header.flags);
    try std.testing.expectEqual(@as(u32, 0x1122_3344), frame.header.session_id);
    try std.testing.expectEqual(@as(u16, 1234), frame.source.port);
    try std.testing.expectEqual(@as(u16, 5678), frame.destination.port);

    var plaintext: [256]u8 = undefined;
    const plaintext_len = try @import("../protocol/des.zig").decryptCbc(
        des_key,
        initial_iv,
        frame.encrypted,
        &plaintext,
    );
    try std.testing.expectEqualSlices(u8, &.{
        0x01, 0x01, 0x02,
        0x03, 0x05, 'a',
        'l',  'i',  'c',
        'e',  0x04, 0x04,
        1,    2,    3,
        4,    0x05, 0x06,
        5,    6,    7,
        8,    9,    10,
    }, plaintext[0..24]);
    try std.testing.expect(plaintext_len >= 24);

    var bypass: [14]u8 = @splat(0);
    std.mem.writeInt(u16, bypass[12..14], 0x0806, .big);
    var bypassed = try value.step(timestamp(7 * std.time.ns_per_s), frameInput(&value, &bypass));
    bypassed.deinit(std.testing.allocator);
    try std.testing.expectEqual(timestamp(9 * std.time.ns_per_s), value.nextDeadline().?);

    var rejected_ack_buffer: [256]u8 = undefined;
    const rejected_ack = try encodeAck(
        &rejected_ack_buffer,
        frame.header.id + 1,
        frame.header.session_id,
        frame.header.timestamp,
        frame.destination,
        frame.source,
        des_key,
        initial_iv,
    );
    var rejected = try value.step(
        timestamp(7 * std.time.ns_per_s),
        frameInput(&value, rejected_ack),
    );
    rejected.deinit(std.testing.allocator);
    try std.testing.expectEqual(timestamp(9 * std.time.ns_per_s), value.nextDeadline().?);

    var ack_buffer: [256]u8 = undefined;
    const ack = try encodeAck(
        &ack_buffer,
        frame.header.id,
        frame.header.session_id,
        frame.header.timestamp,
        frame.destination,
        frame.source,
        des_key,
        initial_iv,
    );
    var acknowledged = try value.step(
        timestamp(7 * std.time.ns_per_s),
        frameInput(&value, ack),
    );
    defer acknowledged.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase{ .direct = .initializing }, acknowledged.phase);
    try std.testing.expectEqual(@as(usize, 1), acknowledged.actions.len);
    try std.testing.expectEqual(timestamp(10 * std.time.ns_per_s), value.nextDeadline().?);

    const user_info_frame = try direct.decodeFrame(acknowledged.actions[0].send_frame);
    var user_info_plaintext: [256]u8 = undefined;
    const user_info_len = try @import("../protocol/des.zig").decryptCbc(
        des_key,
        initial_iv,
        user_info_frame.encrypted,
        &user_info_plaintext,
    );
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 8 }, user_info_plaintext[0..3]);
    try std.testing.expect(user_info_len >= 3);

    var user_ack_buffer: [256]u8 = undefined;
    const user_ack = try encodeAck(
        &user_ack_buffer,
        user_info_frame.header.id,
        user_info_frame.header.session_id,
        user_info_frame.header.timestamp,
        user_info_frame.destination,
        user_info_frame.source,
        des_key,
        initial_iv,
    );
    var waiting = try value.step(
        timestamp(8 * std.time.ns_per_s),
        frameInput(&value, user_ack),
    );
    defer waiting.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        ActivePhase{ .direct = .awaiting_result },
        waiting.phase,
    );
    try std.testing.expectEqual(timestamp(17 * std.time.ns_per_s), value.nextDeadline().?);

    var result_payload: [16]u8 = @splat(0);
    result_payload[0..13].* = .{
        1,    1,   12,
        0x09, 8,   0x02,
        2,    'o', 'k',
        0x13, 1,   1,
        0,
    };
    var result_encrypted: [16]u8 = undefined;
    _ = try @import("../protocol/des.zig").encryptCbc(
        des_key,
        initial_iv,
        &result_payload,
        &result_encrypted,
    );
    var result_frame_buffer: [256]u8 = undefined;
    const result_frame = try encodeData(
        &result_frame_buffer,
        77,
        result_encrypted.len,
        101,
        &result_encrypted,
        user_info_frame.destination,
        user_info_frame.source,
        des_key,
        initial_iv,
    );
    var completed = try value.step(
        timestamp(9 * std.time.ns_per_s),
        frameInput(&value, result_frame),
    );
    defer completed.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase{ .direct = .active }, completed.phase);
    try std.testing.expectEqual(@as(usize, 2), completed.actions.len);
    const auth = completed.actions[1].direct_auth_result;
    try std.testing.expect(auth.success);
    try std.testing.expectEqualStrings("ok", auth.server_message_gbk.?);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), value.nextDeadline());

    var canceled = try value.step(timestamp(10 * std.time.ns_per_s), .cancel);
    defer canceled.deinit(std.testing.allocator);
    try std.testing.expectEqual(ActivePhase.idle, canceled.phase);
    try std.testing.expectEqual(FailureReason.canceled, canceled.failure.?);
    try std.testing.expectEqual(@as(usize, 1), canceled.actions.len);
    const logoff = try eapol.decode(canceled.actions[0].send_frame);
    try std.testing.expectEqual(eapol.PacketType.logoff, logoff.packet_type);
    try std.testing.expectError(
        error.InvalidState,
        value.step(timestamp(11 * std.time.ns_per_s), .cancel),
    );
}

fn encodeAck(
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

fn encodeData(
    output: []u8,
    id: u32,
    total_len: u32,
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
        .session_id = 0x1122_3344,
        .timestamp = direct_timestamp,
        .message_type = 1,
        .flags = 1,
        .total_len = total_len,
    }, encrypted, sender, receiver, output);
    try direct.setAuthenticator(encoded, key, iv);
    return encoded;
}
