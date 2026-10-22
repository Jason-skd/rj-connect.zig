//! Deterministic EAP-MD5 authentication state and external event handling.

const std = @import("std");
const eapol = @import("eapol.zig");

pub const Phase = enum {
    disconnected,
    connecting,
    acquired,
    authenticating,
    authenticated,
    held,
    logoff,
};

pub const Config = struct {
    source_mac: [6]u8,
    destination_mac: [6]u8 = eapol.default_destination,
    start_timeout: std.Io.Duration = .fromSeconds(30),
    auth_timeout: std.Io.Duration = .fromSeconds(30),
    held_timeout: std.Io.Duration = .fromSeconds(30),
    max_start_attempts: u16 = 3,
    max_auth_failures: u16 = 3,
    dhcp_second_auth: bool = false,
};

pub const CredentialPurpose = enum {
    identity,
    md5_challenge,
    credential_request,
};

pub const FailureReason = enum {
    server_failure,
    start_timeout,
    auth_timeout,
    canceled,
    dhcp_timeout,
    server_logoff,
};

pub const DhcpStep = enum(u8) {
    none = 0,
    first = 1,
    second = 2,
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const DhcpLease = struct {
    ip: ?[4]u8 = null,
    gateway: ?[4]u8 = null,
};

pub const ExternalResult = union(enum) {
    dhcp_lease: DhcpLease,
};

/// Byte slices in an input event are borrowed and must remain valid for one call only.
pub const Input = union(enum) {
    start,
    cancel,
    frame: []const u8,
    timer: void,
    credentials: Credentials,
    tunnel_input: []const u8,
    external_result: ExternalResult,
};

pub const Action = union(enum) {
    send_frame: []u8,
    request_credentials: CredentialPurpose,
    poll_dhcp,
};

pub const Outcome = struct {
    /// Sending actions own their frame bytes until `deinit` is called.
    actions: []Action,
    previous_phase: Phase,
    phase: Phase,
    next_deadline: ?std.Io.Timestamp,
    failure: ?FailureReason,

    /// Releases every owned frame and the action slice using the allocator passed to `Session.init`.
    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        for (self.actions) |action| {
            switch (action) {
                .send_frame => |frame| allocator.free(frame),
                else => {},
            }
        }
        allocator.free(self.actions);
        self.* = undefined;
    }
};

pub const Error = error{
    InvalidConfig,
    InvalidInput,
    InvalidFrame,
    InvalidCredentials,
    InvalidState,
    DuplicateFrame,
    StaleIdentifier,
    TimerNotDue,
    UnsupportedEapMethod,
    TimeWentBackwards,
    TimestampOverflow,
    OutOfMemory,
};

const PendingCredentials = enum {
    identity,
    md5_challenge,
    credential_request,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    config: Config,
    current_phase: Phase,
    current_deadline: ?std.Io.Timestamp,
    last_now: ?std.Io.Timestamp,
    current_identifier: ?u8,
    last_inbound_type: ?eapol.EapType,
    last_response_identifier: ?u8,
    challenge: ?[16]u8,
    pending_credentials: ?PendingCredentials,
    peer_mac: ?[6]u8,
    connect_attempts: u16,
    auth_failures: u16,
    failure_reason: ?FailureReason,
    dhcp_step: DhcpStep,
    dhcp_poll_attempts: u8,
    network_completion_pending: bool,
    awaiting_dhcp_result: bool,

    /// Creates a disconnected session. No allocation occurs until `step` produces an outcome.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Session {
        if (config.start_timeout.toNanoseconds() <= 0 or
            config.auth_timeout.toNanoseconds() <= 0 or
            config.held_timeout.toNanoseconds() <= 0 or
            config.max_start_attempts == 0 or
            config.max_auth_failures == 0)
        {
            return error.InvalidConfig;
        }

        return .{
            .allocator = allocator,
            .config = config,
            .current_phase = .disconnected,
            .current_deadline = null,
            .last_now = null,
            .current_identifier = null,
            .last_inbound_type = null,
            .last_response_identifier = null,
            .challenge = null,
            .pending_credentials = null,
            .peer_mac = null,
            .connect_attempts = 0,
            .auth_failures = 0,
            .failure_reason = null,
            .dhcp_step = .none,
            .dhcp_poll_attempts = 0,
            .network_completion_pending = false,
            .awaiting_dhcp_result = false,
        };
    }

    pub fn phase(self: *const Session) Phase {
        return self.current_phase;
    }

    pub fn nextDeadline(self: *const Session) ?std.Io.Timestamp {
        return self.current_deadline;
    }

    pub fn failure(self: *const Session) ?FailureReason {
        return self.failure_reason;
    }

    pub fn dhcpStep(self: *const Session) DhcpStep {
        return self.dhcp_step;
    }

    pub fn dhcpPollAttempts(self: *const Session) u8 {
        return self.dhcp_poll_attempts;
    }

    /// Accepts one external event and commits state only after every returned action is allocated.
    pub fn step(self: *Session, now: std.Io.Timestamp, input: Input) Error!Outcome {
        if (self.last_now) |last_now| {
            if (now.compare(.lt, last_now)) return error.TimeWentBackwards;
        }

        var next = self.*;
        next.last_now = now;
        const previous_phase = next.current_phase;
        var builder = OutcomeBuilder.init(next.allocator);
        errdefer builder.deinit();

        switch (input) {
            .start => {
                if (next.current_phase != .disconnected and next.current_phase != .logoff) {
                    return error.InvalidState;
                }

                next.resetAuthentication();
                next.auth_failures = 0;
                next.failure_reason = null;
                next.dhcp_step = .none;
                next.dhcp_poll_attempts = 0;
                next.network_completion_pending = false;
                next.awaiting_dhcp_result = false;
                next.connect_attempts = 1;
                try next.enterConnecting(now);
                try builder.addFrame(try next.makeStartFrame());
            },
            .frame => |bytes| {
                const frame = eapol.decode(bytes) catch return error.InvalidFrame;
                try next.handleFrame(now, frame, &builder);
            },
            .credentials => |credentials| {
                try next.handleCredentials(now, credentials, &builder);
            },
            .timer => try next.handleTimer(now, &builder),
            .cancel => try next.handleCancel(&builder),
            .external_result => |result| try next.handleExternalResult(now, result, &builder),
            .tunnel_input => return error.InvalidInput,
        }

        const actions = try builder.finish();
        self.* = next;
        const outcome_phase: Phase = if (previous_phase != .disconnected and
            next.current_phase == .disconnected)
            .logoff
        else
            next.current_phase;
        return .{
            .actions = actions,
            .previous_phase = previous_phase,
            .phase = outcome_phase,
            .next_deadline = next.current_deadline,
            .failure = next.failure_reason,
        };
    }

    fn resetAuthentication(self: *Session) void {
        self.current_identifier = null;
        self.last_inbound_type = null;
        self.last_response_identifier = null;
        self.challenge = null;
        self.pending_credentials = null;
        self.peer_mac = null;
    }

    fn enterConnecting(self: *Session, now: std.Io.Timestamp) Error!void {
        self.resetAuthentication();
        self.current_phase = .connecting;
        self.current_deadline = try addDuration(now, self.config.start_timeout);
    }

    fn makeStartFrame(self: *Session) Error![]u8 {
        const frame = try self.allocator.alloc(u8, eapol.header_size);
        errdefer self.allocator.free(frame);
        eapol.encodeStart(self.config.destination_mac, self.config.source_mac, frame[0..eapol.header_size]);
        return frame;
    }

    fn handleFrame(
        self: *Session,
        now: std.Io.Timestamp,
        frame: eapol.Frame,
        builder: *OutcomeBuilder,
    ) Error!void {
        if (frame.packet_type == .logoff) {
            if (self.current_phase == .disconnected or self.current_phase == .logoff) {
                return error.InvalidState;
            }
            self.failure_reason = .server_logoff;
            try self.enterLogoffState();
            return;
        }
        if (frame.packet_type != .eap) return error.InvalidState;
        const eap = frame.eap orelse return error.InvalidFrame;
        self.peer_mac = frame.source;

        switch (eap.code) {
            .request => {
                if (self.current_phase != .connecting and
                    self.current_phase != .acquired and
                    self.current_phase != .authenticating)
                {
                    return error.InvalidState;
                }
                try self.acceptRequestIdentifier(eap);

                switch (eap.type orelse return error.InvalidFrame) {
                    .identity => {
                        self.current_phase = .acquired;
                        self.challenge = null;
                        self.pending_credentials = .identity;
                        self.current_deadline = try addDuration(now, self.config.auth_timeout);
                        try builder.addAction(.{ .request_credentials = .identity });
                    },
                    .md5_challenge => {
                        const decoded = eapol.decodeMd5Challenge(eap) catch return error.InvalidFrame;
                        self.challenge = decoded.challenge;
                        self.current_phase = .authenticating;
                        self.pending_credentials = .md5_challenge;
                        self.current_deadline = try addDuration(now, self.config.auth_timeout);
                        try builder.addAction(.{ .request_credentials = .md5_challenge });
                    },
                    .notification => {
                        try builder.addFrame(try self.makeEapResponse(eap.identifier, .notification, &.{}));
                        self.last_response_identifier = eap.identifier;
                    },
                    .credential => {
                        self.current_phase = .authenticating;
                        self.pending_credentials = .credential_request;
                        self.current_deadline = try addDuration(now, self.config.auth_timeout);
                        try builder.addAction(.{ .request_credentials = .credential_request });
                    },
                    .peap => return error.UnsupportedEapMethod,
                    else => {
                        try builder.addFrame(try self.makeNakFrame(eap.identifier));
                        self.last_response_identifier = eap.identifier;
                    },
                }
            },
            .success => {
                if (self.current_phase != .authenticating) return error.InvalidState;
                if (self.network_completion_pending) return error.DuplicateFrame;
                try self.validateTerminalIdentifier(eap.identifier);
                self.auth_failures = 0;
                if (self.config.dhcp_second_auth and self.dhcp_step == .first) {
                    self.network_completion_pending = true;
                    self.awaiting_dhcp_result = true;
                    self.dhcp_poll_attempts = 1;
                    self.current_deadline = try addDuration(now, .fromSeconds(2));
                    try builder.addAction(.poll_dhcp);
                } else {
                    self.current_phase = .authenticated;
                    self.current_deadline = null;
                    self.challenge = null;
                    self.pending_credentials = null;
                    self.network_completion_pending = false;
                    self.awaiting_dhcp_result = false;
                }
            },
            .failure => {
                if (self.current_phase != .authenticating) return error.InvalidState;
                try self.validateTerminalIdentifier(eap.identifier);
                try self.enterHeld(now, .server_failure);
            },
            else => return error.InvalidFrame,
        }
    }

    fn acceptRequestIdentifier(self: *Session, eap: eapol.Eap) Error!void {
        if (self.current_identifier) |identifier| {
            if (eap.identifier == identifier) {
                if (self.last_inbound_type == eap.type) return error.DuplicateFrame;
                return error.StaleIdentifier;
            }
            if (eap.identifier != identifier +% 1) return error.StaleIdentifier;
        }
        self.current_identifier = eap.identifier;
        self.last_inbound_type = eap.type;
        self.last_response_identifier = null;
    }

    fn validateTerminalIdentifier(self: *Session, identifier: u8) Error!void {
        if (self.last_response_identifier == null or
            self.last_response_identifier.? != identifier)
        {
            return error.StaleIdentifier;
        }
    }

    fn handleCredentials(
        self: *Session,
        now: std.Io.Timestamp,
        credentials: Credentials,
        builder: *OutcomeBuilder,
    ) Error!void {
        const pending = self.pending_credentials orelse return error.InvalidInput;
        if (credentials.username.len == 0 or credentials.username.len > std.math.maxInt(u16) - 38) {
            return error.InvalidCredentials;
        }
        const identifier = self.current_identifier orelse return error.InvalidState;

        const frame = switch (pending) {
            .identity => try self.makeEapResponse(identifier, .identity, credentials.username),
            .md5_challenge => blk: {
                const challenge = self.challenge orelse return error.InvalidState;
                var data: [33 + 255]u8 = undefined;
                if (credentials.username.len > 255) return error.InvalidCredentials;
                const encoded = eapol.encodeMd5ResponseData(
                    identifier,
                    credentials.username,
                    challenge,
                    &data,
                ) catch return error.InvalidCredentials;
                break :blk try self.makeEapResponse(identifier, .md5_challenge, encoded);
            },
            .credential_request => try self.makeCredentialResponse(
                identifier,
                credentials.username,
                credentials.password,
            ),
        };
        try builder.addFrame(frame);
        self.pending_credentials = null;
        self.last_response_identifier = identifier;
        self.current_deadline = try addDuration(now, self.config.auth_timeout);
        if (self.config.dhcp_second_auth and self.dhcp_step == .none) {
            self.dhcp_step = .first;
        }
    }

    fn makeEapResponse(
        self: *Session,
        identifier: u8,
        eap_type: eapol.EapType,
        data: []const u8,
    ) Error![]u8 {
        const frame_len = eapol.header_size + 5 + data.len;
        const frame = try self.allocator.alloc(u8, frame_len);
        errdefer self.allocator.free(frame);
        _ = eapol.encodeEap(
            self.peer_mac orelse self.config.destination_mac,
            self.config.source_mac,
            .response,
            identifier,
            eap_type,
            data,
            frame,
        ) catch return error.InvalidCredentials;
        return frame;
    }

    fn makeNakFrame(self: *Session, identifier: u8) Error![]u8 {
        return self.makeEapResponse(
            identifier,
            .legacy_nak,
            &.{@backingInt(eapol.EapType.md5_challenge)},
        );
    }

    fn makeCredentialResponse(
        self: *Session,
        identifier: u8,
        username: []const u8,
        password: []const u8,
    ) Error![]u8 {
        if (username.len > 255 or password.len > std.math.maxInt(u16) - 6 - username.len) {
            return error.InvalidCredentials;
        }
        const data_len = 1 + username.len + password.len;
        const data = try self.allocator.alloc(u8, data_len);
        defer self.allocator.free(data);
        data[0] = @intCast(username.len);
        @memcpy(data[1 .. 1 + username.len], username);
        @memcpy(data[1 + username.len ..], password);
        return self.makeEapResponse(identifier, .credential, data);
    }

    fn handleTimer(self: *Session, now: std.Io.Timestamp, builder: *OutcomeBuilder) Error!void {
        const deadline = self.current_deadline orelse return error.InvalidState;
        if (now.compare(.lt, deadline)) return error.TimerNotDue;
        if (self.network_completion_pending) {
            return self.handleDhcpTimer(now, builder);
        }

        switch (self.current_phase) {
            .connecting => {
                if (self.connect_attempts < self.config.max_start_attempts) {
                    self.connect_attempts += 1;
                    try self.enterConnecting(now);
                    try builder.addFrame(try self.makeStartFrame());
                } else {
                    try self.enterHeld(now, .start_timeout);
                }
            },
            .acquired, .authenticating => try self.enterHeld(now, .auth_timeout),
            .held => {
                if (self.auth_failures >= self.config.max_auth_failures) {
                    try self.enterLogoff(builder);
                } else {
                    self.failure_reason = null;
                    self.connect_attempts = 1;
                    try self.enterConnecting(now);
                    try builder.addFrame(try self.makeStartFrame());
                }
            },
            else => return error.InvalidState,
        }
    }

    fn handleCancel(self: *Session, builder: *OutcomeBuilder) Error!void {
        if (self.current_phase == .disconnected or self.current_phase == .logoff) {
            return error.InvalidState;
        }
        self.failure_reason = .canceled;
        try self.enterLogoff(builder);
    }

    fn handleExternalResult(
        self: *Session,
        now: std.Io.Timestamp,
        result: ExternalResult,
        builder: *OutcomeBuilder,
    ) Error!void {
        if (!self.network_completion_pending or !self.awaiting_dhcp_result) {
            return error.InvalidState;
        }
        self.awaiting_dhcp_result = false;

        switch (result) {
            .dhcp_lease => |lease| {
                if (lease.ip == null or lease.gateway == null) return;
                self.network_completion_pending = false;
                self.dhcp_step = .second;
                self.dhcp_poll_attempts = 0;
                self.connect_attempts = 1;
                try self.enterConnecting(now);
                try builder.addFrame(try self.makeStartFrame());
            },
        }
    }

    fn handleDhcpTimer(self: *Session, now: std.Io.Timestamp, builder: *OutcomeBuilder) Error!void {
        if (self.dhcp_poll_attempts >= 21) {
            self.failure_reason = .dhcp_timeout;
            try self.enterLogoff(builder);
            return;
        }
        self.dhcp_poll_attempts += 1;
        self.awaiting_dhcp_result = true;
        self.current_deadline = try addDuration(now, .fromSeconds(2));
        try builder.addAction(.poll_dhcp);
    }

    fn enterHeld(self: *Session, now: std.Io.Timestamp, reason: FailureReason) Error!void {
        self.current_phase = .held;
        self.current_deadline = try addDuration(now, self.config.held_timeout);
        self.failure_reason = reason;
        self.challenge = null;
        self.pending_credentials = null;
        self.auth_failures +|= 1;
        self.network_completion_pending = false;
        self.awaiting_dhcp_result = false;
    }

    fn enterLogoff(self: *Session, builder: *OutcomeBuilder) Error!void {
        const destination = self.peer_mac orelse self.config.destination_mac;
        const frame = try self.allocator.alloc(u8, eapol.header_size);
        errdefer self.allocator.free(frame);
        eapol.encodeLogoff(destination, self.config.source_mac, frame[0..eapol.header_size]);
        try builder.addFrame(frame);
        try self.enterLogoffState();
    }

    fn enterLogoffState(self: *Session) Error!void {
        self.current_phase = .disconnected;
        self.current_deadline = null;
        self.challenge = null;
        self.pending_credentials = null;
        self.current_identifier = null;
        self.last_inbound_type = null;
        self.last_response_identifier = null;
        self.network_completion_pending = false;
        self.awaiting_dhcp_result = false;
    }
};

const OutcomeBuilder = struct {
    allocator: std.mem.Allocator,
    actions: [8]Action = undefined,
    action_count: usize = 0,
    frames: [8][]u8 = undefined,
    frame_count: usize = 0,
    transferred: bool = false,

    fn init(allocator: std.mem.Allocator) OutcomeBuilder {
        return .{ .allocator = allocator };
    }

    fn addAction(self: *OutcomeBuilder, action: Action) Error!void {
        if (self.action_count == self.actions.len) return error.InvalidState;
        self.actions[self.action_count] = action;
        self.action_count += 1;
    }

    fn addFrame(self: *OutcomeBuilder, frame: []u8) Error!void {
        if (self.frame_count == self.frames.len) {
            self.allocator.free(frame);
            return error.InvalidState;
        }
        self.frames[self.frame_count] = frame;
        self.frame_count += 1;
        try self.addAction(.{ .send_frame = frame });
    }

    fn finish(self: *OutcomeBuilder) Error![]Action {
        const actions = try self.allocator.dupe(Action, self.actions[0..self.action_count]);
        self.transferred = true;
        return actions;
    }

    fn deinit(self: *OutcomeBuilder) void {
        if (!self.transferred) {
            for (self.frames[0..self.frame_count]) |frame| self.allocator.free(frame);
        }
        self.* = undefined;
    }
};

fn addDuration(base: std.Io.Timestamp, duration: std.Io.Duration) Error!std.Io.Timestamp {
    const result = @addWithOverflow(base.nanoseconds, duration.nanoseconds);
    if (result[1] != 0) return error.TimestampOverflow;
    return .fromNanoseconds(result[0]);
}

fn timestamp(nanoseconds: i96) std.Io.Timestamp {
    return .fromNanoseconds(nanoseconds);
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
    var acquired = try session.step(timestamp(std.time.ns_per_s), .{ .frame = &identity });
    acquired.deinit(std.testing.allocator);

    var identified = try session.step(timestamp(2 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "secret" },
    });
    identified.deinit(std.testing.allocator);

    const challenge = md5ChallengeRequest(0x17);
    var challenged = try session.step(timestamp(3 * std.time.ns_per_s), .{ .frame = &challenge });
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
    var acquired = try session.step(timestamp(std.time.ns_per_s), .{ .frame = &identity });
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
    var challenged = try session.step(timestamp(3 * std.time.ns_per_s), .{ .frame = &challenge });
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
    var authenticated = try session.step(timestamp(5 * std.time.ns_per_s), .{ .frame = &success });
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
    var held = try session.step(timestamp(5 * std.time.ns_per_s), .{ .frame = &failure });
    defer held.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, held.previous_phase);
    try std.testing.expectEqual(Phase.held, held.phase);
    try std.testing.expectEqual(FailureReason.server_failure, held.failure.?);
    try std.testing.expectEqual(timestamp(35 * std.time.ns_per_s), held.next_deadline.?);

    try std.testing.expectError(
        error.TimerNotDue,
        session.step(timestamp(34 * std.time.ns_per_s), .timer),
    );
    try std.testing.expectEqual(Phase.held, session.phase());
    try std.testing.expectEqual(FailureReason.server_failure, session.failure().?);

    var logged_off = try session.step(timestamp(35 * std.time.ns_per_s), .timer);
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
        .{ .frame = &first_failure },
    );
    try std.testing.expectEqual(FailureReason.server_failure, first_held.failure.?);
    first_held.deinit(std.testing.allocator);

    var retry = try session.step(timestamp(10 * std.time.ns_per_s), .timer);
    retry.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, session.phase());

    const second_identity = identityRequest(0x18);
    var acquired = try session.step(
        timestamp(11 * std.time.ns_per_s),
        .{ .frame = &second_identity },
    );
    acquired.deinit(std.testing.allocator);

    var identified = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    identified.deinit(std.testing.allocator);

    const second_challenge = md5ChallengeRequest(0x19);
    var challenged = try session.step(
        timestamp(13 * std.time.ns_per_s),
        .{ .frame = &second_challenge },
    );
    challenged.deinit(std.testing.allocator);

    var answered = try session.step(timestamp(14 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    answered.deinit(std.testing.allocator);

    const second_failure = terminalRequest(.failure, 0x19);
    var second_held = try session.step(
        timestamp(15 * std.time.ns_per_s),
        .{ .frame = &second_failure },
    );
    try std.testing.expectEqual(Phase.held, session.phase());
    second_held.deinit(std.testing.allocator);

    var logged_off = try session.step(timestamp(20 * std.time.ns_per_s), .timer);
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

    var auth_held = try auth_session.step(timestamp(35 * std.time.ns_per_s), .timer);
    defer auth_held.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.held, auth_held.phase);
    try std.testing.expectEqual(FailureReason.auth_timeout, auth_held.failure.?);

    var retried = try auth_session.step(timestamp(40 * std.time.ns_per_s), .timer);
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
    var start_retry = try start_session.step(timestamp(10 * std.time.ns_per_s), .timer);
    start_retry.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, start_session.phase());

    var start_held = try start_session.step(timestamp(20 * std.time.ns_per_s), .timer);
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
        .{ .frame = &remote_logoff_frame },
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
        session.step(timestamp(std.time.ns_per_s), .{ .frame = &peap_frame }),
    );
    try std.testing.expectEqual(Phase.connecting, session.phase());

    const identity = identityRequest(0x16);
    var acquired = try session.step(timestamp(std.time.ns_per_s), .{ .frame = &identity });
    acquired.deinit(std.testing.allocator);
    const deadline = session.nextDeadline();

    try std.testing.expectError(
        error.DuplicateFrame,
        session.step(timestamp(2 * std.time.ns_per_s), .{ .frame = &identity }),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());
    try std.testing.expectEqual(deadline, session.nextDeadline());

    const old_identity = identityRequest(0x15);
    try std.testing.expectError(
        error.StaleIdentifier,
        session.step(timestamp(2 * std.time.ns_per_s), .{ .frame = &old_identity }),
    );
    try std.testing.expectEqual(Phase.acquired, session.phase());

    const success = terminalRequest(.success, 0x16);
    try std.testing.expectError(
        error.InvalidState,
        session.step(timestamp(2 * std.time.ns_per_s), .{ .frame = &success }),
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
        session.step(timestamp(0), .timer),
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
        .{ .frame = &first_success },
    );
    defer waiting_for_dhcp.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, waiting_for_dhcp.phase);
    try std.testing.expectEqual(Action.poll_dhcp, waiting_for_dhcp.actions[0]);
    try std.testing.expectEqual(timestamp(7 * std.time.ns_per_s), waiting_for_dhcp.next_deadline.?);

    try std.testing.expectError(
        error.DuplicateFrame,
        session.step(timestamp(6 * std.time.ns_per_s), .{ .frame = &first_success }),
    );
    try std.testing.expectEqual(Phase.authenticating, session.phase());
    try std.testing.expectEqual(timestamp(7 * std.time.ns_per_s), session.nextDeadline().?);

    var incomplete_lease = try session.step(timestamp(6 * std.time.ns_per_s), .{
        .external_result = .{ .dhcp_lease = .{ .ip = .{ 192, 0, 2, 10 } } },
    });
    defer incomplete_lease.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.authenticating, incomplete_lease.phase);
    try std.testing.expectEqual(@as(usize, 0), incomplete_lease.actions.len);

    var polled_again = try session.step(timestamp(7 * std.time.ns_per_s), .timer);
    defer polled_again.deinit(std.testing.allocator);
    try std.testing.expectEqual(Action.poll_dhcp, polled_again.actions[0]);

    var second_cycle = try session.step(timestamp(8 * std.time.ns_per_s), .{
        .external_result = .{ .dhcp_lease = .{
            .ip = .{ 192, 0, 2, 10 },
            .gateway = .{ 192, 0, 2, 1 },
        } },
    });
    defer second_cycle.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, second_cycle.phase);
    try std.testing.expectEqual(DhcpStep.second, session.dhcpStep());
    try std.testing.expectEqual(@as(usize, 1), second_cycle.actions.len);

    const second_identity = identityRequest(0x18);
    var acquired = try session.step(timestamp(9 * std.time.ns_per_s), .{ .frame = &second_identity });
    acquired.deinit(std.testing.allocator);
    var identified = try session.step(timestamp(10 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    identified.deinit(std.testing.allocator);
    const second_challenge = md5ChallengeRequest(0x19);
    var challenged = try session.step(timestamp(11 * std.time.ns_per_s), .{ .frame = &second_challenge });
    challenged.deinit(std.testing.allocator);
    var answered = try session.step(timestamp(12 * std.time.ns_per_s), .{
        .credentials = .{ .username = "alice", .password = "" },
    });
    answered.deinit(std.testing.allocator);

    const second_success = terminalRequest(.success, 0x19);
    var authenticated = try session.step(timestamp(13 * std.time.ns_per_s), .{ .frame = &second_success });
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
    var first_poll = try session.step(timestamp(5 * std.time.ns_per_s), .{ .frame = &success });
    first_poll.deinit(std.testing.allocator);

    var now: i96 = 7 * std.time.ns_per_s;
    for (2..22) |attempt| {
        var poll = try session.step(timestamp(now), .timer);
        poll.deinit(std.testing.allocator);
        try std.testing.expectEqual(Phase.authenticating, session.phase());
        try std.testing.expectEqual(@as(u8, @intCast(attempt)), session.dhcpPollAttempts());
        now += 2 * std.time.ns_per_s;
    }

    var timed_out = try session.step(timestamp(now), .timer);
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
    var acquired = try session.step(timestamp(std.time.ns_per_s), .{ .frame = &identity });
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
    var challenged = try session.step(timestamp(3 * std.time.ns_per_s), .{ .frame = &challenge });
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
    var notified = try session.step(timestamp(std.time.ns_per_s), .{ .frame = &notification_frame });
    defer notified.deinit(std.testing.allocator);
    try std.testing.expectEqual(Phase.connecting, notified.phase);
    const notification_response = try eapol.decode(notified.actions[0].send_frame);
    try std.testing.expectEqual(eapol.EapCode.response, notification_response.eap.?.code);
    try std.testing.expectEqual(@as(?eapol.EapType, .notification), notification_response.eap.?.type);
    try std.testing.expectEqual(@as(usize, 0), notification_response.eap.?.data.len);

    var credential_frame: [eapol.header_size + 5]u8 = undefined;
    @memcpy(credential_frame[0..eapol.header_size], &eapolHeader(.eap, 5));
    credential_frame[eapol.header_size..].* = .{ 1, 0x17, 0, 5, 7 };
    var credential_request = try session.step(timestamp(2 * std.time.ns_per_s), .{ .frame = &credential_frame });
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
