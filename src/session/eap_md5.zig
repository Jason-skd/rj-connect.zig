//! Deterministic EAP-MD5 protocol machine and external event handling.

const std = @import("std");
const eapol = @import("../protocol/eapol.zig");
const session_outcome = @import("outcome.zig");
const time = @import("time.zig");
const types = @import("types.zig");

const Action = session_outcome.Action;
const ActivePhase = types.ActivePhase;
const Config = types.Config;
const CredentialPurpose = types.CredentialPurpose;
const Credentials = types.Credentials;
const DhcpStep = types.DhcpStep;
const EapMd5Phase = types.EapMd5Phase;
const Error = types.Error;
const ExternalResult = types.ExternalResult;
const FailureReason = types.FailureReason;
const Generation = types.Generation;
const Input = types.Input;
const Outcome = session_outcome.Outcome;
const OutcomeBuilder = session_outcome.OutcomeBuilder;

const PendingCredentials = union(enum) {
    identity,
    md5_challenge: [16]u8,
    credential_request,
};

const Exchange = struct {
    peer_mac: [6]u8,
    identifier: u8,
    last_inbound_type: eapol.EapType,
    last_response_identifier: ?u8,
    pending: ?PendingCredentials,
};

const Connecting = struct {
    deadline: std.Io.Timestamp,
    attempts: u16,
    exchange: ?Exchange,
};

const NetworkCompletion = struct {
    deadline: std.Io.Timestamp,
    poll_attempts: u8,
    peer_mac: [6]u8,
};

const Held = struct {
    deadline: std.Io.Timestamp,
    peer_mac: ?[6]u8,
};

const State = union(enum) {
    disconnected,
    connecting: Connecting,
    acquired: struct {
        deadline: std.Io.Timestamp,
        exchange: Exchange,
    },
    authenticating: struct {
        deadline: std.Io.Timestamp,
        exchange: Exchange,
    },
    network_completion: NetworkCompletion,
    authenticated: struct {
        peer_mac: [6]u8,
    },
    held: Held,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    config: Config,
    state: State,
    generation: Generation,
    last_now: ?std.Io.Timestamp,
    auth_failures: u16,
    failure_reason: ?FailureReason,
    dhcp_step: DhcpStep,

    /// Creates a disconnected engine. No allocation occurs until `step` produces an outcome.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Engine {
        return initWithState(allocator, config, Generation.initial, null);
    }

    pub fn initWithState(
        allocator: std.mem.Allocator,
        config: Config,
        generation: Generation,
        last_now: ?std.Io.Timestamp,
    ) Error!Engine {
        try config.validate();

        return .{
            .allocator = allocator,
            .config = config,
            .state = .disconnected,
            .generation = generation,
            .last_now = last_now,
            .auth_failures = 0,
            .failure_reason = null,
            .dhcp_step = .none,
        };
    }

    pub fn deinit(_: *Engine) void {}

    pub fn phase(self: *const Engine) ActivePhase {
        return switch (self.state) {
            .disconnected => .idle,
            .connecting => .{ .eap_md5 = .connecting },
            .acquired => .{ .eap_md5 = .acquired },
            .authenticating, .network_completion => .{ .eap_md5 = .authenticating },
            .authenticated => .{ .eap_md5 = .authenticated },
            .held => .{ .eap_md5 = .held },
        };
    }

    pub fn nextDeadline(self: *const Engine) ?std.Io.Timestamp {
        return switch (self.state) {
            .connecting => |state| state.deadline,
            .acquired => |state| state.deadline,
            .authenticating => |state| state.deadline,
            .network_completion => |state| state.deadline,
            .held => |state| state.deadline,
            .disconnected, .authenticated => null,
        };
    }

    pub fn failure(self: *const Engine) ?FailureReason {
        return self.failure_reason;
    }

    pub fn dhcpStep(self: *const Engine) DhcpStep {
        return self.dhcp_step;
    }

    pub fn dhcpPollAttempts(self: *const Engine) u8 {
        return switch (self.state) {
            .network_completion => |state| state.poll_attempts,
            else => 0,
        };
    }

    /// Returns the token required by asynchronous inputs to the current attempt.
    pub fn currentGeneration(self: *const Engine) Generation {
        return self.generation;
    }

    pub fn lastNow(self: *const Engine) ?std.Io.Timestamp {
        return self.last_now;
    }

    pub fn authenticatedPeer(self: *const Engine) ?[6]u8 {
        return switch (self.state) {
            .authenticated => |state| state.peer_mac,
            else => null,
        };
    }

    pub const PeapHandoff = struct {
        peer_mac: [6]u8,
        identifier: u8,
    };

    /// Validates a PEAP request against the acquired Identity exchange without
    /// mutating the engine. The caller can construct the PEAP machine first and
    /// commit the handoff only after that construction succeeds.
    pub fn peapHandoff(
        self: *const Engine,
        source: [6]u8,
        eap: eapol.Eap,
    ) Error!PeapHandoff {
        if (eap.code != .request or eap.type != .peap) return error.InvalidFrame;
        var exchange: ?Exchange = switch (self.state) {
            .acquired => |state| state.exchange,
            else => return error.InvalidState,
        };
        if (exchange.?.pending != null or exchange.?.last_response_identifier == null) {
            return error.InvalidState;
        }
        try acceptRequestIdentifier(&exchange, source, eap, .peap);
        return .{
            .peer_mac = exchange.?.peer_mac,
            .identifier = exchange.?.identifier,
        };
    }

    /// Accepts one external event and commits state only after every returned action is allocated.
    pub fn step(self: *Engine, now: std.Io.Timestamp, input: Input) Error!Outcome {
        if (self.last_now) |last_now| {
            if (now.compare(.lt, last_now)) return error.TimeWentBackwards;
        }

        var next = self.*;
        next.last_now = now;
        const previous_phase = next.phase();
        var builder = OutcomeBuilder.init(next.allocator);
        errdefer builder.deinit();

        switch (input) {
            .start => {
                switch (next.state) {
                    .disconnected => {},
                    else => return error.InvalidState,
                }

                next.auth_failures = 0;
                next.failure_reason = null;
                next.dhcp_step = .none;
                try next.enterConnecting(now, 1);
                try builder.addFrame(try next.makeStartFrame());
            },
            .direct_session => return error.InvalidState,
            .frame => |event| {
                if (!event.generation.eql(next.generation)) return error.StaleGeneration;
                const frame = eapol.decode(event.bytes) catch return error.InvalidFrame;
                try next.handleFrame(now, frame, &builder);
            },
            .credentials => |credentials| try next.handleCredentials(now, credentials, &builder),
            .timer => |generation| {
                if (!generation.eql(next.generation)) return error.StaleGeneration;
                try next.handleTimer(now, &builder);
            },
            .cancel => try next.handleCancel(&builder),
            .external_result => |event| {
                if (!event.generation.eql(next.generation)) return error.StaleGeneration;
                try next.handleExternalResult(now, event.result, &builder);
            },
        }

        const actions = try builder.finish();
        self.* = next;
        const outcome_phase = next.phase();
        return .{
            .actions = actions,
            .previous_phase = previous_phase,
            .phase = outcome_phase,
            .next_deadline = next.nextDeadline(),
            .failure = next.failure_reason,
            .generation = next.generation,
        };
    }

    fn enterConnecting(self: *Engine, now: std.Io.Timestamp, attempts: u16) Error!void {
        self.generation = try self.generation.next();
        self.state = .{ .connecting = .{
            .deadline = try addDuration(now, self.config.start_timeout),
            .attempts = attempts,
            .exchange = null,
        } };
    }

    fn makeStartFrame(self: *Engine) Error![]u8 {
        const frame = try self.allocator.alloc(u8, eapol.header_size);
        errdefer self.allocator.free(frame);
        eapol.encodeStart(self.config.destination_mac, self.config.source_mac, frame[0..eapol.header_size]);
        return frame;
    }

    fn handleFrame(
        self: *Engine,
        now: std.Io.Timestamp,
        frame: eapol.Frame,
        builder: *OutcomeBuilder,
    ) Error!void {
        if (frame.packet_type == .logoff) {
            switch (self.state) {
                .disconnected => return error.InvalidState,
                else => {},
            }
            self.failure_reason = .server_logoff;
            self.state = .disconnected;
            return;
        }
        if (frame.packet_type != .eap) return error.InvalidState;
        const eap = frame.eap orelse return error.InvalidFrame;

        switch (eap.code) {
            .request => try self.handleRequest(now, frame.source, eap, builder),
            .success => try self.handleSuccess(now, eap, builder),
            .failure => try self.handleFailure(now, eap),
            else => return error.InvalidFrame,
        }
    }

    fn handleRequest(
        self: *Engine,
        now: std.Io.Timestamp,
        source: [6]u8,
        eap: eapol.Eap,
        builder: *OutcomeBuilder,
    ) Error!void {
        const eap_type = eap.type orelse return error.InvalidFrame;
        var exchange: ?Exchange = switch (self.state) {
            .connecting => |state| state.exchange,
            .acquired => |state| state.exchange,
            .authenticating => |state| state.exchange,
            else => return error.InvalidState,
        };
        try acceptRequestIdentifier(&exchange, source, eap, eap_type);

        switch (eap_type) {
            .identity => {
                exchange.?.pending = .identity;
                self.state = .{ .acquired = .{
                    .deadline = try addDuration(now, self.config.auth_timeout),
                    .exchange = exchange.?,
                } };
                try builder.addAction(.{ .request_credentials = .identity });
            },
            .md5_challenge => {
                const decoded = eapol.decodeMd5Challenge(eap) catch return error.InvalidFrame;
                exchange.?.pending = .{ .md5_challenge = decoded.challenge };
                self.state = .{ .authenticating = .{
                    .deadline = try addDuration(now, self.config.auth_timeout),
                    .exchange = exchange.?,
                } };
                try builder.addAction(.{ .request_credentials = .md5_challenge });
            },
            .notification => {
                try builder.addFrame(try self.makeEapResponse(
                    exchange.?.peer_mac,
                    exchange.?.identifier,
                    .notification,
                    &.{},
                ));
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.replaceExchange(exchange.?);
            },
            .credential => {
                exchange.?.pending = .credential_request;
                self.state = .{ .authenticating = .{
                    .deadline = try addDuration(now, self.config.auth_timeout),
                    .exchange = exchange.?,
                } };
                try builder.addAction(.{ .request_credentials = .credential_request });
            },
            .peap => return error.UnsupportedEapMethod,
            else => {
                try builder.addFrame(try self.makeNakFrame(
                    exchange.?.peer_mac,
                    exchange.?.identifier,
                ));
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.replaceExchange(exchange.?);
            },
        }
    }

    fn handleSuccess(
        self: *Engine,
        now: std.Io.Timestamp,
        eap: eapol.Eap,
        builder: *OutcomeBuilder,
    ) Error!void {
        switch (self.state) {
            .network_completion => return error.DuplicateFrame,
            .authenticating => |state| {
                try validateTerminalIdentifier(state.exchange.last_response_identifier, eap.identifier);
                self.auth_failures = 0;
                if (self.config.dhcp_second_auth and self.dhcp_step == .first) {
                    self.state = .{ .network_completion = .{
                        .deadline = try addDuration(now, .fromSeconds(2)),
                        .poll_attempts = 1,
                        .peer_mac = state.exchange.peer_mac,
                    } };
                    try builder.addAction(.poll_dhcp);
                } else {
                    self.state = .{ .authenticated = .{
                        .peer_mac = state.exchange.peer_mac,
                    } };
                }
            },
            else => return error.InvalidState,
        }
    }

    fn handleFailure(self: *Engine, now: std.Io.Timestamp, eap: eapol.Eap) Error!void {
        switch (self.state) {
            .authenticating => |state| {
                try validateTerminalIdentifier(state.exchange.last_response_identifier, eap.identifier);
                try self.enterHeld(now, state.exchange.peer_mac, .server_failure);
            },
            else => return error.InvalidState,
        }
    }

    fn acceptRequestIdentifier(
        exchange: *?Exchange,
        source: [6]u8,
        eap: eapol.Eap,
        eap_type: eapol.EapType,
    ) Error!void {
        if (exchange.*) |*current| {
            if (eap.identifier == current.identifier) {
                if (current.last_inbound_type == eap_type) return error.DuplicateFrame;
                return error.StaleIdentifier;
            }
            if (eap.identifier != current.identifier +% 1) return error.StaleIdentifier;
            current.peer_mac = source;
            current.identifier = eap.identifier;
            current.last_inbound_type = eap_type;
            current.last_response_identifier = null;
            return;
        }

        exchange.* = .{
            .peer_mac = source,
            .identifier = eap.identifier,
            .last_inbound_type = eap_type,
            .last_response_identifier = null,
            .pending = null,
        };
    }

    fn validateTerminalIdentifier(last_response: ?u8, identifier: u8) Error!void {
        if (last_response == null or last_response.? != identifier) {
            return error.StaleIdentifier;
        }
    }

    fn replaceExchange(self: *Engine, exchange: Exchange) void {
        switch (self.state) {
            .connecting => |*state| state.exchange = exchange,
            .acquired => |*state| state.exchange = exchange,
            .authenticating => |*state| state.exchange = exchange,
            else => unreachable,
        }
    }

    fn handleCredentials(
        self: *Engine,
        now: std.Io.Timestamp,
        credentials: Credentials,
        builder: *OutcomeBuilder,
    ) Error!void {
        var exchange = switch (self.state) {
            .acquired => |state| state.exchange,
            .authenticating => |state| state.exchange,
            else => return error.InvalidInput,
        };
        const pending = exchange.pending orelse return error.InvalidInput;
        if (credentials.username.len == 0 or credentials.username.len > std.math.maxInt(u16) - 38) {
            return error.InvalidCredentials;
        }

        const frame = switch (pending) {
            .identity => try self.makeEapResponse(
                exchange.peer_mac,
                exchange.identifier,
                .identity,
                credentials.username,
            ),
            .md5_challenge => |challenge| blk: {
                var data: [33 + 255]u8 = undefined;
                if (credentials.username.len > 255) return error.InvalidCredentials;
                const encoded = eapol.encodeMd5ResponseData(
                    exchange.identifier,
                    credentials.username,
                    challenge,
                    &data,
                ) catch return error.InvalidCredentials;
                break :blk try self.makeEapResponse(
                    exchange.peer_mac,
                    exchange.identifier,
                    .md5_challenge,
                    encoded,
                );
            },
            .credential_request => try self.makeCredentialResponse(
                exchange.peer_mac,
                exchange.identifier,
                credentials.username,
                credentials.password,
            ),
        };
        try builder.addFrame(frame);
        exchange.pending = null;
        exchange.last_response_identifier = exchange.identifier;

        switch (self.state) {
            .acquired => self.state = .{ .acquired = .{
                .deadline = try addDuration(now, self.config.auth_timeout),
                .exchange = exchange,
            } },
            .authenticating => self.state = .{ .authenticating = .{
                .deadline = try addDuration(now, self.config.auth_timeout),
                .exchange = exchange,
            } },
            else => unreachable,
        }
        if (self.config.dhcp_second_auth and self.dhcp_step == .none) {
            self.dhcp_step = .first;
        }
    }

    fn makeEapResponse(
        self: *Engine,
        peer_mac: [6]u8,
        identifier: u8,
        eap_type: eapol.EapType,
        data: []const u8,
    ) Error![]u8 {
        const frame_len = eapol.header_size + 5 + data.len;
        const frame = try self.allocator.alloc(u8, frame_len);
        errdefer self.allocator.free(frame);
        _ = eapol.encodeEap(
            peer_mac,
            self.config.source_mac,
            .response,
            identifier,
            eap_type,
            data,
            frame,
        ) catch return error.InvalidCredentials;
        return frame;
    }

    fn makeNakFrame(self: *Engine, peer_mac: [6]u8, identifier: u8) Error![]u8 {
        return self.makeEapResponse(
            peer_mac,
            identifier,
            .legacy_nak,
            &.{@backingInt(eapol.EapType.md5_challenge)},
        );
    }

    fn makeCredentialResponse(
        self: *Engine,
        peer_mac: [6]u8,
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
        return self.makeEapResponse(peer_mac, identifier, .credential, data);
    }

    fn handleTimer(self: *Engine, now: std.Io.Timestamp, builder: *OutcomeBuilder) Error!void {
        const deadline = self.nextDeadline() orelse return error.InvalidState;
        if (now.compare(.lt, deadline)) return error.TimerNotDue;

        switch (self.state) {
            .connecting => |state| {
                if (state.attempts < self.config.max_start_attempts) {
                    try self.enterConnecting(now, state.attempts + 1);
                    try builder.addFrame(try self.makeStartFrame());
                } else {
                    try self.enterHeld(
                        now,
                        if (state.exchange) |exchange| exchange.peer_mac else null,
                        .start_timeout,
                    );
                }
            },
            .acquired => |state| try self.enterHeld(now, state.exchange.peer_mac, .auth_timeout),
            .authenticating => |state| try self.enterHeld(now, state.exchange.peer_mac, .auth_timeout),
            .network_completion => try self.handleDhcpTimer(now, builder),
            .held => |state| {
                if (self.auth_failures >= self.config.max_auth_failures) {
                    try self.enterLogoff(state.peer_mac, builder);
                } else {
                    self.failure_reason = null;
                    try self.enterConnecting(now, 1);
                    try builder.addFrame(try self.makeStartFrame());
                }
            },
            else => return error.InvalidState,
        }
    }

    fn handleCancel(self: *Engine, builder: *OutcomeBuilder) Error!void {
        switch (self.state) {
            .disconnected => return error.InvalidState,
            else => {},
        }
        self.failure_reason = .canceled;
        try self.enterLogoff(self.peerMac(), builder);
    }

    fn handleExternalResult(
        self: *Engine,
        now: std.Io.Timestamp,
        result: ExternalResult,
        builder: *OutcomeBuilder,
    ) Error!void {
        switch (self.state) {
            .network_completion => {},
            else => return error.InvalidState,
        }

        switch (result) {
            .dhcp_lease => |lease| {
                if (lease.ip == null or lease.gateway == null) return;
                self.dhcp_step = .second;
                try self.enterConnecting(now, 1);
                try builder.addFrame(try self.makeStartFrame());
            },
        }
    }

    fn handleDhcpTimer(self: *Engine, now: std.Io.Timestamp, builder: *OutcomeBuilder) Error!void {
        const state = switch (self.state) {
            .network_completion => |state| state,
            else => return error.InvalidState,
        };
        if (state.poll_attempts >= 21) {
            self.failure_reason = .dhcp_timeout;
            try self.enterLogoff(state.peer_mac, builder);
            return;
        }

        self.state = .{ .network_completion = .{
            .deadline = try addDuration(now, .fromSeconds(2)),
            .poll_attempts = state.poll_attempts + 1,
            .peer_mac = state.peer_mac,
        } };
        try builder.addAction(.poll_dhcp);
    }

    fn enterHeld(
        self: *Engine,
        now: std.Io.Timestamp,
        peer_mac: ?[6]u8,
        reason: FailureReason,
    ) Error!void {
        self.state = .{ .held = .{
            .deadline = try addDuration(now, self.config.held_timeout),
            .peer_mac = peer_mac,
        } };
        self.failure_reason = reason;
        self.auth_failures +|= 1;
    }

    fn peerMac(self: *const Engine) ?[6]u8 {
        return switch (self.state) {
            .connecting => |state| if (state.exchange) |exchange| exchange.peer_mac else null,
            .acquired => |state| state.exchange.peer_mac,
            .authenticating => |state| state.exchange.peer_mac,
            .network_completion => |state| state.peer_mac,
            .authenticated => |state| state.peer_mac,
            .held => |state| state.peer_mac,
            .disconnected => null,
        };
    }

    fn enterLogoff(
        self: *Engine,
        peer_mac: ?[6]u8,
        builder: *OutcomeBuilder,
    ) Error!void {
        const destination = peer_mac orelse self.config.destination_mac;
        const frame = try self.allocator.alloc(u8, eapol.header_size);
        errdefer self.allocator.free(frame);
        eapol.encodeLogoff(destination, self.config.source_mac, frame[0..eapol.header_size]);
        try builder.addFrame(frame);
        self.state = .disconnected;
    }
};

fn addDuration(base: std.Io.Timestamp, duration: std.Io.Duration) Error!std.Io.Timestamp {
    return time.addDuration(base, duration);
}
