//! Deterministic MentoHUST 0.3.1 wired EAP-MD5 compatibility profile.

const std = @import("std");
const eapol = @import("../protocol/eapol.zig");
const types = @import("legacy_types.zig");

pub const Action = types.Action;
pub const Config = types.Config;
pub const Error = types.Error;
pub const FailureReason = types.FailureReason;
pub const Generation = types.Generation;
pub const Input = types.Input;
pub const Outcome = types.Outcome;
pub const Phase = types.Phase;
pub const TerminalKind = types.TerminalKind;
pub const TerminalMessage = types.TerminalMessage;

const tail_prefix = @embedFile("../protocol/mh031_tail_prefix.bin");
const frame_size = 1000;

const Exchange = struct {
    peer_mac: [6]u8,
    identifier: u8,
    last_inbound_type: eapol.EapType,
    last_response_identifier: ?u8,
};

const State = union(enum) {
    disconnected,
    connecting: struct {
        deadline: std.Io.Timestamp,
        attempts: u16,
        exchange: ?Exchange,
    },
    acquired: struct {
        deadline: std.Io.Timestamp,
        exchange: Exchange,
    },
    authenticating: struct {
        deadline: std.Io.Timestamp,
        exchange: Exchange,
    },
    authenticated: struct {
        peer_mac: [6]u8,
    },
    held: struct {
        deadline: std.Io.Timestamp,
        peer_mac: ?[6]u8,
    },
};

const Reply = struct {
    actions: []Action,

    fn deinit(self: *Reply, allocator: std.mem.Allocator) void {
        for (self.actions) |action| switch (action) {
            .send_frame => |frame| allocator.free(frame),
        };
        allocator.free(self.actions);
        self.* = undefined;
    }
};

/// Legacy frames are padded to the fixed 1000-byte Ethernet frame shape
/// observed for Start, Identity, MD5-Response and Logoff.
pub const Session = struct {
    allocator: std.mem.Allocator,
    config: Config,
    state: State,
    generation: Generation,
    last_now: ?std.Io.Timestamp,
    auth_failures: u16,
    failure_reason: ?FailureReason,
    peer_mac: ?[6]u8,

    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Session {
        try config.validate();
        return .{
            .allocator = allocator,
            .config = config,
            .state = .disconnected,
            .generation = Generation.initial,
            .last_now = null,
            .auth_failures = 0,
            .failure_reason = null,
            .peer_mac = null,
        };
    }

    pub fn deinit(self: *Session) void {
        self.* = undefined;
    }

    pub fn phase(self: *const Session) Phase {
        return switch (self.state) {
            .disconnected => .idle,
            .connecting => .connecting,
            .acquired => .acquired,
            .authenticating => .authenticating,
            .authenticated => .authenticated,
            .held => .held,
        };
    }

    pub fn nextDeadline(self: *const Session) ?std.Io.Timestamp {
        return switch (self.state) {
            .connecting => |value| value.deadline,
            .acquired => |value| value.deadline,
            .authenticating => |value| value.deadline,
            .held => |value| value.deadline,
            .disconnected, .authenticated => null,
        };
    }

    pub fn failure(self: *const Session) ?FailureReason {
        return self.failure_reason;
    }

    pub fn currentGeneration(self: *const Session) Generation {
        return self.generation;
    }

    pub fn step(self: *Session, now: std.Io.Timestamp, input: Input) Error!Outcome {
        if (self.last_now) |last_now| {
            if (now.compare(.lt, last_now)) return error.TimeWentBackwards;
        }

        var next = self.*;
        next.last_now = now;
        const previous_phase = next.phase();
        var reply = switch (input) {
            .start => try next.handleStart(now),
            .cancel => try next.handleCancel(),
            .frame => |event| blk: {
                if (!event.generation.eql(next.generation)) return error.StaleGeneration;
                break :blk try next.handleFrame(now, event.bytes);
            },
            .timer => |generation| blk: {
                if (!generation.eql(next.generation)) return error.StaleGeneration;
                break :blk try next.handleTimer(now);
            },
            .facts => return error.UnsupportedProfileInput,
        };
        errdefer reply.deinit(next.allocator);

        self.* = next;
        return .{
            .actions = reply.actions,
            .previous_phase = previous_phase,
            .phase = next.phase(),
            .next_deadline = next.nextDeadline(),
            .failure = next.failure_reason,
            .generation = next.generation,
            .terminal = null,
        };
    }

    fn handleStart(self: *Session, now: std.Io.Timestamp) Error!Reply {
        switch (self.state) {
            .disconnected => {},
            else => return error.InvalidState,
        }
        self.auth_failures = 0;
        self.failure_reason = null;
        try self.enterConnecting(now, 1);
        const frame = try self.makeFrame(.control_start, 0, null, &.{});
        return .{ .actions = try self.singleFrame(frame) };
    }

    fn handleCancel(self: *Session) Error!Reply {
        switch (self.state) {
            .disconnected => return error.InvalidState,
            else => {},
        }
        self.failure_reason = .canceled;
        const frame = try self.makeFrame(.control_logoff, 0, null, &.{});
        self.state = .disconnected;
        return .{ .actions = try self.singleFrame(frame) };
    }

    fn handleFrame(self: *Session, now: std.Io.Timestamp, bytes: []const u8) Error!Reply {
        const frame = eapol.decode(bytes) catch return error.InvalidFrame;
        switch (frame.packet_type) {
            .logoff => {
                switch (self.state) {
                    .disconnected => return error.InvalidState,
                    else => {},
                }
                self.failure_reason = .server_logoff;
                self.state = .disconnected;
                return self.emptyReply();
            },
            .eap => {},
            else => return error.InvalidState,
        }

        const eap = frame.eap orelse return error.InvalidFrame;
        return switch (eap.code) {
            .request => self.handleRequest(now, frame.source, eap),
            .success => self.handleSuccess(eap),
            .failure => self.handleFailure(now, eap),
            else => error.InvalidFrame,
        };
    }

    fn handleRequest(
        self: *Session,
        now: std.Io.Timestamp,
        source: [6]u8,
        eap: eapol.Eap,
    ) Error!Reply {
        const eap_type = eap.type orelse return error.InvalidFrame;
        var exchange: ?Exchange = switch (self.state) {
            .connecting => |value| value.exchange,
            .acquired => |value| value.exchange,
            .authenticating => |value| value.exchange,
            else => return error.InvalidState,
        };
        try acceptRequestIdentifier(&exchange, source, eap, eap_type);
        self.peer_mac = source;

        switch (eap_type) {
            .identity => {
                const frame = try self.makeResponseFrame(
                    source,
                    eap.identifier,
                    .identity,
                    self.config.credentials.username,
                );
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.state = .{ .acquired = .{
                    .deadline = try addDuration(now, self.config.auth_timeout),
                    .exchange = exchange.?,
                } };
                return .{ .actions = try self.singleFrame(frame) };
            },
            .md5_challenge => {
                const decoded = eapol.decodeMd5Challenge(eap) catch return error.InvalidFrame;
                var data: [17 + 255]u8 = undefined;
                const data_len = 17 + self.config.credentials.username.len;
                _ = eapol.encodeStandardMd5ResponseData(
                    eap.identifier,
                    self.config.credentials.password,
                    decoded.challenge,
                    data[0..17],
                ) catch return error.InvalidCredentials;
                @memcpy(data[17..data_len], self.config.credentials.username);
                const frame = try self.makeResponseFrame(
                    source,
                    eap.identifier,
                    .md5_challenge,
                    data[0..data_len],
                );
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.state = .{ .authenticating = .{
                    .deadline = try addDuration(now, self.config.auth_timeout),
                    .exchange = exchange.?,
                } };
                return .{ .actions = try self.singleFrame(frame) };
            },
            .notification => {
                const frame = try self.makeResponseFrame(source, eap.identifier, .notification, &.{});
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.replaceExchange(exchange.?);
                return .{ .actions = try self.singleFrame(frame) };
            },
            .peap, .credential => return error.UnsupportedEapMethod,
            else => {
                const nak = [_]u8{@backingInt(eapol.EapType.md5_challenge)};
                const frame = try self.makeResponseFrame(source, eap.identifier, .legacy_nak, &nak);
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.replaceExchange(exchange.?);
                return .{ .actions = try self.singleFrame(frame) };
            },
        }
    }

    fn handleSuccess(self: *Session, eap: eapol.Eap) Error!Reply {
        const state = switch (self.state) {
            .authenticating => |value| value,
            else => return error.InvalidState,
        };
        try validateTerminalIdentifier(state.exchange.last_response_identifier, eap.identifier);
        self.auth_failures = 0;
        self.failure_reason = null;
        self.state = .{ .authenticated = .{ .peer_mac = state.exchange.peer_mac } };
        return self.emptyReply();
    }

    fn handleFailure(self: *Session, now: std.Io.Timestamp, eap: eapol.Eap) Error!Reply {
        const peer_mac = switch (self.state) {
            .connecting => |value| if (value.exchange) |exchange| exchange.peer_mac else null,
            .acquired => |value| value.exchange.peer_mac,
            .authenticating => |value| value.exchange.peer_mac,
            else => return error.InvalidState,
        };
        if (lastResponseIdentifier(self.state)) |identifier| {
            try validateTerminalIdentifier(identifier, eap.identifier);
        }
        try self.enterHeld(now, peer_mac, .server_failure);
        return self.emptyReply();
    }

    fn handleTimer(self: *Session, now: std.Io.Timestamp) Error!Reply {
        const deadline = self.nextDeadline() orelse return error.InvalidState;
        if (now.compare(.lt, deadline)) return error.TimerNotDue;

        switch (self.state) {
            .connecting => |value| {
                if (value.attempts < self.config.max_start_attempts) {
                    try self.enterConnecting(now, value.attempts + 1);
                    const frame = try self.makeFrame(.control_start, 0, null, &.{});
                    return .{ .actions = try self.singleFrame(frame) };
                }
                try self.enterHeld(
                    now,
                    if (value.exchange) |exchange| exchange.peer_mac else null,
                    .start_timeout,
                );
                return self.emptyReply();
            },
            .acquired => |value| {
                try self.enterHeld(now, value.exchange.peer_mac, .auth_timeout);
                return self.emptyReply();
            },
            .authenticating => |value| {
                try self.enterHeld(now, value.exchange.peer_mac, .auth_timeout);
                return self.emptyReply();
            },
            .held => {
                if (self.auth_failures >= self.config.max_auth_failures) {
                    const frame = try self.makeFrame(.control_logoff, 0, null, &.{});
                    self.state = .disconnected;
                    return .{ .actions = try self.singleFrame(frame) };
                }
                self.failure_reason = null;
                try self.enterConnecting(now, 1);
                const frame = try self.makeFrame(.control_start, 0, null, &.{});
                return .{ .actions = try self.singleFrame(frame) };
            },
            .authenticated, .disconnected => return error.InvalidState,
        }
    }

    fn enterConnecting(self: *Session, now: std.Io.Timestamp, attempts: u16) Error!void {
        self.generation = try self.generation.next();
        self.state = .{ .connecting = .{
            .deadline = try addDuration(now, self.config.start_timeout),
            .attempts = attempts,
            .exchange = null,
        } };
    }

    fn enterHeld(self: *Session, now: std.Io.Timestamp, peer_mac: ?[6]u8, reason: FailureReason) Error!void {
        self.state = .{ .held = .{
            .deadline = try addDuration(now, self.config.held_timeout),
            .peer_mac = peer_mac,
        } };
        self.failure_reason = reason;
        self.auth_failures +|= 1;
    }

    fn replaceExchange(self: *Session, exchange: Exchange) void {
        switch (self.state) {
            .connecting => |*value| value.exchange = exchange,
            .acquired => |*value| value.exchange = exchange,
            .authenticating => |*value| value.exchange = exchange,
            else => unreachable,
        }
    }

    const Kind = enum { control_start, control_logoff, eap };

    fn makeResponseFrame(
        self: *Session,
        destination: [6]u8,
        identifier: u8,
        eap_type: eapol.EapType,
        data: []const u8,
    ) Error![]u8 {
        return self.makeFrameWithDestination(.eap, destination, identifier, eap_type, data);
    }

    fn makeFrame(
        self: *Session,
        kind: Kind,
        identifier: u8,
        eap_type: ?eapol.EapType,
        data: []const u8,
    ) Error![]u8 {
        const destination = self.peer_mac orelse eapol.default_destination;
        return self.makeFrameWithDestination(kind, destination, identifier, eap_type, data);
    }

    fn makeFrameWithDestination(
        self: *Session,
        kind: Kind,
        destination: [6]u8,
        identifier: u8,
        eap_type: ?eapol.EapType,
        data: []const u8,
    ) Error![]u8 {
        const frame = try self.allocator.alloc(u8, frame_size);
        errdefer self.allocator.free(frame);
        @memset(frame, 0);

        const eap_end = switch (kind) {
            .control_start => blk: {
                eapol.encodeStart(
                    destination,
                    self.config.source_mac,
                    frame[0..eapol.header_size],
                );
                break :blk eapol.header_size;
            },
            .control_logoff => blk: {
                eapol.encodeLogoff(
                    destination,
                    self.config.source_mac,
                    frame[0..eapol.header_size],
                );
                break :blk eapol.header_size;
            },
            .eap => blk: {
                const encoded = eapol.encodeEap(
                    destination,
                    self.config.source_mac,
                    .response,
                    identifier,
                    eap_type,
                    data,
                    frame,
                ) catch return error.InvalidFrame;
                break :blk encoded.len;
            },
        };
        if (tail_prefix.len > frame.len - eap_end) return error.InvalidConfig;
        @memcpy(frame[eap_end..][0..tail_prefix.len], tail_prefix);
        return frame;
    }

    fn singleFrame(self: *Session, frame: []u8) Error![]Action {
        const actions = self.allocator.alloc(Action, 1) catch |err| {
            self.allocator.free(frame);
            return err;
        };
        actions[0] = .{ .send_frame = frame };
        return actions;
    }

    fn emptyReply(self: *Session) Error!Reply {
        return .{ .actions = try self.allocator.alloc(Action, 0) };
    }
};

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
    };
}

fn validateTerminalIdentifier(last_response: ?u8, identifier: u8) Error!void {
    if (last_response == null or last_response.? != identifier) {
        return error.StaleTerminalIdentifier;
    }
}

fn lastResponseIdentifier(state: State) ?u8 {
    return switch (state) {
        .connecting => |value| if (value.exchange) |exchange| exchange.last_response_identifier else null,
        .acquired => |value| value.exchange.last_response_identifier,
        .authenticating => |value| value.exchange.last_response_identifier,
        else => null,
    };
}

fn addDuration(base: std.Io.Timestamp, duration: std.Io.Duration) Error!std.Io.Timestamp {
    const result = @addWithOverflow(base.nanoseconds, duration.nanoseconds);
    if (result[1] != 0) return error.TimestampOverflow;
    return .fromNanoseconds(result[0]);
}
