//! Deterministic target-profile Ruijie EAP-MD5 session machine.

const std = @import("std");
const crypto = @import("../protocol/crypto.zig");
const eapol = @import("../protocol/eapol.zig");
const ruijie = @import("../protocol/ruijie_eap_md5.zig");
const v3_macos135 = @import("../protocol/v3_macos135.zig");
const types = @import("target_types.zig");

const Action = types.Action;
const Config = types.Config;
const Error = types.Error;
const FailureReason = types.FailureReason;
const FrameInput = types.FrameInput;
const Generation = types.Generation;
const Input = types.Input;
const Outcome = types.Outcome;
const Phase = types.Phase;
const TerminalKind = types.TerminalKind;
const TerminalMessage = types.TerminalMessage;

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
    terminal: ?TerminalMessage = null,

    fn deinit(self: *Reply, allocator: std.mem.Allocator) void {
        for (self.actions) |action| switch (action) {
            .send_frame => |frame| allocator.free(frame),
        };
        allocator.free(self.actions);
        if (self.terminal) |terminal| allocator.free(terminal.notification);
        self.* = undefined;
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    config: Config,
    facts: types.Facts,
    credentials: types.Credentials,
    state: State,
    generation: Generation,
    last_now: ?std.Io.Timestamp,
    auth_failures: u16,
    failure_reason: ?FailureReason,
    /// Server source MAC retained for later frames.
    peer_mac: ?[6]u8,
    /// Current `0x2f` password-chain ciphertext. Starts as the zero-IV result
    /// and is replaced by the challenge ciphertext when one is received.
    chain: [ruijie.max_chain_len]u8,
    chain_len: usize,

    /// Validates the configuration and computes the zero-IV chain default.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Session {
        try config.validate();
        var session: Session = .{
            .allocator = allocator,
            .config = config,
            .facts = config.facts,
            .credentials = config.credentials,
            .state = .disconnected,
            .generation = Generation.initial,
            .last_now = null,
            .auth_failures = 0,
            .failure_reason = null,
            .peer_mac = null,
            .chain = @splat(0),
            .chain_len = 0,
        };
        session.chain_len = try session.recomputeChain(@splat(0));
        return session;
    }

    pub fn deinit(self: *Session) void {
        std.crypto.secureZero(u8, &self.chain);
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
            .connecting => |state| state.deadline,
            .acquired => |state| state.deadline,
            .authenticating => |state| state.deadline,
            .held => |state| state.deadline,
            .disconnected, .authenticated => null,
        };
    }

    pub fn failure(self: *const Session) ?FailureReason {
        return self.failure_reason;
    }

    pub fn currentGeneration(self: *const Session) Generation {
        return self.generation;
    }

    /// Accepts one external event and commits state only after every returned
    /// action and terminal message is allocated.
    pub fn step(self: *Session, now: std.Io.Timestamp, input: Input) Error!Outcome {
        if (self.last_now) |last_now| {
            if (now.compare(.lt, last_now)) return error.TimeWentBackwards;
        }

        var next = self.*;
        next.last_now = now;
        const previous_phase = next.phase();

        var reply = switch (input) {
            .start => try next.handleStart(now),
            .cancel => try next.handleCancel(now),
            .frame => |event| blk: {
                if (!event.generation.eql(next.generation)) return error.StaleGeneration;
                break :blk try next.handleFrame(now, event);
            },
            .timer => |generation| blk: {
                if (!generation.eql(next.generation)) return error.StaleGeneration;
                break :blk try next.handleTimer(now);
            },
            .facts => |facts| blk: {
                try facts.validate();
                next.facts = facts;
                break :blk try next.emptyReply();
            },
        };
        errdefer reply.deinit(next.allocator);

        self.* = next;
        return .{
            .actions = reply.actions,
            .previous_phase = previous_phase,
            .phase = self.phase(),
            .next_deadline = self.nextDeadline(),
            .failure = self.failure_reason,
            .generation = self.generation,
            .terminal = reply.terminal,
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
        const frame = try self.makeControlFrame(now, .start);
        return .{ .actions = try self.singleFrame(frame) };
    }

    fn handleCancel(self: *Session, now: std.Io.Timestamp) Error!Reply {
        switch (self.state) {
            .disconnected => return error.InvalidState,
            else => {},
        }
        const frame = try self.makeControlFrame(now, .logoff);
        self.failure_reason = .canceled;
        self.state = .disconnected;
        return .{ .actions = try self.singleFrame(frame) };
    }

    fn handleFrame(
        self: *Session,
        now: std.Io.Timestamp,
        event: FrameInput,
    ) Error!Reply {
        const frame = eapol.decode(event.bytes) catch return error.InvalidFrame;
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

        self.peer_mac = frame.source;
        const eap = frame.eap orelse return error.InvalidFrame;
        return switch (eap.code) {
            .request => self.handleRequest(now, frame.source, eap),
            .success => self.handleSuccess(now, eap),
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
            .connecting => |state| state.exchange,
            .acquired => |state| state.exchange,
            .authenticating => |state| state.exchange,
            else => return error.InvalidState,
        };
        try acceptRequestIdentifier(&exchange, source, eap, eap_type);
        self.peer_mac = source;

        switch (eap_type) {
            .identity => {
                const frame = try self.makeEapFrame(
                    eap.identifier,
                    .identity,
                    self.credentials.username,
                    .identity,
                    @splat(0),
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
                self.chain_len = try self.recomputeChain(decoded.challenge);
                var digest: [ruijie.v3_digest_len]u8 = undefined;
                _ = v3_macos135.digest(decoded.challenge, &digest) catch return error.InvalidConfig;

                const data = try self.encodeMd5ResponseData(eap.identifier, decoded.challenge);
                defer self.allocator.free(data);
                const frame = try self.makeEapFrame(
                    eap.identifier,
                    .md5_challenge,
                    data,
                    .response,
                    digest,
                );
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.state = .{ .authenticating = .{
                    .deadline = try addDuration(now, self.config.auth_timeout),
                    .exchange = exchange.?,
                } };
                return .{ .actions = try self.singleFrame(frame) };
            },
            .notification => {
                const frame = try self.makeEapFrame(
                    eap.identifier,
                    .notification,
                    &.{},
                    .identity,
                    @splat(0),
                );
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.replaceExchange(exchange.?);
                return .{ .actions = try self.singleFrame(frame) };
            },
            .peap, .credential => return error.UnsupportedEapMethod,
            else => {
                const nak = [_]u8{@backingInt(eapol.EapType.md5_challenge)};
                const frame = try self.makeEapFrame(
                    eap.identifier,
                    .legacy_nak,
                    &nak,
                    .identity,
                    @splat(0),
                );
                exchange.?.last_response_identifier = exchange.?.identifier;
                self.replaceExchange(exchange.?);
                return .{ .actions = try self.singleFrame(frame) };
            },
        }
    }

    fn handleSuccess(
        self: *Session,
        now: std.Io.Timestamp,
        eap: eapol.Eap,
    ) Error!Reply {
        _ = now;
        const state = switch (self.state) {
            .authenticating => |state| state,
            else => return error.InvalidState,
        };
        try validateTerminalIdentifier(state.exchange.last_response_identifier, eap.identifier);
        self.auth_failures = 0;
        self.failure_reason = null;
        self.state = .{ .authenticated = .{ .peer_mac = state.exchange.peer_mac } };
        return self.terminalReply(.success, eap.data);
    }

    fn handleFailure(
        self: *Session,
        now: std.Io.Timestamp,
        eap: eapol.Eap,
    ) Error!Reply {
        const peer_mac = switch (self.state) {
            .connecting => |state| if (state.exchange) |exchange| exchange.peer_mac else null,
            .acquired => |state| state.exchange.peer_mac,
            .authenticating => |state| state.exchange.peer_mac,
            else => return error.InvalidState,
        };
        if (lastResponseIdentifier(self.state)) |identifier| {
            try validateTerminalIdentifier(identifier, eap.identifier);
        }
        try self.enterHeld(now, peer_mac, .server_failure);
        return self.terminalReply(.failure, eap.data);
    }

    fn handleTimer(self: *Session, now: std.Io.Timestamp) Error!Reply {
        const deadline = self.nextDeadline() orelse return error.InvalidState;
        if (now.compare(.lt, deadline)) return error.TimerNotDue;

        switch (self.state) {
            .connecting => |state| {
                if (state.attempts < self.config.max_start_attempts) {
                    try self.enterConnecting(now, state.attempts + 1);
                    const frame = try self.makeControlFrame(now, .start);
                    return .{ .actions = try self.singleFrame(frame) };
                }
                try self.enterHeld(
                    now,
                    if (state.exchange) |exchange| exchange.peer_mac else null,
                    .start_timeout,
                );
                return self.emptyReply();
            },
            .acquired => |state| {
                try self.enterHeld(now, state.exchange.peer_mac, .auth_timeout);
                return self.emptyReply();
            },
            .authenticating => |state| {
                try self.enterHeld(now, state.exchange.peer_mac, .auth_timeout);
                return self.emptyReply();
            },
            .held => {
                if (self.auth_failures >= self.config.max_auth_failures) {
                    const frame = try self.makeControlFrame(now, .logoff);
                    self.state = .disconnected;
                    return .{ .actions = try self.singleFrame(frame) };
                }
                self.failure_reason = null;
                try self.enterConnecting(now, 1);
                const frame = try self.makeControlFrame(now, .start);
                return .{ .actions = try self.singleFrame(frame) };
            },
            .authenticated, .disconnected => return error.InvalidState,
        }
    }

    fn enterConnecting(
        self: *Session,
        now: std.Io.Timestamp,
        attempts: u16,
    ) Error!void {
        self.generation = try self.generation.next();
        self.state = .{ .connecting = .{
            .deadline = try addDuration(now, self.config.start_timeout),
            .attempts = attempts,
            .exchange = null,
        } };
    }

    fn enterHeld(
        self: *Session,
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

    fn replaceExchange(self: *Session, exchange: Exchange) void {
        switch (self.state) {
            .connecting => |*state| state.exchange = exchange,
            .acquired => |*state| state.exchange = exchange,
            .authenticating => |*state| state.exchange = exchange,
            else => unreachable,
        }
    }

    fn recomputeChain(self: *Session, start: [16]u8) Error!usize {
        return crypto.encryptPassword(
            self.credentials.username,
            start,
            self.credentials.password,
            &self.chain,
        ) catch |err| switch (err) {
            error.LengthOverflow => error.InvalidCredentials,
            error.OutputTooSmall => unreachable,
        };
    }

    fn encodeMd5ResponseData(
        self: *Session,
        identifier: u8,
        challenge: [16]u8,
    ) Error![]u8 {
        const required = 1 + 16 + self.credentials.username.len;
        const data = try self.allocator.alloc(u8, required);
        errdefer self.allocator.free(data);
        _ = ruijie.encodeResponseData(
            identifier,
            self.credentials.username,
            self.credentials.password,
            challenge,
            data,
        ) catch |err| switch (err) {
            error.OutputTooSmall => unreachable,
            error.LengthTooLarge => return error.InvalidCredentials,
        };
        return data;
    }

    fn makeControlFrame(
        self: *Session,
        now: std.Io.Timestamp,
        kind: ruijie.Frame,
    ) Error![]u8 {
        _ = now;
        const params = self.tailParams(kind, @splat(0));
        const tail_len = ruijie.tailSize(params);
        const destination = self.peer_mac orelse types.destination_mac;
        const frame = try self.allocator.alloc(u8, eapol.header_size + tail_len);
        errdefer self.allocator.free(frame);

        switch (kind) {
            .start => eapol.encodeStart(
                destination,
                self.facts.source_mac,
                frame[0..eapol.header_size],
            ),
            .logoff => eapol.encodeLogoff(
                destination,
                self.facts.source_mac,
                frame[0..eapol.header_size],
            ),
            else => unreachable,
        }
        _ = ruijie.encodeTail(params, frame[eapol.header_size..]) catch
            return error.InvalidConfig;
        return frame;
    }

    fn makeEapFrame(
        self: *Session,
        identifier: u8,
        eap_type: eapol.EapType,
        data: []const u8,
        kind: ruijie.Frame,
        digest: [ruijie.v3_digest_len]u8,
    ) Error![]u8 {
        const destination = self.peer_mac orelse return error.InvalidState;
        const params = self.tailParams(kind, digest);
        const tail_len = ruijie.tailSize(params);
        const eap_len = 5 + data.len;
        const frame = try self.allocator.alloc(u8, eapol.header_size + eap_len + tail_len);
        errdefer self.allocator.free(frame);

        _ = eapol.encodeEap(
            destination,
            self.facts.source_mac,
            .response,
            identifier,
            eap_type,
            data,
            frame[0 .. eapol.header_size + eap_len],
        ) catch return error.InvalidFrame;
        _ = ruijie.encodeTail(params, frame[eapol.header_size + eap_len ..]) catch
            return error.InvalidConfig;
        return frame;
    }

    fn tailParams(
        self: *const Session,
        kind: ruijie.Frame,
        digest: [ruijie.v3_digest_len]u8,
    ) ruijie.Params {
        const with_ipv6 = kind == .identity or kind == .response;
        return .{
            .frame = kind,
            .source_mac = self.facts.source_mac,
            .service_name = self.facts.service_name,
            .disk_serial = self.facts.disk_serial,
            .ipv6_state = if (with_ipv6) self.facts.ipv6_state else 0,
            .ipv6_link_local = if (with_ipv6)
                self.facts.ipv6_link_local orelse @splat(0)
            else
                @splat(0),
            .ipv6_global = if (with_ipv6)
                self.facts.ipv6_global orelse @splat(0)
            else
                @splat(0),
            .ipv6_third = if (with_ipv6)
                self.facts.ipv6_third orelse @splat(0)
            else
                @splat(0),
            .lease = .{
                .dhcp_enabled = self.facts.lease.dhcp_enabled,
                .ip = self.facts.lease.ip,
                .netmask = self.facts.lease.netmask,
                .gateway = self.facts.lease.gateway,
                .dns = self.facts.lease.dns,
            },
            .alternate_dns_text = self.facts.alternate_dns_text,
            .os_bits = self.facts.os_bits,
            .chain = self.chain[0..self.chain_len],
            .v3_digest = digest,
            .security_ok = kind == .response,
        };
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

    fn terminalReply(
        self: *Session,
        kind: TerminalKind,
        data: []const u8,
    ) Error!Reply {
        const actions = try self.allocator.alloc(Action, 0);
        errdefer self.allocator.free(actions);
        const parsed = ruijie.parseTerminal(data) orelse
            return .{ .actions = actions };
        if (parsed.notification.len == 0) return .{ .actions = actions };
        const notification = try self.allocator.dupe(u8, parsed.notification);
        return .{ .actions = actions, .terminal = .{
            .kind = kind,
            .notification = notification,
        } };
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
        return error.StaleIdentifier;
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
