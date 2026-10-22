//! Direct SAM/SMP protocol machine.

const std = @import("std");
const des = @import("../protocol/des.zig");
const wire = @import("../protocol/direct.zig");
const sam = @import("../protocol/sam.zig");
const smp = @import("../protocol/smp.zig");
const reassembly = @import("reassembly.zig");
const session_outcome = @import("outcome.zig");
const time = @import("time.zig");
const types = @import("types.zig");

const Action = session_outcome.Action;
const Error = types.Error;
const FailureReason = types.FailureReason;
const Input = types.Input;
const Outcome = session_outcome.Outcome;
const OutcomeBuilder = session_outcome.OutcomeBuilder;

const TimestampState = union(enum) {
    server: struct {
        server_anchor: u64,
        local_anchor: std.Io.Timestamp,
        received: ?u64 = null,
    },
    monotonic: struct {
        next_send: u64,
        received: u64,
        non_advancing: u8 = 0,
    },
};

const TimestampUpdate = struct {
    timestamp: u64,
    state: TimestampState,
};

const Fragment = struct {
    offset: usize,
    len: usize,
    flags: u8,
};

const Outbound = struct {
    kind: MessageKind,
    encrypted: []u8,
    total_len: usize,
    offset: usize,
    current_len: usize,
    current_flags: u8,
    current_id: u32,
    attempts: u8,
};

const MessageKind = enum {
    handshake,
    smp_hello,
    smp_heartbeat,
    user_info,
    sam_heartbeat,
};

const SmpInitialization = struct {
    attempts: u8 = 1,
    next_request_at: ?std.Io.Timestamp,
    response_deadline: ?std.Io.Timestamp = null,
    initialization_deadline: std.Io.Timestamp,
};

const PreparedFragment = struct {
    frame: []u8,
    timestamps: TimestampState,
};

pub const Machine = struct {
    allocator: std.mem.Allocator,
    config: types.DirectSessionConfig,
    phase: types.DirectPhase = .initializing,
    generation: types.Generation,
    timestamps: TimestampState,
    next_message_id: u32,
    outbound: ?Outbound = null,
    ack_deadline: ?std.Io.Timestamp = null,
    result_deadline: ?std.Io.Timestamp = null,
    heartbeat_deadline: ?std.Io.Timestamp = null,
    reauth_deadline: ?std.Io.Timestamp = null,
    smp_hello_failures: u8 = 0,
    smp_hello_pending: bool = false,
    smp_initialization: ?SmpInitialization = null,
    reassembler: reassembly.Reassembler,
    received_payload: ?[]u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config: types.DirectSessionConfig,
        now: std.Io.Timestamp,
        generation: types.Generation,
    ) Error!Machine {
        try config.validate();
        const username = try allocator.dupe(u8, config.username_gbk);
        errdefer allocator.free(username);

        var owned = config;
        owned.username_gbk = username;
        return .{
            .allocator = allocator,
            .config = owned,
            .generation = generation,
            .timestamps = switch (config.timestamp) {
                .server => |server_timestamp| .{ .server = .{
                    .server_anchor = server_timestamp,
                    .local_anchor = now,
                } },
                .monotonic => |value| .{ .monotonic = .{
                    .next_send = value,
                    .received = value,
                } },
            },
            .next_message_id = config.next_message_id,
            .reassembler = reassembly.Reassembler.init(allocator, config.max_message_size),
        };
    }

    pub fn deinit(self: *Machine) void {
        self.allocator.free(self.config.username_gbk);
        if (self.outbound) |outbound| self.allocator.free(outbound.encrypted);
        if (self.received_payload) |payload| self.allocator.free(payload);
        self.reassembler.deinit();
        self.* = undefined;
    }

    pub fn currentPhase(self: *const Machine) types.ActivePhase {
        return .{ .direct = self.phase };
    }

    pub fn currentGeneration(self: *const Machine) types.Generation {
        return self.generation;
    }

    pub fn nextDeadline(self: *const Machine) ?std.Io.Timestamp {
        var deadline = minimumDeadline(
            minimumDeadline(self.ack_deadline, self.reassembler.nextDeadline()),
            self.result_deadline,
        );
        deadline = minimumDeadline(deadline, self.heartbeat_deadline);
        deadline = minimumDeadline(deadline, self.reauth_deadline);
        if (self.smp_initialization) |state| {
            deadline = minimumDeadline(deadline, state.initialization_deadline);
            deadline = minimumDeadline(deadline, state.response_deadline);
            deadline = minimumDeadline(deadline, state.next_request_at);
        }
        return deadline;
    }

    pub fn start(self: *Machine, now: std.Io.Timestamp) Error!Outcome {
        return switch (self.config.mode) {
            .sam => self.beginSamHandshake(.handshake, now),
            .smp => |smp_config| blk: {
                const send_immediately = smp_config.initial_request_delay.toNanoseconds() == 0;
                self.smp_initialization = .{
                    .attempts = if (send_immediately) 1 else 0,
                    .next_request_at = if (send_immediately)
                        try time.addDuration(now, smp_config.retry_interval)
                    else
                        try time.addDuration(now, smp_config.initial_request_delay),
                    .initialization_deadline = try time.addDuration(
                        now,
                        smp_config.initialization_timeout,
                    ),
                };
                break :blk if (send_immediately)
                    self.beginSmpHello(.smp_hello, now)
                else
                    self.emptyInitializingOutcome();
            },
        };
    }

    pub fn step(self: *Machine, now: std.Io.Timestamp, input: Input) Error!Outcome {
        return switch (input) {
            .frame => |event| self.handleFrame(now, event.bytes),
            .timer => |generation| {
                if (!generation.eql(self.generation)) return error.StaleGeneration;
                return self.handleTimer(now);
            },
            else => error.InvalidState,
        };
    }

    fn beginMessage(
        self: *Machine,
        encrypted: []u8,
        kind: MessageKind,
        now: std.Io.Timestamp,
    ) Error!Outcome {
        const fragment = fragmentAt(encrypted.len, 0);
        const id = self.next_message_id;
        const prepared = try self.prepareFragment(
            encrypted,
            fragment,
            id,
            self.timestamps,
            now,
        );
        errdefer self.allocator.free(prepared.frame);

        var builder = OutcomeBuilder.init(self.allocator);
        errdefer builder.deinit();
        try builder.addFrame(prepared.frame);
        const actions = try builder.finish();

        self.timestamps = prepared.timestamps;
        self.next_message_id +%= 1;
        self.outbound = .{
            .kind = kind,
            .encrypted = encrypted,
            .total_len = encrypted.len,
            .offset = 0,
            .current_len = fragment.len,
            .current_flags = fragment.flags,
            .current_id = id,
            .attempts = 1,
        };
        self.ack_deadline = try time.addDuration(now, self.config.ack_timeout);
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = .initializing },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = self.generation,
        };
    }

    fn beginPayload(
        self: *Machine,
        payload: []const u8,
        kind: MessageKind,
        now: std.Io.Timestamp,
    ) Error!Outcome {
        const encrypted = try encryptPayload(
            self.allocator,
            self.config.des_key,
            self.config.initial_iv,
            payload,
        );
        errdefer self.allocator.free(encrypted);
        return self.beginMessage(encrypted, kind, now);
    }

    fn beginSmpHello(
        self: *Machine,
        kind: MessageKind,
        now: std.Io.Timestamp,
    ) Error!Outcome {
        const config = switch (self.config.mode) {
            .smp => |smp_config| smp_config,
            .sam => return error.InvalidState,
        };
        const payload = try self.allocator.alloc(
            u8,
            smp.helloSize(self.config.username_gbk.len, config.session_parameter.len),
        );
        defer self.allocator.free(payload);
        _ = smp.encodeHello(
            self.config.username_gbk,
            &config.session_parameter,
            payload,
        ) catch return error.InvalidConfig;
        return self.beginPayload(payload, kind, now);
    }

    fn beginSamHandshake(
        self: *Machine,
        kind: MessageKind,
        now: std.Io.Timestamp,
    ) Error!Outcome {
        const handshake = switch (self.config.mode) {
            .sam => |value| value,
            .smp => return error.InvalidState,
        };
        const payload = try self.allocator.alloc(
            u8,
            sam.handshakeSize(
                self.config.username_gbk.len,
                handshake.session_parameter.len,
                handshake.endpoint_parameter.len,
            ),
        );
        defer self.allocator.free(payload);
        _ = sam.encodeHandshake(
            self.config.username_gbk,
            handshake.session_parameter,
            handshake.endpoint_parameter,
            payload,
        ) catch return error.InvalidConfig;
        return self.beginPayload(payload, kind, now);
    }

    fn emptyInitializingOutcome(self: *Machine) Error!Outcome {
        return .{
            .actions = try self.allocator.alloc(Action, 0),
            .previous_phase = .{ .direct = .initializing },
            .phase = .{ .direct = .initializing },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = self.generation,
        };
    }

    fn beginUserInfo(self: *Machine, now: std.Io.Timestamp) Error!Outcome {
        const current = self.outbound;
        self.outbound = null;

        const payload_len = switch (self.config.mode) {
            .sam => sam.userInfoSize(.{
                .username_gbk = self.config.username_gbk,
                .ipv4 = self.config.network.ipv4,
                .mac = self.config.network.mac,
                .netmask = self.config.network.netmask,
                .gateway = self.config.network.gateway,
                .dns = self.config.network.dns,
            }),
            .smp => smp.userInfoSize(.{
                .username_gbk = self.config.username_gbk,
                .ipv4 = self.config.network.ipv4,
                .netmask = self.config.network.netmask,
                .gateway = self.config.network.gateway,
                .dns = self.config.network.dns,
                .alternate_dns = self.config.network.alternate_dns,
                .mac = self.config.network.mac,
            }),
        };
        const payload = self.allocator.alloc(u8, payload_len) catch |err| {
            self.outbound = current;
            return err;
        };
        defer self.allocator.free(payload);
        switch (self.config.mode) {
            .sam => _ = sam.encodeUserInfo(.{
                .username_gbk = self.config.username_gbk,
                .ipv4 = self.config.network.ipv4,
                .mac = self.config.network.mac,
                .netmask = self.config.network.netmask,
                .gateway = self.config.network.gateway,
                .dns = self.config.network.dns,
            }, payload) catch {
                self.outbound = current;
                return error.InvalidConfig;
            },
            .smp => _ = smp.encodeUserInfo(.{
                .username_gbk = self.config.username_gbk,
                .ipv4 = self.config.network.ipv4,
                .netmask = self.config.network.netmask,
                .gateway = self.config.network.gateway,
                .dns = self.config.network.dns,
                .alternate_dns = self.config.network.alternate_dns,
                .mac = self.config.network.mac,
            }, payload) catch {
                self.outbound = current;
                return error.InvalidConfig;
            },
        }

        const result = self.beginPayload(payload, .user_info, now) catch |err| {
            self.outbound = current;
            return err;
        };
        if (current) |previous| self.allocator.free(previous.encrypted);
        return result;
    }

    fn handleFrame(
        self: *Machine,
        now: std.Io.Timestamp,
        bytes: []const u8,
    ) Error!Outcome {
        const frame = wire.decodeFrame(bytes) catch return self.noop();
        if (!self.matchesEndpoints(frame)) return self.noop();
        if (frame.header.code == 1) return self.handleData(now, frame, bytes);
        if (frame.header.packet_len != wire.header_size or
            frame.header.total_len != 0 or
            frame.header.code != 2) return self.noop();

        const outbound = self.outbound orelse return self.noop();
        if (outbound.current_id != frame.header.id) return self.noop();

        const packet = bytes[wire.ethernet_header_size + wire.ipv4_header_size + wire.udp_header_size ..];
        const valid_authenticator = wire.verifyAuthenticator(
            packet,
            self.config.des_key,
            self.config.initial_iv,
        ) catch false;
        if (!valid_authenticator) return self.noop();

        const timestamp_update = try validateReceivedTimestamp(
            self.timestamps,
            now,
            frame.header.timestamp,
        );
        if (!timestamp_update.accepted) return self.noop();

        const next_offset = outbound.offset + outbound.current_len;
        if (next_offset == outbound.total_len) {
            self.timestamps = timestamp_update.state;
            switch (outbound.kind) {
                .handshake => return self.beginUserInfo(now),
                .smp_hello => {
                    const smp_config = switch (self.config.mode) {
                        .smp => |value| value,
                        .sam => return error.InvalidState,
                    };
                    const actions = try self.allocator.alloc(Action, 0);
                    errdefer self.allocator.free(actions);
                    self.allocator.free(outbound.encrypted);
                    self.outbound = null;
                    self.ack_deadline = null;
                    self.smp_initialization.?.response_deadline = try time.addDuration(
                        now,
                        smp_config.request_timeout,
                    );
                    return .{
                        .actions = actions,
                        .previous_phase = .{ .direct = .initializing },
                        .phase = .{ .direct = .initializing },
                        .next_deadline = self.nextDeadline(),
                        .failure = null,
                        .generation = self.generation,
                    };
                },
                .smp_heartbeat => {
                    const actions = try self.allocator.alloc(Action, 0);
                    errdefer self.allocator.free(actions);
                    self.allocator.free(outbound.encrypted);
                    self.outbound = null;
                    self.ack_deadline = null;
                    return .{
                        .actions = actions,
                        .previous_phase = .{ .direct = .active },
                        .phase = .{ .direct = .active },
                        .next_deadline = self.nextDeadline(),
                        .failure = null,
                        .generation = self.generation,
                    };
                },
                .sam_heartbeat => {
                    const actions = try self.allocator.alloc(Action, 0);
                    errdefer self.allocator.free(actions);
                    self.allocator.free(outbound.encrypted);
                    self.outbound = null;
                    self.ack_deadline = null;
                    self.heartbeat_deadline = if (self.config.heartbeat_interval.toNanoseconds() > 0)
                        try time.addDuration(now, self.config.heartbeat_interval)
                    else
                        null;
                    return .{
                        .actions = actions,
                        .previous_phase = .{ .direct = .active },
                        .phase = .{ .direct = .active },
                        .next_deadline = self.nextDeadline(),
                        .failure = null,
                        .generation = self.generation,
                    };
                },
                .user_info => {
                    const actions = try self.allocator.alloc(Action, 0);
                    errdefer self.allocator.free(actions);
                    self.allocator.free(outbound.encrypted);
                    self.outbound = null;
                    self.ack_deadline = null;
                    self.phase = .awaiting_result;
                    self.result_deadline = try time.addDuration(now, .fromSeconds(9));
                    return .{
                        .actions = actions,
                        .previous_phase = .{ .direct = .initializing },
                        .phase = .{ .direct = self.phase },
                        .next_deadline = self.result_deadline,
                        .failure = null,
                        .generation = self.generation,
                    };
                },
            }
        }

        const fragment = fragmentAt(outbound.total_len, next_offset);
        const id = self.next_message_id;
        const prepared = try self.prepareFragment(
            outbound.encrypted,
            fragment,
            id,
            timestamp_update.state,
            now,
        );
        errdefer self.allocator.free(prepared.frame);
        var builder = OutcomeBuilder.init(self.allocator);
        errdefer builder.deinit();
        try builder.addFrame(prepared.frame);
        const actions = try builder.finish();

        self.timestamps = prepared.timestamps;
        self.next_message_id +%= 1;
        self.outbound = .{
            .kind = outbound.kind,
            .encrypted = outbound.encrypted,
            .total_len = outbound.total_len,
            .offset = next_offset,
            .current_len = fragment.len,
            .current_flags = fragment.flags,
            .current_id = id,
            .attempts = 1,
        };
        self.ack_deadline = try time.addDuration(now, self.config.ack_timeout);
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = self.phase },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = self.generation,
        };
    }

    fn handleData(
        self: *Machine,
        now: std.Io.Timestamp,
        frame: wire.DecodedFrame,
        bytes: []const u8,
    ) Error!Outcome {
        if (frame.header.message_type != 1 or frame.encrypted.len > wire.max_encrypted_chunk) {
            return self.noop();
        }

        const packet = bytes[wire.ethernet_header_size + wire.ipv4_header_size + wire.udp_header_size ..];
        const valid_authenticator = wire.verifyAuthenticator(
            packet,
            self.config.des_key,
            self.config.initial_iv,
        ) catch false;
        if (!valid_authenticator) return self.noop();

        const timestamp_update = try validateReceivedTimestamp(
            self.timestamps,
            now,
            frame.header.timestamp,
        );
        if (!timestamp_update.accepted) return self.noop();
        if (frame.header.total_len == 0 or
            frame.header.total_len > self.config.max_message_size or
            frame.header.total_len % 8 != 0)
        {
            return self.noop();
        }

        const complete_len: ?usize = switch (frame.header.flags) {
            1 => frame.header.total_len,
            4 => if (self.reassembler.total_len == 0) null else self.reassembler.total_len,
            else => null,
        };
        const plaintext_buffer = if (complete_len) |len|
            try self.allocator.alloc(u8, len)
        else
            null;
        errdefer if (plaintext_buffer) |buffer| self.allocator.free(buffer);

        const ack = try self.makeFrame(
            2,
            1,
            frame.header.id,
            0,
            0,
            frame.header.timestamp,
            &.{},
            frame.destination,
            frame.source,
        );

        var builder = OutcomeBuilder.init(self.allocator);
        errdefer builder.deinit();
        try builder.addFrame(ack);
        const actions = try builder.finish();

        const accepted = self.reassembler.accept(
            frame.header.id,
            frame.header.flags,
            frame.header.total_len,
            frame.encrypted,
            now,
        ) catch |err| {
            session_outcome.freeActions(self.allocator, actions);
            return err;
        };
        switch (accepted) {
            .ignored => {
                session_outcome.freeActions(self.allocator, actions);
                if (plaintext_buffer) |buffer| self.allocator.free(buffer);
                return self.noop();
            },
            .duplicate, .buffered => {},
            .complete => |complete| {
                if (plaintext_buffer) |plaintext| {
                    _ = des.decryptCbc(
                        self.config.des_key,
                        self.config.initial_iv,
                        complete,
                        plaintext,
                    ) catch {
                        self.allocator.free(plaintext);
                        self.allocator.free(complete);
                        self.timestamps = timestamp_update.state;
                        return .{
                            .actions = actions,
                            .previous_phase = .{ .direct = self.phase },
                            .phase = .{ .direct = self.phase },
                            .next_deadline = self.nextDeadline(),
                            .failure = null,
                            .generation = self.generation,
                        };
                    };
                    const auth_result: ?sam.DhcpAuthResult = switch (self.config.mode) {
                        .sam => sam.parseDhcpAuthResult(plaintext) catch null,
                        .smp => blk: {
                            if (smp.isHello(plaintext) and self.smp_initialization != null) {
                                self.allocator.free(complete);
                                const outcome = self.acceptSmpHello(
                                    actions,
                                    now,
                                    timestamp_update.state,
                                ) catch |err| {
                                    return err;
                                };
                                self.allocator.free(plaintext);
                                return outcome;
                            }
                            if (smp.isHello(plaintext) and self.phase == .active) {
                                self.allocator.free(complete);
                                self.allocator.free(plaintext);
                                self.timestamps = timestamp_update.state;
                                self.smp_hello_pending = false;
                                self.smp_hello_failures = 0;
                                return .{
                                    .actions = actions,
                                    .previous_phase = .{ .direct = .active },
                                    .phase = .{ .direct = .active },
                                    .next_deadline = self.nextDeadline(),
                                    .failure = null,
                                    .generation = self.generation,
                                };
                            }
                            const result = smp.parseDhcpAuthResult(plaintext) catch null;
                            if (result) |value| {
                                break :blk .{
                                    .success = value.success,
                                    .message_gbk = value.message_gbk,
                                };
                            }
                            break :blk null;
                        },
                    };
                    if (auth_result) |result| {
                        self.allocator.free(complete);
                        const outcome = self.completeWithSamResult(
                            actions,
                            result,
                            timestamp_update.state,
                            now,
                        ) catch |err| {
                            return err;
                        };
                        self.allocator.free(plaintext);
                        return outcome;
                    }
                    if (self.received_payload) |previous| self.allocator.free(previous);
                    self.received_payload = plaintext;
                }
                self.allocator.free(complete);
            },
        }

        self.timestamps = timestamp_update.state;
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = self.phase },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = self.generation,
        };
    }

    fn acceptSmpHello(
        self: *Machine,
        actions: []Action,
        now: std.Io.Timestamp,
        timestamps: TimestampState,
    ) Error!Outcome {
        self.timestamps = timestamps;
        self.smp_initialization = null;
        const user_info = self.beginUserInfo(now) catch |err| {
            session_outcome.freeActions(self.allocator, actions);
            return err;
        };
        const combined = try combineActionSlices(self.allocator, actions, user_info.actions);
        return .{
            .actions = combined,
            .previous_phase = .{ .direct = .initializing },
            .phase = user_info.phase,
            .next_deadline = user_info.next_deadline,
            .failure = null,
            .generation = self.generation,
        };
    }

    fn completeWithSamResult(
        self: *Machine,
        actions: []Action,
        result: sam.DhcpAuthResult,
        timestamps: TimestampState,
        now: std.Io.Timestamp,
    ) Error!Outcome {
        const message = if (result.message_gbk.len == 0)
            null
        else
            try self.allocator.dupe(u8, result.message_gbk);
        errdefer if (message) |value| self.allocator.free(value);

        const combined = self.allocator.alloc(Action, 2) catch |err| {
            session_outcome.freeActions(self.allocator, actions);
            return err;
        };
        errdefer self.allocator.free(combined);
        combined[0] = actions[0];
        combined[1] = .{ .direct_auth_result = .{
            .success = result.success,
            .server_message_gbk = message,
        } };
        self.allocator.free(actions);

        self.timestamps = timestamps;
        self.result_deadline = null;
        if (result.success) {
            self.heartbeat_deadline = if (self.config.heartbeat_interval.toNanoseconds() > 0)
                try time.addDuration(now, self.config.heartbeat_interval)
            else
                null;
            self.reauth_deadline = if (self.config.reauth_interval.toNanoseconds() > 0)
                try time.addDuration(now, self.config.reauth_interval)
            else
                null;
            self.phase = .active;
            return .{
                .actions = combined,
                .previous_phase = .{ .direct = .awaiting_result },
                .phase = .{ .direct = .active },
                .next_deadline = self.nextDeadline(),
                .failure = null,
                .generation = self.generation,
            };
        }

        self.phase = .initializing;
        return .{
            .actions = combined,
            .previous_phase = .{ .direct = .awaiting_result },
            .phase = .idle,
            .next_deadline = null,
            .failure = if (result.message_gbk.len == 0)
                .direct_result_timeout
            else
                .direct_result_rejected,
            .generation = self.generation,
        };
    }

    fn matchesEndpoints(self: *const Machine, frame: wire.DecodedFrame) bool {
        return frame.header.session_id == self.config.session_id and
            std.mem.eql(u8, &frame.source.mac, &self.config.peer_mac) and
            std.mem.eql(u8, &frame.destination.mac, &self.config.network.mac) and
            frame.source.port == self.config.peer_udp_port and
            frame.destination.port == self.config.local_udp_port and
            std.mem.eql(u8, &frame.source.ip, &self.config.peer_ipv4) and
            std.mem.eql(u8, &frame.destination.ip, &self.config.network.ipv4);
    }

    fn handleTimer(self: *Machine, now: std.Io.Timestamp) Error!Outcome {
        if (try self.handleSmpTimer(now)) |outcome| return outcome;
        if (try self.handleActiveTimer(now)) |outcome| return outcome;
        const reassembly_deadline = self.reassembler.nextDeadline();
        const reassembly_expired = self.reassembler.expire(now);
        const result_deadline = self.result_deadline;
        const result_expired = if (result_deadline) |deadline|
            !now.compare(.lt, deadline)
        else
            false;
        const deadline = self.ack_deadline orelse {
            if (reassembly_expired) return self.noop();
            if (result_expired) return self.resultTimeout();
            if (result_deadline) |result_at| {
                if (now.compare(.lt, result_at)) return error.TimerNotDue;
            }
            if (reassembly_deadline) |reassembly_at| {
                if (now.compare(.lt, reassembly_at)) return error.TimerNotDue;
            }
            if (self.nextDeadline()) |next| {
                if (now.compare(.lt, next)) return error.TimerNotDue;
            }
            return error.InvalidState;
        };
        if (now.compare(.lt, deadline)) {
            if (reassembly_expired) return self.noop();
            return error.TimerNotDue;
        }
        const outbound = self.outbound orelse return error.InvalidState;

        if (outbound.attempts >= self.config.max_send_attempts) {
            const actions = try self.allocator.alloc(Action, 0);
            errdefer self.allocator.free(actions);
            self.allocator.free(outbound.encrypted);
            self.outbound = null;
            self.ack_deadline = null;
            return .{
                .actions = actions,
                .previous_phase = .{ .direct = self.phase },
                .phase = .idle,
                .next_deadline = null,
                .failure = .direct_send_failed,
                .generation = self.generation,
            };
        }

        const fragment: Fragment = .{
            .offset = outbound.offset,
            .len = outbound.current_len,
            .flags = outbound.current_flags,
        };
        const prepared = try self.prepareFragment(
            outbound.encrypted,
            fragment,
            outbound.current_id,
            self.timestamps,
            now,
        );
        errdefer self.allocator.free(prepared.frame);
        var builder = OutcomeBuilder.init(self.allocator);
        errdefer builder.deinit();
        try builder.addFrame(prepared.frame);
        const actions = try builder.finish();

        self.timestamps = prepared.timestamps;
        self.outbound.?.attempts += 1;
        self.ack_deadline = try time.addDuration(now, self.config.ack_timeout);
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = self.phase },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = self.generation,
        };
    }

    fn handleActiveTimer(self: *Machine, now: std.Io.Timestamp) Error!?Outcome {
        if (self.phase != .active) return null;
        if (self.reauth_deadline) |deadline| {
            if (!now.compare(.lt, deadline)) return try self.reauthRequired();
        }
        if (self.heartbeat_deadline) |deadline| {
            if (!now.compare(.lt, deadline) and self.outbound == null) {
                switch (self.config.mode) {
                    .sam => {
                        const previous = self.heartbeat_deadline;
                        self.heartbeat_deadline = null;
                        var outcome = self.beginSamHandshake(.sam_heartbeat, now) catch |err| {
                            self.heartbeat_deadline = previous;
                            return err;
                        };
                        outcome.next_deadline = self.nextDeadline();
                        return outcome;
                    },
                    .smp => {
                        if (self.smp_hello_pending) {
                            self.smp_hello_pending = false;
                            self.smp_hello_failures += 1;
                            if (self.smp_hello_failures >= 3) return try self.reauthRequired();
                        }

                        var outcome = try self.beginSmpHello(.smp_heartbeat, now);
                        self.smp_hello_pending = true;
                        self.heartbeat_deadline = try time.addDuration(
                            now,
                            self.config.heartbeat_interval,
                        );
                        outcome.next_deadline = self.nextDeadline();
                        return outcome;
                    },
                }
            }
        }
        return null;
    }

    fn reauthRequired(self: *Machine) Error!Outcome {
        const actions = try self.allocator.alloc(Action, 1);
        errdefer self.allocator.free(actions);
        actions[0] = .reauth_required;
        self.heartbeat_deadline = null;
        self.reauth_deadline = null;
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = .active },
            .phase = .idle,
            .next_deadline = null,
            .failure = null,
            .generation = self.generation,
        };
    }

    fn handleSmpTimer(self: *Machine, now: std.Io.Timestamp) Error!?Outcome {
        var state = &(self.smp_initialization orelse return null);
        if (!now.compare(.lt, state.initialization_deadline)) {
            return try self.smpInitializationTimeout();
        }
        var response_expired = false;
        if (state.response_deadline) |deadline| {
            if (!now.compare(.lt, deadline)) {
                state.response_deadline = null;
                response_expired = true;
            }
        }
        if (state.next_request_at) |request_at| {
            if (!now.compare(.lt, request_at) and self.outbound == null) {
                const smp_config = switch (self.config.mode) {
                    .smp => |value| value,
                    .sam => return null,
                };
                var outcome = try self.beginSmpHello(.smp_hello, now);
                state.attempts += 1;
                state.response_deadline = null;
                state.next_request_at = if (state.attempts < 3)
                    try time.addDuration(now, smp_config.retry_interval)
                else
                    null;
                outcome.next_deadline = self.nextDeadline();
                return outcome;
            }
        }
        if (response_expired) return try self.noop();
        return null;
    }

    fn smpInitializationTimeout(self: *Machine) Error!Outcome {
        const actions = try self.allocator.alloc(Action, 1);
        errdefer self.allocator.free(actions);
        actions[0] = .{ .direct_auth_result = .{
            .success = false,
            .server_message_gbk = null,
        } };
        self.smp_initialization = null;
        self.phase = .initializing;
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = .initializing },
            .phase = .idle,
            .next_deadline = null,
            .failure = .smp_initialization_timeout,
            .generation = self.generation,
        };
    }

    fn resultTimeout(self: *Machine) Error!Outcome {
        const actions = try self.allocator.alloc(Action, 1);
        errdefer self.allocator.free(actions);
        actions[0] = .{ .direct_auth_result = .{
            .success = false,
            .server_message_gbk = null,
        } };
        self.result_deadline = null;
        self.phase = .initializing;
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = .awaiting_result },
            .phase = .idle,
            .next_deadline = null,
            .failure = .direct_result_timeout,
            .generation = self.generation,
        };
    }

    fn prepareFragment(
        self: *Machine,
        encrypted: []const u8,
        fragment: Fragment,
        id: u32,
        timestamps: TimestampState,
        now: std.Io.Timestamp,
    ) Error!PreparedFragment {
        const timestamp_update = try nextSendTimestamp(timestamps, now);
        const frame = try self.makeFrame(
            1,
            1,
            id,
            fragment.flags,
            @intCast(encrypted.len),
            timestamp_update.timestamp,
            encrypted[fragment.offset..][0..fragment.len],
            .{
                .mac = self.config.network.mac,
                .ip = self.config.network.ipv4,
                .port = self.config.local_udp_port,
            },
            .{
                .mac = self.config.peer_mac,
                .ip = self.config.peer_ipv4,
                .port = self.config.peer_udp_port,
            },
        );
        return .{
            .frame = frame,
            .timestamps = timestamp_update.state,
        };
    }

    fn noop(self: *const Machine) Error!Outcome {
        return .{
            .actions = try self.allocator.alloc(Action, 0),
            .previous_phase = .{ .direct = self.phase },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = self.generation,
        };
    }

    fn makeFrame(
        self: *Machine,
        code: u8,
        message_type: u8,
        id: u32,
        flags: u8,
        total_len: u32,
        timestamp: u64,
        encrypted: []const u8,
        source: wire.Endpoint,
        destination: wire.Endpoint,
    ) Error![]u8 {
        const frame_len = wire.ethernet_header_size + wire.ipv4_header_size +
            wire.udp_header_size + wire.header_size + encrypted.len;
        const frame = try self.allocator.alloc(u8, frame_len);
        errdefer self.allocator.free(frame);

        _ = wire.encodeFrame(.{
            .version = 1,
            .code = code,
            .id = id,
            .packet_len = @intCast(wire.header_size + encrypted.len),
            .authenticator = @splat(0),
            .session_id = self.config.session_id,
            .timestamp = timestamp,
            .message_type = message_type,
            .flags = flags,
            .total_len = total_len,
        }, encrypted, source, destination, frame) catch return error.InvalidConfig;

        wire.setAuthenticator(
            frame,
            self.config.des_key,
            self.config.initial_iv,
        ) catch return error.InvalidConfig;
        return frame;
    }
};

fn nextSendTimestamp(
    state: TimestampState,
    now: std.Io.Timestamp,
) Error!TimestampUpdate {
    var next = state;
    return switch (next) {
        .server => |*server| blk: {
            const elapsed = now.nanoseconds - server.local_anchor.nanoseconds;
            if (elapsed < 0) return error.TimeWentBackwards;
            const seconds: u64 = @intCast(@divFloor(elapsed, std.time.ns_per_s));
            const timestamp = std.math.add(u64, server.server_anchor, seconds) catch
                return error.TimestampOverflow;
            break :blk .{ .timestamp = timestamp, .state = next };
        },
        .monotonic => |*monotonic| blk: {
            const timestamp = monotonic.next_send;
            monotonic.next_send = std.math.add(u64, monotonic.next_send, 1) catch
                return error.TimestampOverflow;
            break :blk .{ .timestamp = timestamp, .state = next };
        },
    };
}

fn validateReceivedTimestamp(
    state: TimestampState,
    now: std.Io.Timestamp,
    received: u64,
) Error!struct { accepted: bool, state: TimestampState } {
    var next = state;
    return switch (next) {
        .server => |*server| blk: {
            const elapsed = now.nanoseconds - server.local_anchor.nanoseconds;
            if (elapsed < 0) return error.TimeWentBackwards;
            const seconds: u64 = @intCast(@divFloor(elapsed, std.time.ns_per_s));
            const expected = std.math.add(u64, server.server_anchor, seconds) catch
                return error.TimestampOverflow;
            const distance = if (received >= expected) received - expected else expected - received;
            if (distance >= 61) break :blk .{ .accepted = false, .state = state };
            server.received = received;
            break :blk .{ .accepted = true, .state = next };
        },
        .monotonic => |*monotonic| blk: {
            if (received > monotonic.received) {
                monotonic.received = received;
                monotonic.non_advancing = 0;
                break :blk .{ .accepted = true, .state = next };
            }
            if (monotonic.non_advancing >= 5) {
                break :blk .{ .accepted = false, .state = state };
            }
            monotonic.non_advancing += 1;
            break :blk .{ .accepted = true, .state = next };
        },
    };
}

fn fragmentAt(total_len: usize, offset: usize) Fragment {
    const remaining = total_len - offset;
    const len = @min(remaining, wire.max_encrypted_chunk);
    const flags: u8 = if (offset == 0 and len == total_len)
        1
    else if (offset == 0)
        2
    else if (offset + len == total_len)
        4
    else
        3;
    return .{ .offset = offset, .len = len, .flags = flags };
}

fn minimumDeadline(
    first: ?std.Io.Timestamp,
    second: ?std.Io.Timestamp,
) ?std.Io.Timestamp {
    if (first == null) return second;
    if (second == null) return first;
    return if (first.?.compare(.lt, second.?)) first.? else second.?;
}

fn combineActionSlices(
    allocator: std.mem.Allocator,
    first: []Action,
    second: []Action,
) Error![]Action {
    const combined = allocator.alloc(Action, first.len + second.len) catch |err| {
        session_outcome.freeActions(allocator, first);
        session_outcome.freeActions(allocator, second);
        return err;
    };
    @memcpy(combined[0..first.len], first);
    @memcpy(combined[first.len..], second);
    allocator.free(first);
    allocator.free(second);
    return combined;
}

fn encryptPayload(
    allocator: std.mem.Allocator,
    key: [8]u8,
    iv: [8]u8,
    payload: []const u8,
) Error![]u8 {
    const padded_len = std.mem.alignForward(usize, payload.len, 8);
    const padded = try allocator.alloc(u8, padded_len);
    defer allocator.free(padded);
    @memset(padded, 0);
    @memcpy(padded[0..payload.len], payload);

    const encrypted = try allocator.alloc(u8, padded_len);
    errdefer allocator.free(encrypted);
    _ = des.encryptCbc(key, iv, padded, encrypted) catch return error.InvalidConfig;
    return encrypted;
}

test "Direct fragments a message in strict flag order" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const encrypted = try std.testing.allocator.alloc(u8, 3008);
    @memset(encrypted, 0x5a);
    var outcome = try machine.beginMessage(encrypted, .user_info, testTimestamp(0));

    const expected_flags = [_]u8{ 2, 3, 4 };
    for (expected_flags, 0..) |expected_flag, index| {
        try std.testing.expectEqual(@as(usize, 1), outcome.actions.len);
        const frame = try wire.decodeFrame(outcome.actions[0].send_frame);
        try std.testing.expectEqual(expected_flag, frame.header.flags);
        try std.testing.expectEqual(@as(u32, 3008), frame.header.total_len);

        var ack_buffer: [256]u8 = undefined;
        const ack = try encodeAckForFrame(&ack_buffer, frame, config);
        outcome.deinit(std.testing.allocator);
        outcome = try machine.step(
            testTimestamp((index + 1) * std.time.ns_per_s),
            .{ .frame = .{
                .generation = machine.currentGeneration(),
                .bytes = ack,
            } },
        );
    }
    outcome.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(12 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );
    try std.testing.expectEqual(
        types.ActivePhase{ .direct = .awaiting_result },
        machine.currentPhase(),
    );
}

test "Direct retransmits the same fragment until attempts are exhausted" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const encrypted = try std.testing.allocator.alloc(u8, 100);
    @memset(encrypted, 0x33);
    var initial = try machine.beginMessage(encrypted, .user_info, testTimestamp(0));
    const initial_frame = try wire.decodeFrame(initial.actions[0].send_frame);

    try std.testing.expectError(error.TimerNotDue, machine.step(
        testTimestamp(2 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    ));
    var retry = try machine.step(
        testTimestamp(3 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    const retried_frame = try wire.decodeFrame(retry.actions[0].send_frame);
    try std.testing.expectEqual(initial_frame.header.id, retried_frame.header.id);
    try std.testing.expectEqual(initial_frame.header.flags, retried_frame.header.flags);
    try std.testing.expectEqualSlices(u8, initial_frame.encrypted, retried_frame.encrypted);
    try std.testing.expect(initial_frame.header.timestamp != retried_frame.header.timestamp);
    initial.deinit(std.testing.allocator);
    retry.deinit(std.testing.allocator);

    var final_attempt = try machine.step(
        testTimestamp(6 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    final_attempt.deinit(std.testing.allocator);

    var failed = try machine.step(
        testTimestamp(9 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectEqual(types.ActivePhase.idle, failed.phase);
    try std.testing.expectEqual(types.FailureReason.direct_send_failed, failed.failure.?);
    try std.testing.expectEqual(@as(usize, 0), failed.actions.len);
}

test "Direct acknowledges and decrypts a complete inbound message" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    var plaintext: [16]u8 = undefined;
    for (&plaintext, 0..) |*byte, index| byte.* = @intCast(index);
    var encrypted: [16]u8 = undefined;
    _ = try des.encryptCbc(config.des_key, config.initial_iv, &plaintext, &encrypted);

    var frame_buffer: [256]u8 = undefined;
    const frame = try encodeDataForTest(
        &frame_buffer,
        config,
        1,
        1,
        encrypted.len,
        100,
        &encrypted,
    );
    var received = try machine.step(
        testTimestamp(0),
        .{ .frame = .{
            .generation = machine.currentGeneration(),
            .bytes = frame,
        } },
    );
    defer received.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), received.actions.len);
    const ack = try wire.decodeFrame(received.actions[0].send_frame);
    try std.testing.expectEqual(@as(u8, 2), ack.header.code);
    try std.testing.expectEqual(@as(u32, 1), ack.header.id);
    try std.testing.expectEqual(@as(u16, wire.header_size), ack.header.packet_len);
    try std.testing.expectEqual(@as(u32, 0), ack.header.total_len);
    try std.testing.expectEqualSlices(u8, &plaintext, machine.received_payload.?);
}

test "Direct reassembles only a complete ordered sequence" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const total_len = 3008;
    const plaintext = try std.testing.allocator.alloc(u8, total_len);
    defer std.testing.allocator.free(plaintext);
    for (plaintext, 0..) |*byte, index| byte.* = @truncate(index);
    const encrypted = try std.testing.allocator.alloc(u8, total_len);
    defer std.testing.allocator.free(encrypted);
    _ = try des.encryptCbc(config.des_key, config.initial_iv, plaintext, encrypted);

    var first = try sendDataForTest(&machine, config, 1, 2, total_len, 100, encrypted[0..1358]);
    first.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(?[]u8, null), machine.received_payload);
    try std.testing.expectEqual(
        testTimestamp(9 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );

    var skipped = try sendDataForTest(&machine, config, 3, 3, total_len, 100, encrypted[1358..2716]);
    try std.testing.expectEqual(@as(usize, 0), skipped.actions.len);
    skipped.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(9 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );

    var duplicate = try sendDataForTest(&machine, config, 1, 2, total_len, 100, encrypted[0..1358]);
    try std.testing.expectEqual(@as(usize, 1), duplicate.actions.len);
    duplicate.deinit(std.testing.allocator);

    var middle = try sendDataForTest(&machine, config, 2, 3, total_len, 100, encrypted[1358..2716]);
    middle.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(?[]u8, null), machine.received_payload);

    var last = try sendDataForTest(&machine, config, 3, 4, total_len, 100, encrypted[2716..]);
    last.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, plaintext, machine.received_payload.?);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), machine.nextDeadline());
}

test "Direct expires incomplete reassembly after nine seconds" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const encrypted = try std.testing.allocator.alloc(u8, 3008);
    defer std.testing.allocator.free(encrypted);
    @memset(encrypted, 0x44);

    var first = try sendDataForTest(&machine, config, 1, 2, 3008, 100, encrypted[0..1358]);
    first.deinit(std.testing.allocator);
    var expired = try machine.step(
        testTimestamp(9 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer expired.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), expired.actions.len);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), machine.nextDeadline());

    var last = try sendDataForTest(&machine, config, 2, 4, 3008, 100, encrypted[1358..2716]);
    try std.testing.expectEqual(@as(usize, 0), last.actions.len);
    last.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(?[]u8, null), machine.received_payload);
}

test "Direct rejects oversized reassembly before allocation" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const encrypted = try std.testing.allocator.alloc(u8, 1358);
    defer std.testing.allocator.free(encrypted);
    @memset(encrypted, 0x55);
    var rejected = try sendDataForTest(
        &machine,
        config,
        1,
        2,
        @intCast(config.max_message_size + 8),
        100,
        encrypted,
    );
    defer rejected.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), rejected.actions.len);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), machine.nextDeadline());
}

test "Direct timestamp modes reject timestamps outside their windows" {
    const server = TimestampState{ .server = .{
        .server_anchor = 1000,
        .local_anchor = testTimestamp(0),
    } };
    const accepted_server = try validateReceivedTimestamp(server, testTimestamp(0), 1038);
    try std.testing.expect(accepted_server.accepted);
    const rejected_server = try validateReceivedTimestamp(server, testTimestamp(0), 1061);
    try std.testing.expect(!rejected_server.accepted);

    const monotonic = TimestampState{ .monotonic = .{
        .next_send = 100,
        .received = 100,
    } };
    var state = monotonic;
    for (0..5) |_| {
        const update = try validateReceivedTimestamp(state, testTimestamp(0), 100);
        try std.testing.expect(update.accepted);
        state = update.state;
    }
    const rejected_monotonic = try validateReceivedTimestamp(state, testTimestamp(0), 100);
    try std.testing.expect(!rejected_monotonic.accepted);
}

test "Direct maps a rejected SAM result to a terminal event" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();
    try enterAwaitingResult(&machine, config);

    var payload: [16]u8 = @splat(0);
    payload[0..15].* = .{
        1,    1,   12,
        0x09, 10,  0x02,
        5,    'b', 'a',
        'd',  '!', '!',
        0x13, 1,   0,
    };
    var encrypted: [16]u8 = undefined;
    _ = try des.encryptCbc(config.des_key, config.initial_iv, &payload, &encrypted);
    var result = try sendDataForTest(&machine, config, 50, 1, encrypted.len, 100, &encrypted);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(types.ActivePhase.idle, result.phase);
    try std.testing.expectEqual(types.FailureReason.direct_result_rejected, result.failure.?);
    try std.testing.expectEqual(@as(usize, 2), result.actions.len);
    const auth = result.actions[1].direct_auth_result;
    try std.testing.expect(!auth.success);
    try std.testing.expectEqualStrings("bad!!", auth.server_message_gbk.?);
}

test "Direct terminates when the SAM result deadline expires" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();
    try enterAwaitingResult(&machine, config);

    var timeout = try machine.step(
        testTimestamp(9 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer timeout.deinit(std.testing.allocator);
    try std.testing.expectEqual(types.ActivePhase.idle, timeout.phase);
    try std.testing.expectEqual(types.FailureReason.direct_result_timeout, timeout.failure.?);
    try std.testing.expectEqual(@as(usize, 1), timeout.actions.len);
    const auth = timeout.actions[0].direct_auth_result;
    try std.testing.expect(!auth.success);
    try std.testing.expectEqual(@as(?[]u8, null), auth.server_message_gbk);
}

test "Direct retries SMP hello on the configured schedule and times out" {
    const config = testSmpConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    var started = try machine.start(testTimestamp(0));
    try std.testing.expectEqual(@as(usize, 1), started.actions.len);
    try std.testing.expectEqual(
        testTimestamp(3 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );
    try acknowledgeCurrentFrame(&machine, config, started.actions[0].send_frame, 0);
    started.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(10 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );

    var response_expired = try machine.step(
        testTimestamp(10 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    response_expired.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(30 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );

    var second = try machine.step(
        testTimestamp(30 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    const second_frame = try wire.decodeFrame(second.actions[0].send_frame);
    try std.testing.expectEqual(@as(u8, 1), second_frame.header.flags);
    try acknowledgeCurrentFrame(&machine, config, second.actions[0].send_frame, 30);
    second.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(40 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );

    var second_expired = try machine.step(
        testTimestamp(40 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    second_expired.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(60 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );
    var third = try machine.step(
        testTimestamp(60 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    third.deinit(std.testing.allocator);

    var timed_out = try machine.step(
        testTimestamp(90 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer timed_out.deinit(std.testing.allocator);
    try std.testing.expectEqual(types.ActivePhase.idle, timed_out.phase);
    try std.testing.expectEqual(
        types.FailureReason.smp_initialization_timeout,
        timed_out.failure.?,
    );
}

test "Direct completes SMP initialization and authentication" {
    const config = testSmpConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    var started = try machine.start(testTimestamp(0));
    try acknowledgeCurrentFrame(&machine, config, started.actions[0].send_frame, 1);
    started.deinit(std.testing.allocator);

    var hello_payload: [64]u8 = undefined;
    const hello = try smp.encodeHello("alice", &.{ 1, 2, 3, 4 }, &hello_payload);
    var hello_encrypted: [64]u8 = undefined;
    const hello_cipher_len = std.mem.alignForward(usize, hello.len, 8);
    var padded_hello: [64]u8 = @splat(0);
    @memcpy(padded_hello[0..hello.len], hello);
    _ = try des.encryptCbc(
        config.des_key,
        config.initial_iv,
        padded_hello[0..hello_cipher_len],
        &hello_encrypted,
    );
    var hello_response = try sendDataAtForTest(
        &machine,
        config,
        40,
        1,
        @intCast(hello_cipher_len),
        100,
        hello_encrypted[0..hello_cipher_len],
        testTimestamp(2 * std.time.ns_per_s),
    );
    try std.testing.expectEqual(@as(usize, 2), hello_response.actions.len);
    const user_info_frame = try wire.decodeFrame(hello_response.actions[1].send_frame);
    try std.testing.expectEqual(@as(u8, 1), user_info_frame.header.code);
    hello_response.deinit(std.testing.allocator);

    var user_info_ack_buffer: [256]u8 = undefined;
    const user_info_ack = try encodeAckForFrame(
        &user_info_ack_buffer,
        user_info_frame,
        config,
    );
    var waiting = try machine.step(
        testTimestamp(3 * std.time.ns_per_s),
        .{ .frame = .{
            .generation = machine.currentGeneration(),
            .bytes = user_info_ack,
        } },
    );
    waiting.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        types.ActivePhase{ .direct = .awaiting_result },
        machine.currentPhase(),
    );

    var result_payload: [16]u8 = @splat(0);
    result_payload[0..11].* = .{
        1,    0, 1, 0x2e,
        0xce, 0, 1, 1,
        0xcf, 0, 2,
    };
    result_payload[11] = 'o';
    result_payload[12] = 'k';
    var result_encrypted: [16]u8 = undefined;
    _ = try des.encryptCbc(
        config.des_key,
        config.initial_iv,
        &result_payload,
        &result_encrypted,
    );
    var result = try sendDataAtForTest(
        &machine,
        config,
        41,
        1,
        result_encrypted.len,
        102,
        &result_encrypted,
        testTimestamp(4 * std.time.ns_per_s),
    );
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        types.ActivePhase{ .direct = .active },
        result.phase,
    );
    const auth = result.actions[1].direct_auth_result;
    try std.testing.expect(auth.success);
    try std.testing.expectEqualStrings("ok", auth.server_message_gbk.?);
}

test "Direct honors a delayed first SMP hello" {
    var config = testSmpConfig();
    config.mode.smp.initial_request_delay = .fromSeconds(5);
    config.mode.smp.initialization_timeout = .fromSeconds(20);
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    var started = try machine.start(testTimestamp(0));
    try std.testing.expectEqual(@as(usize, 0), started.actions.len);
    try std.testing.expectEqual(
        testTimestamp(5 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );
    started.deinit(std.testing.allocator);
    try std.testing.expectError(error.TimerNotDue, machine.step(
        testTimestamp(4 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    ));

    var hello = try machine.step(
        testTimestamp(5 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer hello.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), hello.actions.len);
}

test "Direct sends SAM heartbeats and terminates on reauthentication" {
    var config = testConfig();
    config.heartbeat_interval = .fromSeconds(5);
    config.reauth_interval = .fromSeconds(20);
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();
    try enterActiveSam(&machine, config);

    try std.testing.expectEqual(
        testTimestamp(5 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );
    var heartbeat = try machine.step(
        testTimestamp(5 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    try std.testing.expectEqual(@as(usize, 1), heartbeat.actions.len);
    const heartbeat_frame = try wire.decodeFrame(heartbeat.actions[0].send_frame);
    try std.testing.expectEqual(@as(u8, 1), heartbeat_frame.header.code);
    try acknowledgeCurrentFrame(&machine, config, heartbeat.actions[0].send_frame, 5);
    heartbeat.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        testTimestamp(10 * std.time.ns_per_s),
        machine.nextDeadline().?,
    );

    var next_heartbeat = try machine.step(
        testTimestamp(10 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    try std.testing.expectEqual(@as(usize, 1), next_heartbeat.actions.len);
    next_heartbeat.deinit(std.testing.allocator);

    var reauth = try machine.step(
        testTimestamp(20 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer reauth.deinit(std.testing.allocator);
    try std.testing.expectEqual(types.ActivePhase.idle, reauth.phase);
    try std.testing.expectEqual(Action.reauth_required, reauth.actions[0]);
}

test "Direct requires three unanswered SMP hello intervals" {
    var config = testSmpConfig();
    config.heartbeat_interval = .fromSeconds(5);
    config.reauth_interval = .fromSeconds(100);
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();
    try enterActiveSmp(&machine, config);

    var first = try machine.step(
        testTimestamp(5 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    const first_frame = try wire.decodeFrame(first.actions[0].send_frame);
    try std.testing.expectEqual(@as(u8, 1), first_frame.header.code);
    try acknowledgeCurrentFrame(&machine, config, first.actions[0].send_frame, 5);
    first.deinit(std.testing.allocator);

    var second = try machine.step(
        testTimestamp(10 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    try std.testing.expectEqual(@as(usize, 1), second.actions.len);
    try acknowledgeCurrentFrame(&machine, config, second.actions[0].send_frame, 10);
    second.deinit(std.testing.allocator);

    var hello_payload: [32]u8 = undefined;
    const hello = try smp.encodeHello("alice", &.{ 1, 2, 3, 4 }, &hello_payload);
    const hello_cipher_len = std.mem.alignForward(usize, hello.len, 8);
    var padded_hello: [32]u8 = @splat(0);
    @memcpy(padded_hello[0..hello.len], hello);
    var hello_encrypted: [32]u8 = undefined;
    _ = try des.encryptCbc(
        config.des_key,
        config.initial_iv,
        padded_hello[0..hello_cipher_len],
        &hello_encrypted,
    );
    var response = try sendDataAtForTest(
        &machine,
        config,
        62,
        1,
        @intCast(hello_cipher_len),
        102,
        hello_encrypted[0..hello_cipher_len],
        testTimestamp(11 * std.time.ns_per_s),
    );
    response.deinit(std.testing.allocator);

    var third = try machine.step(
        testTimestamp(15 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    try acknowledgeCurrentFrame(&machine, config, third.actions[0].send_frame, 15);
    third.deinit(std.testing.allocator);

    var fourth = try machine.step(
        testTimestamp(20 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    try std.testing.expectEqual(types.ActivePhase{ .direct = .active }, fourth.phase);
    try std.testing.expectEqual(@as(usize, 1), fourth.actions.len);
    try acknowledgeCurrentFrame(&machine, config, fourth.actions[0].send_frame, 20);
    fourth.deinit(std.testing.allocator);

    var fifth = try machine.step(
        testTimestamp(25 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    try std.testing.expectEqual(@as(usize, 1), fifth.actions.len);
    try acknowledgeCurrentFrame(&machine, config, fifth.actions[0].send_frame, 25);
    fifth.deinit(std.testing.allocator);

    var reauth = try machine.step(
        testTimestamp(30 * std.time.ns_per_s),
        .{ .timer = machine.currentGeneration() },
    );
    defer reauth.deinit(std.testing.allocator);
    try std.testing.expectEqual(types.ActivePhase.idle, reauth.phase);
    try std.testing.expectEqual(Action.reauth_required, reauth.actions[0]);
}

fn testConfig() types.DirectSessionConfig {
    return .{
        .mode = .{ .sam = .{
            .session_parameter = .{ 1, 2, 3, 4 },
            .endpoint_parameter = .{ 5, 6, 7, 8, 9, 10 },
        } },
        .peer_mac = .{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb },
        .peer_ipv4 = .{ 192, 0, 2, 1 },
        .peer_udp_port = 5678,
        .local_udp_port = 1234,
        .session_id = 0x1122_3344,
        .des_key = .{ 0, 1, 2, 3, 4, 5, 6, 7 },
        .initial_iv = .{ 8, 9, 10, 11, 12, 13, 14, 15 },
        .timestamp = .{ .monotonic = 100 },
        .username_gbk = "alice",
        .network = .{
            .ipv4 = .{ 192, 0, 2, 10 },
            .netmask = .{ 255, 255, 255, 0 },
            .gateway = .{ 192, 0, 2, 1 },
            .dns = .{ 203, 0, 113, 53 },
            .mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        },
    };
}

fn testSmpConfig() types.DirectSessionConfig {
    var config = testConfig();
    config.mode = .{ .smp = .{
        .session_parameter = .{ 1, 2, 3, 4 },
    } };
    return config;
}

fn encodeAckForFrame(
    output: []u8,
    frame: wire.DecodedFrame,
    config: types.DirectSessionConfig,
) ![]u8 {
    const encoded = try wire.encodeFrame(.{
        .version = 1,
        .code = 2,
        .id = frame.header.id,
        .packet_len = wire.header_size,
        .authenticator = @splat(0),
        .session_id = frame.header.session_id,
        .timestamp = frame.header.timestamp,
        .message_type = 1,
        .flags = 0,
        .total_len = 0,
    }, &.{}, frame.destination, frame.source, output);
    try wire.setAuthenticator(encoded, config.des_key, config.initial_iv);
    return encoded;
}

fn encodeDataForTest(
    output: []u8,
    config: types.DirectSessionConfig,
    id: u32,
    flags: u8,
    total_len: u32,
    timestamp: u64,
    encrypted: []const u8,
) ![]u8 {
    const encoded = try wire.encodeFrame(.{
        .version = 1,
        .code = 1,
        .id = id,
        .packet_len = @intCast(wire.header_size + encrypted.len),
        .authenticator = @splat(0),
        .session_id = config.session_id,
        .timestamp = timestamp,
        .message_type = 1,
        .flags = flags,
        .total_len = total_len,
    }, encrypted, .{
        .mac = config.peer_mac,
        .ip = config.peer_ipv4,
        .port = config.peer_udp_port,
    }, .{
        .mac = config.network.mac,
        .ip = config.network.ipv4,
        .port = config.local_udp_port,
    }, output);
    try wire.setAuthenticator(encoded, config.des_key, config.initial_iv);
    return encoded;
}

fn sendDataForTest(
    machine: *Machine,
    config: types.DirectSessionConfig,
    id: u32,
    flags: u8,
    total_len: u32,
    timestamp: u64,
    encrypted: []const u8,
) !Outcome {
    return sendDataAtForTest(
        machine,
        config,
        id,
        flags,
        total_len,
        timestamp,
        encrypted,
        testTimestamp(0),
    );
}

fn sendDataAtForTest(
    machine: *Machine,
    config: types.DirectSessionConfig,
    id: u32,
    flags: u8,
    total_len: u32,
    timestamp: u64,
    encrypted: []const u8,
    now: std.Io.Timestamp,
) !Outcome {
    var frame_buffer: [4096]u8 = undefined;
    const frame = try encodeDataForTest(
        &frame_buffer,
        config,
        id,
        flags,
        total_len,
        timestamp,
        encrypted,
    );
    return machine.step(now, .{ .frame = .{
        .generation = machine.currentGeneration(),
        .bytes = frame,
    } });
}

fn enterAwaitingResult(
    machine: *Machine,
    config: types.DirectSessionConfig,
) !void {
    const encrypted = try std.testing.allocator.alloc(u8, 16);
    var initial = try machine.beginMessage(encrypted, .user_info, testTimestamp(0));
    const frame = try wire.decodeFrame(initial.actions[0].send_frame);
    var ack_buffer: [256]u8 = undefined;
    const ack = try encodeAckForFrame(&ack_buffer, frame, config);
    initial.deinit(std.testing.allocator);

    var awaiting = try machine.step(
        testTimestamp(0),
        .{ .frame = .{
            .generation = machine.currentGeneration(),
            .bytes = ack,
        } },
    );
    awaiting.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        types.ActivePhase{ .direct = .awaiting_result },
        machine.currentPhase(),
    );
}

fn enterActiveSam(
    machine: *Machine,
    config: types.DirectSessionConfig,
) !void {
    try enterAwaitingResult(machine, config);

    var payload: [16]u8 = @splat(0);
    payload[0..13].* = .{
        1,    1,   12,
        0x09, 8,   0x02,
        2,    'o', 'k',
        0x13, 1,   1,
        0,
    };
    var encrypted: [16]u8 = undefined;
    _ = try des.encryptCbc(config.des_key, config.initial_iv, &payload, &encrypted);
    var result = try sendDataAtForTest(
        machine,
        config,
        60,
        1,
        encrypted.len,
        100,
        &encrypted,
        testTimestamp(0),
    );
    result.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        types.ActivePhase{ .direct = .active },
        machine.currentPhase(),
    );
}

fn enterActiveSmp(
    machine: *Machine,
    config: types.DirectSessionConfig,
) !void {
    try enterAwaitingResult(machine, config);

    var payload: [16]u8 = @splat(0);
    payload[0..13].* = .{
        1,    0,    1,
        0x2e, 0xce, 0,
        1,    1,    0xcf,
        0,    2,    'o',
        'k',
    };
    var encrypted: [16]u8 = undefined;
    _ = try des.encryptCbc(config.des_key, config.initial_iv, &payload, &encrypted);
    var result = try sendDataAtForTest(
        machine,
        config,
        61,
        1,
        encrypted.len,
        100,
        &encrypted,
        testTimestamp(0),
    );
    result.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        types.ActivePhase{ .direct = .active },
        machine.currentPhase(),
    );
}

fn acknowledgeCurrentFrame(
    machine: *Machine,
    config: types.DirectSessionConfig,
    encoded: []const u8,
    now_seconds: i96,
) !void {
    const frame = try wire.decodeFrame(encoded);
    var ack_buffer: [256]u8 = undefined;
    const ack = try encodeAckForFrame(&ack_buffer, frame, config);
    var acknowledged = try machine.step(
        testTimestamp(now_seconds * std.time.ns_per_s),
        .{ .frame = .{
            .generation = machine.currentGeneration(),
            .bytes = ack,
        } },
    );
    acknowledged.deinit(std.testing.allocator);
}

fn testTimestamp(nanoseconds: i96) std.Io.Timestamp {
    return .fromNanoseconds(nanoseconds);
}
