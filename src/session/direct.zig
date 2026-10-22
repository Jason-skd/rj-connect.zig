//! Direct SAM/SMP protocol machine.

const std = @import("std");
const des = @import("../protocol/des.zig");
const wire = @import("../protocol/direct.zig");
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

const Pending = struct {
    id: u32,
    encrypted: []u8,
    flags: u8,
    total_len: u32,
};

pub const Machine = struct {
    allocator: std.mem.Allocator,
    config: types.DirectSessionConfig,
    phase: types.DirectPhase = .initializing,
    generation: types.Generation,
    timestamps: TimestampState,
    next_message_id: u32,
    pending: ?Pending = null,
    ack_deadline: ?std.Io.Timestamp = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config: types.DirectSessionConfig,
        now: std.Io.Timestamp,
        generation: types.Generation,
    ) Error!Machine {
        try config.validate();
        if (config.mode != .sam) return error.InvalidConfig;

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
        };
    }

    pub fn deinit(self: *Machine) void {
        self.allocator.free(self.config.username_gbk);
        if (self.pending) |pending| self.allocator.free(pending.encrypted);
        self.* = undefined;
    }

    pub fn currentPhase(self: *const Machine) types.ActivePhase {
        return .{ .direct = self.phase };
    }

    pub fn currentGeneration(self: *const Machine) types.Generation {
        return self.generation;
    }

    pub fn nextDeadline(self: *const Machine) ?std.Io.Timestamp {
        return self.ack_deadline;
    }

    pub fn start(self: *Machine, now: std.Io.Timestamp) Error!Outcome {
        const payload = try makeSamHandshake(self.allocator, self.config);
        defer self.allocator.free(payload);

        const encrypted = try encryptPayload(
            self.allocator,
            self.config.des_key,
            self.config.initial_iv,
            payload,
        );
        errdefer self.allocator.free(encrypted);

        const timestamp = try self.nextSendTimestamp(now);
        const id = self.next_message_id;
        const frame = try self.makeFrame(
            id,
            1,
            @intCast(encrypted.len),
            timestamp,
            encrypted,
        );
        var builder = OutcomeBuilder.init(self.allocator);
        errdefer builder.deinit();
        try builder.addFrame(frame);
        const actions = try builder.finish();

        self.pending = .{
            .id = id,
            .encrypted = encrypted,
            .flags = 1,
            .total_len = @intCast(encrypted.len),
        };
        self.ack_deadline = try time.addDuration(now, self.config.ack_timeout);
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = .initializing },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.ack_deadline,
            .failure = null,
            .generation = self.generation,
        };
    }

    pub fn step(self: *Machine, now: std.Io.Timestamp, input: Input) Error!Outcome {
        return switch (input) {
            .frame => |event| self.handleFrame(now, event.bytes),
            else => error.InvalidState,
        };
    }

    fn handleFrame(
        self: *Machine,
        now: std.Io.Timestamp,
        bytes: []const u8,
    ) Error!Outcome {
        const frame = wire.decodeFrame(bytes) catch return self.noop();
        if (frame.header.code != 2 or
            frame.header.packet_len != wire.header_size or
            frame.header.total_len != 0 or
            frame.header.session_id != self.config.session_id or
            !std.mem.eql(u8, &frame.source.mac, &self.config.peer_mac) or
            !std.mem.eql(u8, &frame.destination.mac, &self.config.network.mac) or
            frame.source.port != self.config.peer_udp_port or
            frame.destination.port != self.config.local_udp_port or
            !std.mem.eql(u8, &frame.source.ip, &self.config.peer_ipv4) or
            !std.mem.eql(u8, &frame.destination.ip, &self.config.network.ipv4))
        {
            return self.noop();
        }

        const pending = self.pending orelse return self.noop();
        if (pending.id != frame.header.id) return self.noop();

        const packet = bytes[wire.ethernet_header_size + wire.ipv4_header_size + wire.udp_header_size ..];
        const valid_authenticator = wire.verifyAuthenticator(
            packet,
            self.config.des_key,
            self.config.initial_iv,
        ) catch false;
        if (!valid_authenticator or !try self.acceptTimestamp(now, frame.header.timestamp)) {
            return self.noop();
        }

        const actions = try self.allocator.alloc(Action, 0);
        errdefer self.allocator.free(actions);
        self.allocator.free(pending.encrypted);
        self.pending = null;
        self.ack_deadline = null;
        self.next_message_id +%= 1;
        return .{
            .actions = actions,
            .previous_phase = .{ .direct = self.phase },
            .phase = .{ .direct = self.phase },
            .next_deadline = null,
            .failure = null,
            .generation = self.generation,
        };
    }

    fn noop(self: *const Machine) Error!Outcome {
        return .{
            .actions = try self.allocator.alloc(Action, 0),
            .previous_phase = .{ .direct = self.phase },
            .phase = .{ .direct = self.phase },
            .next_deadline = self.ack_deadline,
            .failure = null,
            .generation = self.generation,
        };
    }

    fn makeFrame(
        self: *Machine,
        id: u32,
        flags: u8,
        total_len: u32,
        timestamp: u64,
        encrypted: []const u8,
    ) Error![]u8 {
        const frame_len = wire.ethernet_header_size + wire.ipv4_header_size +
            wire.udp_header_size + wire.header_size + encrypted.len;
        const frame = try self.allocator.alloc(u8, frame_len);
        errdefer self.allocator.free(frame);

        _ = wire.encodeFrame(.{
            .version = 1,
            .code = 1,
            .id = id,
            .packet_len = @intCast(wire.header_size + encrypted.len),
            .authenticator = @splat(0),
            .session_id = self.config.session_id,
            .timestamp = timestamp,
            .message_type = 1,
            .flags = flags,
            .total_len = total_len,
        }, encrypted, .{
            .mac = self.config.network.mac,
            .ip = self.config.network.ipv4,
            .port = self.config.local_udp_port,
        }, .{
            .mac = self.config.peer_mac,
            .ip = self.config.peer_ipv4,
            .port = self.config.peer_udp_port,
        }, frame) catch return error.InvalidConfig;

        wire.setAuthenticator(
            frame,
            self.config.des_key,
            self.config.initial_iv,
        ) catch return error.InvalidConfig;
        return frame;
    }

    fn nextSendTimestamp(self: *Machine, now: std.Io.Timestamp) Error!u64 {
        return switch (self.timestamps) {
            .server => |*state| blk: {
                const elapsed = now.nanoseconds - state.local_anchor.nanoseconds;
                if (elapsed < 0) return error.TimeWentBackwards;
                const seconds: u64 = @intCast(@divFloor(elapsed, std.time.ns_per_s));
                break :blk std.math.add(u64, state.server_anchor, seconds) catch
                    return error.TimestampOverflow;
            },
            .monotonic => |*state| blk: {
                const result = state.next_send;
                state.next_send = std.math.add(u64, state.next_send, 1) catch
                    return error.TimestampOverflow;
                break :blk result;
            },
        };
    }

    fn acceptTimestamp(self: *Machine, now: std.Io.Timestamp, received: u64) Error!bool {
        return switch (self.timestamps) {
            .server => |*state| blk: {
                const elapsed = now.nanoseconds - state.local_anchor.nanoseconds;
                if (elapsed < 0) return error.TimeWentBackwards;
                const seconds: u64 = @intCast(@divFloor(elapsed, std.time.ns_per_s));
                const expected = std.math.add(u64, state.server_anchor, seconds) catch
                    return error.TimestampOverflow;
                const distance = if (received >= expected) received - expected else expected - received;
                if (distance >= 61) break :blk false;
                state.received = received;
                break :blk true;
            },
            .monotonic => |*state| blk: {
                if (received > state.received) {
                    state.received = received;
                    state.non_advancing = 0;
                    break :blk true;
                }
                if (state.non_advancing >= 5) break :blk false;
                state.non_advancing += 1;
                break :blk true;
            },
        };
    }
};

fn makeSamHandshake(
    allocator: std.mem.Allocator,
    config: types.DirectSessionConfig,
) Error![]u8 {
    const sam = switch (config.mode) {
        .sam => |value| value,
    };
    const payload_len = 3 + 2 + config.username_gbk.len + 2 + sam.session_parameter.len +
        2 + sam.endpoint_parameter.len;
    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);

    var index: usize = 0;
    payload[index..][0..3].* = .{ 0x01, 0x01, 0x02 };
    index += 3;
    payload[index] = 0x03;
    payload[index + 1] = @intCast(config.username_gbk.len);
    index += 2;
    @memcpy(payload[index..][0..config.username_gbk.len], config.username_gbk);
    index += config.username_gbk.len;
    payload[index] = 0x04;
    payload[index + 1] = sam.session_parameter.len;
    index += 2;
    @memcpy(payload[index..][0..sam.session_parameter.len], &sam.session_parameter);
    index += sam.session_parameter.len;
    payload[index] = 0x05;
    payload[index + 1] = sam.endpoint_parameter.len;
    index += 2;
    @memcpy(payload[index..][0..sam.endpoint_parameter.len], &sam.endpoint_parameter);
    return payload;
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
