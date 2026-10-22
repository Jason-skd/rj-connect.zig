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
    encrypted: []u8,
    total_len: usize,
    offset: usize,
    current_len: usize,
    current_flags: u8,
    current_id: u32,
    attempts: u8,
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
        if (self.outbound) |outbound| self.allocator.free(outbound.encrypted);
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
        return self.beginMessage(encrypted, now);
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
            .next_deadline = self.ack_deadline,
            .failure = null,
            .generation = self.generation,
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
            const actions = try self.allocator.alloc(Action, 0);
            errdefer self.allocator.free(actions);
            self.timestamps = timestamp_update.state;
            self.allocator.free(outbound.encrypted);
            self.outbound = null;
            self.ack_deadline = null;
            return .{
                .actions = actions,
                .previous_phase = .{ .direct = self.phase },
                .phase = .{ .direct = self.phase },
                .next_deadline = null,
                .failure = null,
                .generation = self.generation,
            };
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
            .next_deadline = self.ack_deadline,
            .failure = null,
            .generation = self.generation,
        };
    }

    fn handleTimer(self: *Machine, now: std.Io.Timestamp) Error!Outcome {
        const deadline = self.ack_deadline orelse return error.InvalidState;
        if (now.compare(.lt, deadline)) return error.TimerNotDue;
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
            .next_deadline = self.ack_deadline,
            .failure = null,
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
            id,
            fragment.flags,
            @intCast(encrypted.len),
            timestamp_update.timestamp,
            encrypted[fragment.offset..][0..fragment.len],
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

test "Direct fragments a message in strict flag order" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const encrypted = try std.testing.allocator.alloc(u8, 3008);
    @memset(encrypted, 0x5a);
    var outcome = try machine.beginMessage(encrypted, testTimestamp(0));

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
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), machine.nextDeadline());
}

test "Direct retransmits the same fragment until attempts are exhausted" {
    const config = testConfig();
    var machine = try Machine.init(std.testing.allocator, config, testTimestamp(0), .initial);
    defer machine.deinit();

    const encrypted = try std.testing.allocator.alloc(u8, 100);
    @memset(encrypted, 0x33);
    var initial = try machine.beginMessage(encrypted, testTimestamp(0));
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

fn testTimestamp(nanoseconds: i96) std.Io.Timestamp {
    return .fromNanoseconds(nanoseconds);
}
