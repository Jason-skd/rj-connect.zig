//! Deterministic PEAPv0 orchestration with caller-owned TLS and MSCHAPv2.

const std = @import("std");
const eap = @import("../protocol/eap.zig");
const eapol = @import("../protocol/eapol.zig");
const peap = @import("../protocol/peap.zig");
const ruijie = @import("../protocol/ruijie_peap.zig");
const v3 = @import("../protocol/v3.zig");
const session_outcome = @import("outcome.zig");
const time = @import("time.zig");
const types = @import("types.zig");

const Action = session_outcome.Action;
const Error = types.Error;
const FailureReason = types.FailureReason;
const Input = types.Input;
const Outcome = session_outcome.Outcome;
const OutcomeBuilder = session_outcome.OutcomeBuilder;

pub const Handoff = struct {
    peer_mac: [6]u8,
    identifier: u8,
};

const State = enum {
    idle,
    handshake,
    awaiting_identity,
    awaiting_mschapv2,
    verifying_mschapv2_success,
    protecting,
    awaiting_inner,
    awaiting_outer_success,
    waiting_dhcp,
};

const ProtectStage = enum {
    identity,
    mschapv2,
    mschapv2_success,
};

pub const Machine = struct {
    allocator: std.mem.Allocator,
    config: types.PeapConfig,
    source_mac: [6]u8,
    peer_mac: [6]u8,
    generation: types.Generation,
    outer_identifier: u8,
    inner_identifier: ?u8 = null,
    last_outer_response_identifier: ?u8 = null,
    state: State = .handshake,
    protect_stage: ?ProtectStage = null,
    tls_established: bool = false,
    inner_success: bool = false,
    tls_buffer: ?[]u8 = null,
    tls_expected_length: ?usize = null,
    auth_timeout: std.Io.Duration,
    deadline: std.Io.Timestamp,
    dhcp_poll_attempts: u8 = 0,
    failure_reason: ?FailureReason = null,
    server_info: ruijie.ServerInfo = .{},
    username_gbk: ?[]u8 = null,
    direct_ready: ?types.DirectSessionConfig = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config: types.PeapConfig,
        handoff: Handoff,
        source_mac: [6]u8,
        now: std.Io.Timestamp,
        generation: types.Generation,
        auth_timeout: std.Io.Duration,
    ) Error!Machine {
        try config.validate();
        return .{
            .allocator = allocator,
            .config = config,
            .source_mac = source_mac,
            .peer_mac = handoff.peer_mac,
            .generation = generation,
            .outer_identifier = handoff.identifier,
            .auth_timeout = auth_timeout,
            .deadline = try time.addDuration(now, auth_timeout),
        };
    }

    pub fn deinit(self: *Machine) void {
        if (self.tls_buffer) |buffer| self.allocator.free(buffer);
        if (self.username_gbk) |username| self.allocator.free(username);
        self.tls_buffer = null;
        self.username_gbk = null;
    }

    pub fn currentPhase(self: *const Machine) types.ActivePhase {
        return .{ .peap = switch (self.state) {
            .idle => return .idle,
            .waiting_dhcp => .waiting_dhcp,
            .handshake => .handshake,
            .awaiting_identity,
            .awaiting_mschapv2,
            .verifying_mschapv2_success,
            .protecting,
            .awaiting_inner,
            .awaiting_outer_success,
            => .authenticating,
        } };
    }

    pub fn currentGeneration(self: *const Machine) types.Generation {
        return self.generation;
    }

    pub fn nextDeadline(self: *const Machine) ?std.Io.Timestamp {
        return if (self.state == .idle) null else self.deadline;
    }

    pub fn isWaitingDhcp(self: *const Machine) bool {
        return self.state == .waiting_dhcp;
    }

    pub fn readyDirectConfig(self: *const Machine) ?types.DirectSessionConfig {
        return self.direct_ready;
    }

    pub fn clearReadyDirect(self: *Machine) void {
        self.direct_ready = null;
    }

    pub fn step(self: *Machine, now: std.Io.Timestamp, input: Input) Error!Outcome {
        var next = self.*;
        const old_tls = self.tls_buffer;
        const old_username = self.username_gbk;
        var replacement_tls: ?[]u8 = null;
        var builder = OutcomeBuilder.init(self.allocator);
        errdefer builder.deinit();
        errdefer if (replacement_tls) |buffer| self.allocator.free(buffer);
        errdefer if (next.username_gbk != null and
            (old_username == null or next.username_gbk.?.ptr != old_username.?.ptr))
        {
            self.allocator.free(next.username_gbk.?);
        };

        const previous_phase = self.currentPhase();
        switch (input) {
            .frame => |event| {
                if (!event.generation.eql(self.generation)) return error.StaleGeneration;
                try next.handleFrame(now, event.bytes, &builder, &replacement_tls);
            },
            .credentials => |credentials| try next.handleCredentials(now, credentials, &builder),
            .tunnel_output => |event| {
                if (!event.generation.eql(self.generation)) return error.StaleGeneration;
                try next.handleTunnelOutput(now, event.output, &builder);
            },
            .external_result => |event| {
                if (!event.generation.eql(self.generation)) return error.StaleGeneration;
                try next.handleExternalResult(now, event.result, &builder);
            },
            .timer => |generation| {
                if (!generation.eql(self.generation)) return error.StaleGeneration;
                try next.handleTimer(now, &builder);
            },
            .cancel => try next.handleCancel(&builder),
            else => return error.InvalidState,
        }

        const actions = try builder.finish();
        self.* = next;
        if (old_tls) |buffer| {
            if (self.tls_buffer == null or self.tls_buffer.?.ptr != buffer.ptr) {
                self.allocator.free(buffer);
            }
        }
        if (old_username) |username| {
            if (self.username_gbk == null or self.username_gbk.?.ptr != username.ptr) {
                self.allocator.free(username);
            }
        }
        return .{
            .actions = actions,
            .previous_phase = previous_phase,
            .phase = self.currentPhase(),
            .next_deadline = self.nextDeadline(),
            .failure = self.failure_reason,
            .generation = self.generation,
        };
    }

    fn handleFrame(
        self: *Machine,
        now: std.Io.Timestamp,
        bytes: []const u8,
        builder: *OutcomeBuilder,
        replacement_tls: *?[]u8,
    ) Error!void {
        const frame = eapol.decode(bytes) catch return error.InvalidFrame;
        if (frame.packet_type == .logoff) {
            try self.finish(.server_logoff);
            return;
        }
        if (frame.packet_type != .eap) return error.InvalidFrame;
        const packet = frame.eap orelse return error.InvalidFrame;
        switch (packet.code) {
            .request => {
                if (packet.type != .peap) return error.InvalidFrame;
                if (packet.identifier != self.outer_identifier and
                    packet.identifier != self.outer_identifier +% 1)
                {
                    return error.StaleIdentifier;
                }
                self.outer_identifier = packet.identifier;
                try self.handlePeapRequest(now, packet.data, builder, replacement_tls);
            },
            .success => {
                if (self.last_outer_response_identifier == null or
                    self.last_outer_response_identifier.? != packet.identifier or
                    !self.inner_success or !self.tls_established)
                {
                    return error.InvalidFrame;
                }
                self.state = .waiting_dhcp;
                self.deadline = try time.addDuration(now, .fromSeconds(2));
                self.dhcp_poll_attempts = 1;
                try builder.addAction(.poll_dhcp);
            },
            .failure => try self.finish(.server_failure),
            else => return error.InvalidFrame,
        }
    }

    fn handlePeapRequest(
        self: *Machine,
        now: std.Io.Timestamp,
        payload: []const u8,
        builder: *OutcomeBuilder,
        replacement_tls: *?[]u8,
    ) Error!void {
        const decoded = peap.decode(payload) catch return error.InvalidFrame;
        self.deadline = try time.addDuration(now, self.auth_timeout);
        if (decoded.flags.start) self.tls_buffer = null;
        if (decoded.tls_message_length) |expected| {
            if (expected > 64 * 1024) return error.InvalidTunnelInput;
            self.tls_expected_length = expected;
        }

        const current_len = if (self.tls_buffer) |buffer| buffer.len else 0;
        const total_len = std.math.add(usize, current_len, decoded.tls.len) catch
            return error.InvalidTunnelInput;
        if (total_len > 64 * 1024) return error.InvalidTunnelInput;
        if (self.tls_expected_length) |expected| {
            if (total_len > expected) return error.InvalidTunnelInput;
        }

        const combined = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(combined);
        if (self.tls_buffer) |buffer| @memcpy(combined[0..buffer.len], buffer);
        @memcpy(combined[current_len..], decoded.tls);

        const complete = !decoded.flags.more and
            (self.tls_expected_length == null or total_len == self.tls_expected_length.?);
        if (!complete) {
            replacement_tls.* = combined;
            self.tls_buffer = combined;
            return;
        }

        self.tls_buffer = null;
        self.tls_expected_length = null;
        try builder.addAction(.{ .tunnel_input = .{
            .operation = .process_server_tls,
            .bytes = combined,
        } });
    }

    fn handleTunnelOutput(
        self: *Machine,
        now: std.Io.Timestamp,
        output: types.TunnelOutput,
        builder: *OutcomeBuilder,
    ) Error!void {
        if (output.version != 0 or output.cryptobinding) return error.UnsupportedPeapMode;
        if (output.status == .failed) {
            try self.finish(.tls_failed);
            return;
        }
        if (output.status == .established) self.tls_established = true;

        try self.addOutboundTunnelFrames(output.outbound_tls, builder);
        if (output.plaintext.len != 0) {
            try self.handlePlaintext(now, output.plaintext, builder);
            if (self.state == .protecting) self.advanceProtectedStage();
        } else if (self.state == .protecting) {
            self.advanceProtectedStage();
        }
        if (self.state != .idle and self.state != .waiting_dhcp) {
            self.deadline = try time.addDuration(now, self.auth_timeout);
        }
    }

    fn addOutboundTunnelFrames(
        self: *Machine,
        tls_bytes: []const u8,
        builder: *OutcomeBuilder,
    ) Error!void {
        if (tls_bytes.len == 0) return;
        var offset: usize = 0;
        while (offset < tls_bytes.len) {
            const chunk_len = @min(self.config.tls_fragment_size, tls_bytes.len - offset);
            const more = offset + chunk_len < tls_bytes.len;
            var payload: [types.max_tls_fragment_size + 5]u8 = undefined;
            const encoded_peap = peap.encode(.{
                .more = more,
                .length_included = offset == 0,
            }, if (offset == 0) @intCast(tls_bytes.len) else null, tls_bytes[offset..][0..chunk_len], &payload) catch
                return error.InvalidTunnelInput;
            const frame_len = eapol.header_size + 5 + encoded_peap.len;
            const frame = try self.allocator.alloc(u8, frame_len);
            errdefer self.allocator.free(frame);
            _ = eapol.encodeEap(
                self.peer_mac,
                self.source_mac,
                .response,
                self.outer_identifier,
                .peap,
                encoded_peap,
                frame,
            ) catch return error.InvalidTunnelInput;
            try builder.addFrame(frame);
            self.last_outer_response_identifier = self.outer_identifier;
            offset += chunk_len;
        }
    }

    fn handlePlaintext(
        self: *Machine,
        now: std.Io.Timestamp,
        plaintext: []const u8,
        builder: *OutcomeBuilder,
    ) Error!void {
        const packet = eap.decodePrefix(plaintext) catch {
            const parsed = ruijie.parseServerInfo(plaintext) catch
                return error.InvalidTunnelInput;
            self.server_info = ruijie.mergeServerInfo(self.server_info, parsed);
            return;
        };
        if (packet.encoded_len < plaintext.len) {
            const parsed = ruijie.parseServerInfo(plaintext[packet.encoded_len..]) catch
                return error.InvalidTunnelInput;
            self.server_info = ruijie.mergeServerInfo(self.server_info, parsed);
        }
        if (packet.code == .success) {
            self.inner_success = true;
            self.state = .awaiting_outer_success;
            self.deadline = try time.addDuration(now, self.auth_timeout);
            return;
        }
        if (packet.code == .failure) {
            try self.finish(.mschapv2_failed);
            return;
        }
        if (packet.code != .request) return error.InvalidTunnelInput;
        if (self.inner_identifier) |current| {
            if (packet.identifier != current +% 1) return error.StaleIdentifier;
        }
        self.inner_identifier = packet.identifier;
        switch (packet.type orelse return error.InvalidTunnelInput) {
            .identity => {
                self.state = .awaiting_identity;
                self.deadline = try time.addDuration(now, self.auth_timeout);
                try builder.addAction(.{ .request_credentials = .peap_identity });
            },
            .mschapv2 => {
                if (packet.data.len == 0) return error.InvalidTunnelInput;
                const request = try self.allocator.dupe(u8, packet.data);
                errdefer self.allocator.free(request);
                switch (packet.data[0]) {
                    1 => {
                        try builder.addAction(.{ .authenticate_mschapv2 = .{
                            .identifier = packet.identifier,
                            .request_data = request,
                        } });
                        self.state = .awaiting_mschapv2;
                    },
                    3 => {
                        try builder.addAction(.{ .verify_mschapv2 = .{
                            .identifier = packet.identifier,
                            .request_data = request,
                        } });
                        self.state = .verifying_mschapv2_success;
                    },
                    else => return error.InvalidTunnelInput,
                }
                self.deadline = try time.addDuration(now, self.auth_timeout);
            },
            else => return error.InvalidTunnelInput,
        }
    }

    fn handleCredentials(
        self: *Machine,
        now: std.Io.Timestamp,
        credentials: types.Credentials,
        builder: *OutcomeBuilder,
    ) Error!void {
        if (self.state != .awaiting_identity) return error.InvalidState;
        if (credentials.username.len == 0 or credentials.username.len > 255) {
            return error.InvalidCredentials;
        }
        try self.captureUsername(credentials.username);
        const identifier = self.inner_identifier orelse return error.InvalidState;
        const packet = try encodeInner(
            self.allocator,
            identifier,
            .identity,
            credentials.username,
        );
        errdefer self.allocator.free(packet);
        try builder.addAction(.{ .tunnel_input = .{
            .operation = .protect_inner_eap,
            .bytes = packet,
        } });
        self.state = .protecting;
        self.protect_stage = .identity;
        self.deadline = try time.addDuration(now, self.auth_timeout);
    }

    fn handleExternalResult(
        self: *Machine,
        now: std.Io.Timestamp,
        result: types.ExternalResult,
        builder: *OutcomeBuilder,
    ) Error!void {
        switch (result) {
            .mschapv2_response => |response| {
                if (self.state != .awaiting_mschapv2) return error.InvalidState;
                try self.protectMschapv2Response(now, response, builder);
            },
            .mschapv2_success => |success| {
                if (self.state != .verifying_mschapv2_success) return error.InvalidState;
                if (!success.verified) {
                    try self.finish(.mschapv2_failed);
                    return;
                }
                const identifier = self.inner_identifier orelse return error.InvalidState;
                const packet = try encodeInner(
                    self.allocator,
                    identifier,
                    .mschapv2,
                    success.response_data,
                );
                errdefer self.allocator.free(packet);
                try builder.addAction(.{ .tunnel_input = .{
                    .operation = .protect_inner_eap,
                    .bytes = packet,
                } });
                self.inner_success = true;
                self.state = .protecting;
                self.protect_stage = .mschapv2_success;
                self.deadline = try time.addDuration(now, self.auth_timeout);
            },
            .dhcp_lease => |lease| {
                if (self.state != .waiting_dhcp) return error.InvalidState;
                self.direct_ready = try self.makeDirectConfig(lease);
            },
        }
    }

    fn protectMschapv2Response(
        self: *Machine,
        now: std.Io.Timestamp,
        response: types.Mschapv2Response,
        builder: *OutcomeBuilder,
    ) Error!void {
        const identifier = self.inner_identifier orelse return error.InvalidState;
        if (response.credentials.username.len == 0 or response.credentials.username.len > 255) {
            return error.InvalidCredentials;
        }
        try self.captureUsername(response.credentials.username);
        var digest: [128]u8 = undefined;
        _ = v3.digest(
            self.config.v3_application_data,
            self.config.v3_dll_data,
            ruijie.password_start,
            &digest,
        ) catch return error.InvalidTunnelInput;

        const network = self.config.network;
        const fields: ruijie.ClientFields = .{
            .program_name_gbk = self.config.program_name_gbk,
            .client_version = self.config.client_version,
            .ipv4 = if (network) |value| value.ipv4 else null,
            .netmask = if (network) |value| value.netmask else null,
            .gateway = if (network) |value| value.gateway else null,
            .dns = if (network) |value| value.dns else null,
            .dhcp_enabled = network != null,
            .source_mac = self.source_mac,
            .ipv6_aux_state = self.config.ipv6_aux_state,
            .ipv6_addresses = self.config.ipv6_addresses,
            .service_name_gbk = self.config.service_name_gbk,
            .alternate_dns = self.config.alternate_dns_text,
            .username_gbk = response.credentials.username,
            .password_gbk = response.credentials.password,
            .v3_digest = digest,
            .disk_serial_ascii = self.config.disk_serial_ascii,
            .security_domain_ascii = self.config.security_domain_ascii,
            .security_check_ok = self.config.security_check_ok,
            .ipd_result = self.config.ipd_result,
            .direct_max_version = self.config.direct_max_version,
        };
        const compact_len = ruijie.encodedSize(fields) catch return error.InvalidTunnelInput;
        const inner_data_len = std.math.add(usize, response.response_data.len, compact_len) catch
            return error.InvalidTunnelInput;
        const packet_len = eap.encodedSize(inner_data_len, true) catch
            return error.InvalidTunnelInput;
        const packet = try self.allocator.alloc(u8, packet_len);
        errdefer self.allocator.free(packet);
        const inner_data = try self.allocator.alloc(u8, inner_data_len);
        defer self.allocator.free(inner_data);
        @memcpy(inner_data[0..response.response_data.len], response.response_data);
        _ = ruijie.buildClientFields(fields, inner_data[response.response_data.len..]) catch
            return error.InvalidTunnelInput;
        _ = eap.encode(.response, identifier, .mschapv2, inner_data, packet) catch
            return error.InvalidTunnelInput;
        try builder.addAction(.{ .tunnel_input = .{
            .operation = .protect_inner_eap,
            .bytes = packet,
        } });
        self.state = .protecting;
        self.protect_stage = .mschapv2;
        self.deadline = try time.addDuration(now, self.auth_timeout);
    }

    fn handleTimer(self: *Machine, now: std.Io.Timestamp, builder: *OutcomeBuilder) Error!void {
        if (now.compare(.lt, self.deadline)) return error.TimerNotDue;
        if (self.state == .waiting_dhcp) {
            if (self.dhcp_poll_attempts >= 21) {
                try self.finish(.dhcp_timeout);
                return;
            }
            self.dhcp_poll_attempts += 1;
            self.deadline = try time.addDuration(now, .fromSeconds(2));
            try builder.addAction(.poll_dhcp);
            return;
        }
        try self.finish(.auth_timeout);
    }

    fn handleCancel(self: *Machine, builder: *OutcomeBuilder) Error!void {
        try self.addLogoff(builder);
        try self.finish(.canceled);
    }

    fn addLogoff(self: *Machine, builder: *OutcomeBuilder) Error!void {
        const frame = try self.allocator.alloc(u8, eapol.header_size);
        errdefer self.allocator.free(frame);
        eapol.encodeLogoff(self.peer_mac, self.source_mac, frame[0..eapol.header_size]);
        try builder.addFrame(frame);
    }

    fn advanceProtectedStage(self: *Machine) void {
        self.state = switch (self.protect_stage orelse .identity) {
            .identity, .mschapv2 => .awaiting_inner,
            .mschapv2_success => .awaiting_outer_success,
        };
        self.protect_stage = null;
    }

    fn captureUsername(self: *Machine, username: []const u8) Error!void {
        if (self.username_gbk) |existing| {
            if (std.mem.eql(u8, existing, username)) return;
            return error.InvalidCredentials;
        }
        self.username_gbk = try self.allocator.dupe(u8, username);
    }

    fn makeDirectConfig(self: *Machine, lease: types.DhcpLease) Error!?types.DirectSessionConfig {
        const ip = lease.ip orelse return null;
        const netmask = lease.netmask orelse return null;
        const gateway = lease.gateway orelse return null;
        const dns = lease.dns orelse return null;
        const peer_ipv4 = self.server_info.direct_ipv4 orelse
            return error.MissingDirectParameters;
        const peer_udp_port = self.server_info.direct_udp_port orelse
            return error.MissingDirectParameters;
        const des_key = self.server_info.des_key orelse return error.MissingDirectParameters;
        const initial_iv = self.server_info.initial_iv orelse return error.MissingDirectParameters;
        const session_id = self.config.direct_session_id orelse
            return error.MissingDirectParameters;
        const username = self.username_gbk orelse return error.MissingDirectParameters;
        const timestamp = if (self.server_info.server_utc) |server_time|
            types.DirectTimestampMode{ .server = server_time }
        else
            self.config.direct_timestamp orelse return error.MissingDirectParameters;
        const mode: types.DirectMode = switch (self.server_info.radius_type orelse
            return error.MissingDirectParameters) {
            .sam => .{ .sam = self.config.sam orelse return error.MissingDirectParameters },
            .smp => .{ .smp = self.config.smp orelse return error.MissingDirectParameters },
        };

        const config: types.DirectSessionConfig = .{
            .mode = mode,
            .peer_mac = self.peer_mac,
            .peer_ipv4 = peer_ipv4,
            .peer_udp_port = peer_udp_port,
            .local_udp_port = self.server_info.local_udp_port orelse self.config.local_udp_port,
            .session_id = session_id,
            .des_key = des_key,
            .initial_iv = initial_iv,
            .timestamp = timestamp,
            .username_gbk = username,
            .network = .{
                .ipv4 = ip,
                .netmask = netmask,
                .gateway = gateway,
                .dns = dns,
                .alternate_dns = lease.alternate_dns,
                .mac = self.source_mac,
            },
            .heartbeat_interval = seconds(self.server_info.heartbeat_interval_seconds),
            .reauth_interval = seconds(self.server_info.reauth_interval_seconds),
        };
        try config.validate();
        return config;
    }

    fn finish(self: *Machine, reason: FailureReason) Error!void {
        self.state = .idle;
        self.deadline = .fromNanoseconds(0);
        self.failure_reason = reason;
        self.tls_expected_length = null;
    }
};

fn seconds(value: ?u32) std.Io.Duration {
    return .fromSeconds(if (value) |seconds_value| @intCast(seconds_value) else 0);
}

fn encodeInner(
    allocator: std.mem.Allocator,
    identifier: u8,
    eap_type: eap.Type,
    data: []const u8,
) Error![]u8 {
    const packet_len = eap.encodedSize(data.len, true) catch return error.InvalidInput;
    const packet = try allocator.alloc(u8, packet_len);
    errdefer allocator.free(packet);
    _ = eap.encode(.response, identifier, eap_type, data, packet) catch
        return error.InvalidTunnelInput;
    return packet;
}
