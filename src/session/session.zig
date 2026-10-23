//! Public deterministic session coordinator.

const std = @import("std");
const eapol = @import("../protocol/eapol.zig");
const context = @import("context.zig");
const direct_machine = @import("direct.zig");
const eap_md5 = @import("eap_md5.zig");
const peap_machine = @import("peap.zig");
const session_outcome = @import("outcome.zig");
const types = @import("types.zig");

pub const Generation = types.Generation;
pub const EapMd5Phase = types.EapMd5Phase;
pub const PeapPhase = types.PeapPhase;
pub const ActivePhase = types.ActivePhase;
pub const DirectPhase = types.DirectPhase;
pub const Config = types.Config;
pub const EapMethods = types.EapMethods;
pub const PeapConfig = types.PeapConfig;
pub const CredentialPurpose = types.CredentialPurpose;
pub const FailureReason = types.FailureReason;
pub const DhcpStep = types.DhcpStep;
pub const Credentials = types.Credentials;
pub const DhcpLease = types.DhcpLease;
pub const ExternalResult = types.ExternalResult;
pub const ExternalResultInput = types.ExternalResultInput;
pub const FrameInput = types.FrameInput;
pub const DirectNetworkInfo = types.DirectNetworkInfo;
pub const DirectTimestampMode = types.DirectTimestampMode;
pub const SamConfig = types.SamConfig;
pub const SmpConfig = types.SmpConfig;
pub const DirectMode = types.DirectMode;
pub const DirectSessionConfig = types.DirectSessionConfig;
pub const DirectAuthResult = types.DirectAuthResult;
pub const Input = types.Input;
pub const Action = session_outcome.Action;
pub const Outcome = session_outcome.Outcome;
pub const Error = types.Error;

pub const Session = struct {
    allocator: std.mem.Allocator,
    config: Config,
    context: context.Context,
    failure_reason: ?FailureReason,
    eap_peer_mac: ?[6]u8,
    peap_config: ?PeapConfig,
    machine: Machine,

    const Machine = union(enum) {
        empty,
        eap_md5: eap_md5.Engine,
        peap: peap_machine.Machine,
        direct: direct_machine.Machine,

        fn deinit(self: *Machine) void {
            switch (self.*) {
                .empty => {},
                .eap_md5 => |*engine| engine.deinit(),
                .peap => |*engine| engine.deinit(),
                .direct => |*engine| engine.deinit(),
            }
            self.* = .empty;
        }
    };

    /// Creates an idle session. No machine or frame is allocated until `step` starts one.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Session {
        try config.validate();
        var owned_peap: ?PeapConfig = null;
        if (config.peap) |peap_config| {
            owned_peap = try clonePeapConfig(allocator, peap_config);
        }
        errdefer if (owned_peap) |*peap_config| freePeapConfig(allocator, peap_config);

        var owned_config = config;
        owned_config.peap = null;
        return .{
            .allocator = allocator,
            .config = owned_config,
            .context = .{},
            .failure_reason = null,
            .eap_peer_mac = null,
            .peap_config = owned_peap,
            .machine = .empty,
        };
    }

    pub fn deinit(self: *Session) void {
        self.machine.deinit();
        if (self.peap_config) |*config| freePeapConfig(self.allocator, config);
        self.peap_config = null;
    }

    pub fn phase(self: *const Session) ActivePhase {
        return switch (self.machine) {
            .empty => .idle,
            .eap_md5 => |*engine| engine.phase(),
            .peap => |*engine| engine.currentPhase(),
            .direct => |*engine| engine.currentPhase(),
        };
    }

    pub fn nextDeadline(self: *const Session) ?std.Io.Timestamp {
        return switch (self.machine) {
            .empty => null,
            .eap_md5 => |*engine| engine.nextDeadline(),
            .peap => |*engine| engine.nextDeadline(),
            .direct => |*engine| engine.nextDeadline(),
        };
    }

    pub fn failure(self: *const Session) ?FailureReason {
        return self.failure_reason;
    }

    pub fn dhcpStep(self: *const Session) DhcpStep {
        return switch (self.machine) {
            .empty => .none,
            .eap_md5 => |*engine| engine.dhcpStep(),
            .peap => |*engine| if (engine.phase == .waiting_dhcp) .first else .none,
            .direct => .none,
        };
    }

    pub fn dhcpPollAttempts(self: *const Session) u8 {
        return switch (self.machine) {
            .empty => 0,
            .eap_md5 => |*engine| engine.dhcpPollAttempts(),
            .peap => 0,
            .direct => 0,
        };
    }

    /// Returns the token required by asynchronous inputs to the current session.
    pub fn currentGeneration(self: *const Session) Generation {
        return self.context.generation;
    }

    /// Accepts one external event and commits state only after every returned action is allocated.
    pub fn step(self: *Session, now: std.Io.Timestamp, input: Input) Error!Outcome {
        if (self.context.last_now) |last_now| {
            if (now.compare(.lt, last_now)) return error.TimeWentBackwards;
        }

        return switch (input) {
            .start => self.start(now),
            .cancel => self.cancel(now),
            .direct_session => |config| self.startDirect(now, config),
            else => self.stepActive(now, input),
        };
    }

    fn start(self: *Session, now: std.Io.Timestamp) Error!Outcome {
        switch (self.machine) {
            .empty => {},
            else => return error.InvalidState,
        }

        var candidate = try eap_md5.Engine.initWithState(
            self.allocator,
            self.config,
            self.context.generation,
            self.context.last_now,
        );
        errdefer candidate.deinit();

        const result = try candidate.step(now, .start);
        self.eap_peer_mac = null;
        self.context.generation = candidate.currentGeneration();
        self.context.last_now = now;
        self.failure_reason = result.failure;
        self.machine = .{ .eap_md5 = candidate };
        return result;
    }

    fn stepActive(self: *Session, now: std.Io.Timestamp, input: Input) Error!Outcome {
        return switch (self.machine) {
            .empty => switch (input) {
                .frame => |event| blk: {
                    if (!event.generation.eql(self.context.generation)) {
                        return error.StaleGeneration;
                    }
                    if (etherType(event.bytes) == 0x0800) break :blk self.noop();
                    break :blk error.InvalidState;
                },
                else => error.InvalidState,
            },
            .eap_md5 => |*engine| {
                switch (input) {
                    .frame => |event| {
                        if (!event.generation.eql(self.context.generation)) {
                            return error.StaleGeneration;
                        }
                        if (etherType(event.bytes) == 0x0800) return self.noop();
                        if (etherType(event.bytes) == 0x888e) {
                            const frame = eapol.decode(event.bytes) catch return error.InvalidFrame;
                            if (frame.eap) |eap| {
                                if (eap.code == .request and eap.type == .md5_challenge and
                                    !self.config.allowed_methods.md5_challenge)
                                {
                                    return error.UnsupportedEapMethod;
                                }
                                if (eap.code == .request and eap.type == .peap) {
                                    return self.startPeap(now, engine, frame);
                                }
                            }
                        }
                    },
                    else => {},
                }
                const result = try engine.step(now, input);
                self.context.generation = engine.currentGeneration();
                self.context.last_now = now;
                self.failure_reason = engine.failure();

                if (engine.phase() == .idle) {
                    engine.deinit();
                    self.machine = .empty;
                }
                return result;
            },
            .peap => |*engine| {
                switch (input) {
                    .frame => |event| {
                        if (!event.generation.eql(self.context.generation)) {
                            return error.StaleGeneration;
                        }
                    },
                    .timer => |generation| {
                        if (!generation.eql(self.context.generation)) {
                            return error.StaleGeneration;
                        }
                    },
                    else => {},
                }
                const result = try engine.step(now, input);
                self.context.generation = engine.currentGeneration();
                self.context.last_now = now;
                self.failure_reason = result.failure;
                if (result.phase == .idle) {
                    engine.deinit();
                    self.machine = .empty;
                }
                return result;
            },
            .direct => |*engine| {
                switch (input) {
                    .frame => |event| {
                        if (!event.generation.eql(self.context.generation)) {
                            return error.StaleGeneration;
                        }
                        if (etherType(event.bytes) == 0x888e) {
                            const frame = eapol.decode(event.bytes) catch return self.noop();
                            if (frame.packet_type == .logoff) {
                                return self.finishDirect(now, false, .server_logoff);
                            }
                            return self.noop();
                        }
                    },
                    else => {},
                }
                const result = try engine.step(now, input);
                self.context.generation = engine.currentGeneration();
                self.context.last_now = now;
                self.failure_reason = result.failure;
                if (result.phase == .idle) {
                    engine.deinit();
                    self.machine = .empty;
                }
                return result;
            },
        };
    }

    fn startDirect(
        self: *Session,
        now: std.Io.Timestamp,
        config: DirectSessionConfig,
    ) Error!Outcome {
        switch (self.phase()) {
            .eap_md5 => |eap_phase| if (eap_phase != .authenticated) return error.InvalidState,
            else => return error.InvalidState,
        }

        const generation = try self.context.generation.next();
        var candidate = try direct_machine.Machine.init(
            self.allocator,
            config,
            now,
            generation,
        );
        errdefer candidate.deinit();

        var result = try candidate.start(now);
        result.previous_phase = self.phase();
        self.eap_peer_mac = switch (self.machine) {
            .eap_md5 => |*engine| engine.authenticatedPeer(),
            else => null,
        };
        self.machine.deinit();
        self.machine = .{ .direct = candidate };
        self.context.generation = generation;
        self.context.last_now = now;
        self.failure_reason = null;
        return result;
    }

    fn startPeap(
        self: *Session,
        now: std.Io.Timestamp,
        eap_engine: *eap_md5.Engine,
        frame: eapol.Frame,
    ) Error!Outcome {
        if (!self.config.allowed_methods.peap) return error.UnsupportedEapMethod;
        const peap_config = self.peap_config orelse return error.MissingDependency;
        const eap = frame.eap orelse return error.InvalidFrame;
        const handoff = try eap_engine.peapHandoff(frame.source, eap);
        const generation = try self.context.generation.next();

        var candidate = try peap_machine.Machine.init(
            peap_config,
            .{ .peer_mac = handoff.peer_mac, .identifier = handoff.identifier },
            now,
            generation,
            self.config.auth_timeout,
        );
        errdefer candidate.deinit();
        const actions = try self.allocator.alloc(Action, 0);
        errdefer self.allocator.free(actions);

        const previous_phase = eap_engine.phase();
        self.machine.deinit();
        self.machine = .{ .peap = candidate };
        self.context.generation = generation;
        self.context.last_now = now;
        self.failure_reason = null;
        self.eap_peer_mac = handoff.peer_mac;
        return .{
            .actions = actions,
            .previous_phase = previous_phase,
            .phase = .{ .peap = .handshake },
            .next_deadline = self.nextDeadline(),
            .failure = null,
            .generation = generation,
        };
    }

    fn cancel(self: *Session, now: std.Io.Timestamp) Error!Outcome {
        return switch (self.machine) {
            .empty => error.InvalidState,
            .eap_md5 => self.stepActive(now, .cancel),
            .peap => self.stepActive(now, .cancel),
            .direct => self.finishDirect(now, true, .canceled),
        };
    }

    fn finishDirect(
        self: *Session,
        now: std.Io.Timestamp,
        send_logoff: bool,
        reason: FailureReason,
    ) Error!Outcome {
        const previous_phase = self.phase();
        const action_count: usize = if (send_logoff) 1 else 0;
        const actions = try self.allocator.alloc(Action, action_count);
        errdefer self.allocator.free(actions);
        if (send_logoff) {
            const destination = self.eap_peer_mac orelse self.config.destination_mac;
            const frame = try self.allocator.alloc(u8, eapol.header_size);
            errdefer self.allocator.free(frame);
            eapol.encodeLogoff(
                destination,
                self.config.source_mac,
                frame[0..eapol.header_size],
            );
            actions[0] = .{ .send_frame = frame };
        }
        self.machine.deinit();
        self.machine = .empty;
        self.context.last_now = now;
        self.failure_reason = reason;
        return .{
            .actions = actions,
            .previous_phase = previous_phase,
            .phase = .idle,
            .next_deadline = null,
            .failure = reason,
            .generation = self.context.generation,
        };
    }

    fn noop(self: *const Session) Error!Outcome {
        return .{
            .actions = try self.allocator.alloc(Action, 0),
            .previous_phase = self.phase(),
            .phase = self.phase(),
            .next_deadline = self.nextDeadline(),
            .failure = self.failure_reason,
            .generation = self.context.generation,
        };
    }
};

fn etherType(frame: []const u8) ?u16 {
    if (frame.len < 14) return null;
    return std.mem.readInt(u16, frame[12..14], .big);
}

fn clonePeapConfig(
    allocator: std.mem.Allocator,
    source: PeapConfig,
) Error!PeapConfig {
    var owned = source;
    owned.v3_application_data = try allocator.dupe(u8, source.v3_application_data);
    errdefer allocator.free(owned.v3_application_data);
    owned.v3_dll_data = try allocator.dupe(u8, source.v3_dll_data);
    errdefer allocator.free(owned.v3_dll_data);
    owned.service_name_gbk = try allocator.dupe(u8, source.service_name_gbk);
    errdefer allocator.free(owned.service_name_gbk);
    owned.program_name_gbk = try allocator.dupe(u8, source.program_name_gbk);
    errdefer allocator.free(owned.program_name_gbk);
    owned.disk_serial_ascii = try allocator.dupe(u8, source.disk_serial_ascii);
    errdefer allocator.free(owned.disk_serial_ascii);
    owned.security_domain_ascii = try allocator.dupe(u8, source.security_domain_ascii);
    errdefer allocator.free(owned.security_domain_ascii);
    owned.ipd_result = try allocator.dupe(u8, source.ipd_result);
    return owned;
}

fn freePeapConfig(allocator: std.mem.Allocator, config: *PeapConfig) void {
    allocator.free(config.v3_application_data);
    allocator.free(config.v3_dll_data);
    allocator.free(config.service_name_gbk);
    allocator.free(config.program_name_gbk);
    allocator.free(config.disk_serial_ascii);
    allocator.free(config.security_domain_ascii);
    allocator.free(config.ipd_result);
    config.* = undefined;
}
