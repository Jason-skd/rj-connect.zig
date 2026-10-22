//! Public deterministic session coordinator.

const std = @import("std");
const context = @import("context.zig");
const direct_machine = @import("direct.zig");
const eap_md5 = @import("eap_md5.zig");
const session_outcome = @import("outcome.zig");
const types = @import("types.zig");

pub const Generation = types.Generation;
pub const EapMd5Phase = types.EapMd5Phase;
pub const ActivePhase = types.ActivePhase;
pub const DirectPhase = types.DirectPhase;
pub const Config = types.Config;
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
    machine: Machine,

    const Machine = union(enum) {
        empty,
        eap_md5: eap_md5.Engine,
        direct: direct_machine.Machine,

        fn deinit(self: *Machine) void {
            switch (self.*) {
                .empty => {},
                .eap_md5 => |*engine| engine.deinit(),
                .direct => |*engine| engine.deinit(),
            }
            self.* = .empty;
        }
    };

    /// Creates an idle session. No machine or frame is allocated until `step` starts one.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Session {
        try config.validate();
        return .{
            .allocator = allocator,
            .config = config,
            .context = .{},
            .failure_reason = null,
            .machine = .empty,
        };
    }

    pub fn deinit(self: *Session) void {
        self.machine.deinit();
    }

    pub fn phase(self: *const Session) ActivePhase {
        return switch (self.machine) {
            .empty => .idle,
            .eap_md5 => |*engine| engine.phase(),
            .direct => |*engine| engine.currentPhase(),
        };
    }

    pub fn nextDeadline(self: *const Session) ?std.Io.Timestamp {
        return switch (self.machine) {
            .empty => null,
            .eap_md5 => |*engine| engine.nextDeadline(),
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
            .direct => .none,
        };
    }

    pub fn dhcpPollAttempts(self: *const Session) u8 {
        return switch (self.machine) {
            .empty => 0,
            .eap_md5 => |*engine| engine.dhcpPollAttempts(),
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
            .direct => |*engine| {
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
        self.machine.deinit();
        self.machine = .{ .direct = candidate };
        self.context.generation = generation;
        self.context.last_now = now;
        self.failure_reason = null;
        return result;
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
