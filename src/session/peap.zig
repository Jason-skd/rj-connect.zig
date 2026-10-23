//! Deterministic PEAPv0 orchestration with caller-owned TLS and MSCHAPv2.

const std = @import("std");
const time = @import("time.zig");
const types = @import("types.zig");

const Error = types.Error;
const Input = types.Input;
const Outcome = @import("outcome.zig").Outcome;

pub const Handoff = struct {
    peer_mac: [6]u8,
    identifier: u8,
};

pub const Machine = struct {
    config: types.PeapConfig,
    generation: types.Generation,
    phase: types.PeapPhase = .handshake,
    peer_mac: [6]u8,
    identifier: u8,
    deadline: std.Io.Timestamp,

    pub fn init(
        config: types.PeapConfig,
        handoff: Handoff,
        now: std.Io.Timestamp,
        generation: types.Generation,
        auth_timeout: std.Io.Duration,
    ) Error!Machine {
        try config.validate();
        return .{
            .config = config,
            .generation = generation,
            .peer_mac = handoff.peer_mac,
            .identifier = handoff.identifier,
            .deadline = try time.addDuration(now, auth_timeout),
        };
    }

    pub fn deinit(_: *Machine) void {}

    pub fn currentPhase(self: *const Machine) types.ActivePhase {
        return .{ .peap = self.phase };
    }

    pub fn currentGeneration(self: *const Machine) types.Generation {
        return self.generation;
    }

    pub fn nextDeadline(self: *const Machine) ?std.Io.Timestamp {
        return self.deadline;
    }

    pub fn step(_: *Machine, _: std.Io.Timestamp, _: Input) Error!Outcome {
        return error.InvalidState;
    }
};
