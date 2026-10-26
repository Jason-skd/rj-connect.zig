//! Public deterministic EAP-MD5 session entry points.

const std = @import("std");
const macos = @import("target_session.zig");
pub const legacy = @import("legacy_session.zig");

const types = @import("target_types.zig");
const legacy_types = @import("legacy_types.zig");

pub const Profile = enum {
    macos_1_35_wired,
    mentohust_0_3_1_wired,
};

pub const Generation = types.Generation;
pub const Phase = types.Phase;
pub const Facts = types.Facts;
pub const Lease = types.Lease;
pub const Credentials = types.Credentials;
pub const Config = types.Config;
pub const FailureReason = types.FailureReason;
pub const TerminalKind = types.TerminalKind;
pub const TerminalMessage = types.TerminalMessage;
pub const Action = types.Action;
pub const FrameInput = types.FrameInput;
pub const Input = types.Input;
pub const Outcome = types.Outcome;
pub const Error = types.Error;

pub const LegacyConfig = legacy_types.Config;

/// Initial Start destination embedded in the macOS 1.35 client.
pub const destination_mac = types.destination_mac;

pub const Session = struct {
    inner: Inner,

    const Inner = union(Profile) {
        macos_1_35_wired: macos.Session,
        mentohust_0_3_1_wired: legacy.Session,
    };

    /// Creates the macOS 1.35 wired EAP-MD5 profile.
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!Session {
        return .{ .inner = .{ .macos_1_35_wired = try macos.Session.init(allocator, config) } };
    }

    /// Creates the MentoHUST 0.3.1 wired EAP-MD5 compatibility profile.
    pub fn initLegacy(allocator: std.mem.Allocator, config: LegacyConfig) Error!Session {
        return .{ .inner = .{
            .mentohust_0_3_1_wired = try legacy.Session.init(allocator, config),
        } };
    }

    pub fn deinit(self: *Session) void {
        switch (self.inner) {
            .macos_1_35_wired => |*value| value.deinit(),
            .mentohust_0_3_1_wired => |*value| value.deinit(),
        }
        self.* = undefined;
    }

    pub fn profile(self: *const Session) Profile {
        return std.meta.activeTag(self.inner);
    }

    pub fn phase(self: *const Session) Phase {
        return switch (self.inner) {
            .macos_1_35_wired => |value| value.phase(),
            .mentohust_0_3_1_wired => |value| switch (value.phase()) {
                .idle => .idle,
                .connecting => .connecting,
                .acquired => .acquired,
                .authenticating => .authenticating,
                .authenticated => .authenticated,
                .held => .held,
            },
        };
    }

    pub fn nextDeadline(self: *const Session) ?std.Io.Timestamp {
        return switch (self.inner) {
            .macos_1_35_wired => |value| value.nextDeadline(),
            .mentohust_0_3_1_wired => |value| value.nextDeadline(),
        };
    }

    pub fn failure(self: *const Session) ?FailureReason {
        return switch (self.inner) {
            .macos_1_35_wired => |value| value.failure(),
            .mentohust_0_3_1_wired => |value| switch (value.failure() orelse return null) {
                .server_failure => .server_failure,
                .start_timeout => .start_timeout,
                .auth_timeout => .auth_timeout,
                .canceled => .canceled,
                .server_logoff => .server_logoff,
            },
        };
    }

    pub fn currentGeneration(self: *const Session) Generation {
        return switch (self.inner) {
            .macos_1_35_wired => |value| value.currentGeneration(),
            .mentohust_0_3_1_wired => |value| value.currentGeneration(),
        };
    }

    /// Advances the selected profile. The macOS profile accepts `.facts`;
    /// the legacy profile explicitly rejects it because it has no mutable facts.
    pub fn step(self: *Session, now: std.Io.Timestamp, input: Input) Error!Outcome {
        return switch (self.inner) {
            .macos_1_35_wired => |*value| value.step(now, input),
            .mentohust_0_3_1_wired => |*value| value.step(now, input) catch |err| return mapLegacyError(err),
        };
    }
};

fn mapLegacyError(err: legacy_types.Error) Error {
    return switch (err) {
        error.InvalidConfig => error.InvalidConfig,
        error.InvalidCredentials => error.InvalidCredentials,
        error.InvalidFrame => error.InvalidFrame,
        error.InvalidState => error.InvalidState,
        error.DuplicateFrame => error.DuplicateFrame,
        error.StaleIdentifier => error.StaleIdentifier,
        error.StaleTerminalIdentifier => error.StaleTerminalIdentifier,
        error.TimerNotDue => error.TimerNotDue,
        error.UnsupportedProfileInput => error.UnsupportedProfileInput,
        error.UnsupportedEapMethod => error.UnsupportedEapMethod,
        error.StaleGeneration => error.StaleGeneration,
        error.TimeWentBackwards => error.TimeWentBackwards,
        error.TimestampOverflow => error.TimestampOverflow,
        error.GenerationOverflow => error.GenerationOverflow,
        error.OutOfMemory => error.OutOfMemory,
        else => unreachable,
    };
}
