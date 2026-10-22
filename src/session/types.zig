//! Public session values shared across protocol machines.

const std = @import("std");
const eapol = @import("../protocol/eapol.zig");

/// Identifies one authentication attempt. Network frames, timers, and external
/// results must carry the generation returned by the attempt that requested them.
pub const Generation = struct {
    value: u32,

    pub const initial: Generation = .{ .value = 0 };

    pub fn eql(self: Generation, other: Generation) bool {
        return self.value == other.value;
    }

    pub fn next(self: Generation) Error!Generation {
        if (self.value == std.math.maxInt(u32)) return error.GenerationOverflow;
        return .{ .value = self.value + 1 };
    }
};

pub const Phase = enum {
    disconnected,
    connecting,
    acquired,
    authenticating,
    authenticated,
    held,
    logoff,
};

pub const Config = struct {
    source_mac: [6]u8,
    destination_mac: [6]u8 = eapol.default_destination,
    start_timeout: std.Io.Duration = .fromSeconds(30),
    auth_timeout: std.Io.Duration = .fromSeconds(30),
    held_timeout: std.Io.Duration = .fromSeconds(30),
    max_start_attempts: u16 = 3,
    max_auth_failures: u16 = 3,
    dhcp_second_auth: bool = false,
};

pub const CredentialPurpose = enum {
    identity,
    md5_challenge,
    credential_request,
};

pub const FailureReason = enum {
    server_failure,
    start_timeout,
    auth_timeout,
    canceled,
    dhcp_timeout,
    server_logoff,
};

pub const DhcpStep = enum(u8) {
    none = 0,
    first = 1,
    second = 2,
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const DhcpLease = struct {
    ip: ?[4]u8 = null,
    gateway: ?[4]u8 = null,
};

pub const ExternalResult = union(enum) {
    dhcp_lease: DhcpLease,
};

pub const ExternalResultInput = struct {
    generation: Generation,
    result: ExternalResult,
};

pub const FrameInput = struct {
    generation: Generation,
    bytes: []const u8,
};

/// Byte slices in an input event are borrowed and must remain valid for one call only.
/// Asynchronous inputs are ignored with `StaleGeneration` after a new attempt begins.
pub const Input = union(enum) {
    start,
    cancel,
    frame: FrameInput,
    timer: Generation,
    credentials: Credentials,
    external_result: ExternalResultInput,
};

pub const Error = error{
    InvalidConfig,
    InvalidInput,
    InvalidFrame,
    InvalidCredentials,
    InvalidState,
    DuplicateFrame,
    StaleIdentifier,
    TimerNotDue,
    UnsupportedEapMethod,
    TimeWentBackwards,
    TimestampOverflow,
    StaleGeneration,
    GenerationOverflow,
    OutOfMemory,
};
