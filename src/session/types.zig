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

pub const EapMd5Phase = enum {
    connecting,
    acquired,
    authenticating,
    authenticated,
    held,
};

pub const ActivePhase = union(enum) {
    idle,
    eap_md5: EapMd5Phase,
    direct: DirectPhase,
};

pub const DirectPhase = enum {
    initializing,
    awaiting_result,
    active,
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

    pub fn validate(self: Config) Error!void {
        if (self.start_timeout.toNanoseconds() <= 0 or
            self.auth_timeout.toNanoseconds() <= 0 or
            self.held_timeout.toNanoseconds() <= 0 or
            self.max_start_attempts == 0 or
            self.max_auth_failures == 0)
        {
            return error.InvalidConfig;
        }
    }
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

pub const DirectNetworkInfo = struct {
    ipv4: [4]u8,
    netmask: [4]u8,
    gateway: [4]u8,
    dns: [4]u8,
    alternate_dns: ?[4]u8 = null,
    mac: [6]u8,
};

pub const DirectTimestampMode = union(enum) {
    server: u64,
    monotonic: u64,
};

pub const SamConfig = struct {
    session_parameter: [4]u8,
    endpoint_parameter: [6]u8,
};

pub const DirectMode = union(enum) {
    sam: SamConfig,
};

pub const DirectSessionConfig = struct {
    mode: DirectMode,
    peer_mac: [6]u8,
    peer_ipv4: [4]u8,
    peer_udp_port: u16,
    local_udp_port: u16,
    session_id: u32,
    des_key: [8]u8,
    initial_iv: [8]u8,
    timestamp: DirectTimestampMode,
    username_gbk: []const u8,
    network: DirectNetworkInfo,
    next_message_id: u32 = 1,
    max_message_size: usize = 1024 * 1024,
    ack_timeout: std.Io.Duration = .fromSeconds(3),
    max_send_attempts: u8 = 3,

    pub fn validate(self: DirectSessionConfig) Error!void {
        if (self.username_gbk.len == 0 or self.username_gbk.len > 255 or
            self.max_message_size == 0 or self.max_message_size > std.math.maxInt(u32) or
            self.ack_timeout.toNanoseconds() <= 0 or self.max_send_attempts == 0)
        {
            return error.InvalidConfig;
        }
    }
};

/// Byte slices in an input event are borrowed and must remain valid for one call only.
/// Asynchronous inputs are ignored with `StaleGeneration` after a new attempt begins.
pub const Input = union(enum) {
    start,
    cancel,
    frame: FrameInput,
    direct_session: DirectSessionConfig,
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
