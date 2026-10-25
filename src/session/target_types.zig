//! Public values for the target Ruijie EAP-MD5 session profile.

const std = @import("std");

/// Identifies one authentication attempt. Frames and timers must carry the
/// generation returned by the attempt that requested them.
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
    idle,
    connecting,
    acquired,
    authenticating,
    authenticated,
    held,
};

/// IPv4 lease facts used by the legacy DHCP block in the private tail.
pub const Lease = struct {
    dhcp_enabled: bool = false,
    ip: [4]u8 = @splat(0),
    netmask: [4]u8 = @splat(0),
    gateway: [4]u8 = @splat(0),
    dns: [4]u8 = @splat(0),
};

/// Runtime facts supplied by the client. Byte slices are borrowed and must
/// remain valid for the duration of the call that uses them.
pub const Facts = struct {
    source_mac: [6]u8,
    service_name: []const u8 = &.{},
    disk_serial: []const u8 = &.{},
    ipv6_state: u8 = 0,
    ipv6_link_local: ?[16]u8 = null,
    ipv6_global: ?[16]u8 = null,
    ipv6_third: ?[16]u8 = null,
    lease: Lease = .{},
    alternate_dns_text: []const u8 = &.{},
    os_bits: u8 = 0x40,

    pub fn validate(self: Facts) Error!void {
        if (self.service_name.len > 32 or
            self.disk_serial.len > 64 or
            self.alternate_dns_text.len > 247 or
            (self.os_bits != 0x20 and self.os_bits != 0x40))
        {
            return error.InvalidFacts;
        }
    }
};

/// Credentials are borrowed for the lifetime of the session; the client keeps
/// the backing bytes alive and must not mutate them while the session runs.
pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const Config = struct {
    facts: Facts,
    credentials: Credentials,
    start_timeout: std.Io.Duration = .fromSeconds(30),
    auth_timeout: std.Io.Duration = .fromSeconds(30),
    held_timeout: std.Io.Duration = .fromSeconds(30),
    max_start_attempts: u16 = 3,
    max_auth_failures: u16 = 3,

    pub fn validate(self: Config) Error!void {
        try self.facts.validate();
        if (self.credentials.username.len == 0 or
            self.credentials.username.len > 255 or
            self.credentials.password.len > 240)
        {
            return error.InvalidCredentials;
        }
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

pub const FailureReason = enum {
    server_failure,
    start_timeout,
    auth_timeout,
    canceled,
    server_logoff,
};

pub const TerminalKind = enum {
    success,
    failure,
};

/// Private terminal notification. `notification` is owned by the outcome.
pub const TerminalMessage = struct {
    kind: TerminalKind,
    notification: []u8,
};

pub const Action = union(enum) {
    send_frame: []u8,
};

pub const FrameInput = struct {
    generation: Generation,
    bytes: []const u8,
};

/// External events accepted by `Session.step`. Facts carries no generation:
/// it is a synchronous runtime snapshot for the current attempt.
pub const Input = union(enum) {
    start,
    cancel,
    frame: FrameInput,
    timer: Generation,
    facts: Facts,
};

pub const Outcome = struct {
    /// Sending actions own their frame bytes until `deinit` is called.
    actions: []Action,
    previous_phase: Phase,
    phase: Phase,
    next_deadline: ?std.Io.Timestamp,
    failure: ?FailureReason,
    generation: Generation,
    terminal: ?TerminalMessage,

    /// Releases every owned frame and terminal allocation.
    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        for (self.actions) |action| switch (action) {
            .send_frame => |frame| allocator.free(frame),
        };
        allocator.free(self.actions);
        if (self.terminal) |terminal| allocator.free(terminal.notification);
        self.* = undefined;
    }
};

pub const Error = error{
    InvalidConfig,
    InvalidFacts,
    InvalidCredentials,
    InvalidFrame,
    InvalidState,
    DuplicateFrame,
    StaleIdentifier,
    TimerNotDue,
    UnsupportedEapMethod,
    StaleGeneration,
    TimeWentBackwards,
    TimestampOverflow,
    GenerationOverflow,
    OutOfMemory,
};

pub const destination_mac = [6]u8{ 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
