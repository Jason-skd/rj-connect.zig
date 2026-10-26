//! Public values for the legacy MentoHUST 0.3.1 wired EAP-MD5 profile.

const std = @import("std");
const shared = @import("target_types.zig");

pub const Generation = shared.Generation;
pub const Phase = shared.Phase;
pub const FailureReason = shared.FailureReason;
pub const TerminalKind = shared.TerminalKind;
pub const TerminalMessage = shared.TerminalMessage;
pub const Action = shared.Action;
pub const FrameInput = shared.FrameInput;
pub const Outcome = shared.Outcome;
pub const Error = error{
    InvalidConfig,
    InvalidCredentials,
    InvalidFrame,
    InvalidState,
    DuplicateFrame,
    StaleIdentifier,
    StaleTerminalIdentifier,
    TimerNotDue,
    UnsupportedEapMethod,
    UnsupportedProfileInput,
    StaleGeneration,
    TimeWentBackwards,
    TimestampOverflow,
    GenerationOverflow,
    OutOfMemory,
};

pub const Credentials = shared.Credentials;

pub const Config = struct {
    source_mac: [6]u8,
    credentials: Credentials,
    start_timeout: std.Io.Duration = .fromSeconds(30),
    auth_timeout: std.Io.Duration = .fromSeconds(30),
    held_timeout: std.Io.Duration = .fromSeconds(30),
    max_start_attempts: u16 = 3,
    max_auth_failures: u16 = 3,

    pub fn validate(self: Config) Error!void {
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

pub const Input = shared.Input;
