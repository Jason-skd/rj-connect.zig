//! Public target-profile session entry points.

pub const Session = @import("target_session.zig").Session;

const types = @import("target_types.zig");

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

/// Initial Start destination embedded in the target client.
pub const destination_mac = types.destination_mac;
