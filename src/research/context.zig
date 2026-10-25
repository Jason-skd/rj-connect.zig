//! State shared across a Session's active protocol machines.

const std = @import("std");
const types = @import("types.zig");

pub const Context = struct {
    generation: types.Generation = types.Generation.initial,
    last_now: ?std.Io.Timestamp = null,
};
