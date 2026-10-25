//! Checked arithmetic for session deadlines.

const std = @import("std");
const types = @import("types.zig");

pub fn addDuration(base: std.Io.Timestamp, duration: std.Io.Duration) types.Error!std.Io.Timestamp {
    const result = @addWithOverflow(base.nanoseconds, duration.nanoseconds);
    if (result[1] != 0) return error.TimestampOverflow;
    return .fromNanoseconds(result[0]);
}
