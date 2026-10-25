//! Shared DHCP lease polling policy for authentication paths.

const std = @import("std");
const time = @import("time.zig");
const types = @import("types.zig");

pub const interval = std.Io.Duration.fromSeconds(2);
pub const max_attempts: u8 = 21;

pub const State = struct {
    attempts: u8 = 0,
    deadline: std.Io.Timestamp = .fromNanoseconds(0),

    pub fn begin(now: std.Io.Timestamp) types.Error!State {
        return .{
            .attempts = 1,
            .deadline = try time.addDuration(now, interval),
        };
    }

    /// Returns the next polling state, or null when the retry budget is exhausted.
    pub fn retry(self: State, now: std.Io.Timestamp) types.Error!?State {
        if (now.compare(.lt, self.deadline)) return error.TimerNotDue;
        if (self.attempts >= max_attempts) return null;
        return .{
            .attempts = self.attempts + 1,
            .deadline = try time.addDuration(now, interval),
        };
    }
};

test "DHCP polling begins and retries within the shared budget" {
    const first = try State.begin(.fromNanoseconds(0));
    try std.testing.expectEqual(@as(u8, 1), first.attempts);
    try std.testing.expectEqual(interval.nanoseconds, first.deadline.nanoseconds);
    try std.testing.expectError(
        error.TimerNotDue,
        first.retry(.fromNanoseconds(1)),
    );

    const second = (try first.retry(first.deadline)).?;
    try std.testing.expectEqual(@as(u8, 2), second.attempts);

    const exhausted = State{
        .attempts = max_attempts,
        .deadline = first.deadline,
    };
    try std.testing.expect((try exhausted.retry(exhausted.deadline)) == null);
}
