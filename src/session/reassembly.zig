//! Strictly ordered single-message Direct reassembly.

const std = @import("std");
const wire = @import("../protocol/direct.zig");
const types = @import("types.zig");

pub const AcceptResult = union(enum) {
    ignored,
    duplicate,
    buffered,
    complete: Complete,
};

pub const CompleteStorage = enum {
    caller,
    reassembler,
};

pub const Complete = struct {
    id: u32,
    bytes: []u8,
    storage: CompleteStorage,
};

const Classification = enum {
    ignored,
    duplicate,
    buffered,
    complete,
};

pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    max_message_size: usize,
    buffer: ?[]u8 = null,
    total_len: usize = 0,
    filled: usize = 0,
    last_id: ?u32 = null,
    expires_at: ?std.Io.Timestamp = null,

    pub fn init(allocator: std.mem.Allocator, max_message_size: usize) Reassembler {
        return .{
            .allocator = allocator,
            .max_message_size = max_message_size,
        };
    }

    pub fn deinit(self: *Reassembler) void {
        if (self.buffer) |buffer| self.allocator.free(buffer);
        self.* = undefined;
    }

    pub fn nextDeadline(self: *const Reassembler) ?std.Io.Timestamp {
        return self.expires_at;
    }

    pub fn incompleteTotal(self: *const Reassembler) ?usize {
        if (self.buffer == null) return null;
        return self.total_len;
    }

    pub fn expire(self: *Reassembler, now: std.Io.Timestamp) bool {
        const deadline = self.expires_at orelse return false;
        if (now.compare(.lt, deadline)) return false;
        self.clear();
        return true;
    }

    pub fn commitComplete(self: *Reassembler, id: u32, total_len: usize) void {
        if (self.buffer) |buffer| self.allocator.free(buffer);
        self.buffer = null;
        self.total_len = total_len;
        self.filled = total_len;
        self.last_id = id;
        self.expires_at = null;
    }

    /// Restores the pre-append length after a completed message cannot be committed.
    pub fn rollbackAppend(self: *Reassembler, amount: usize) void {
        if (self.buffer != null and amount <= self.filled) {
            self.filled -= amount;
        }
    }

    pub fn accepts(
        self: *const Reassembler,
        id: u32,
        flags: u8,
        total_len: u32,
        chunk_len: usize,
    ) bool {
        return self.classify(id, flags, total_len, chunk_len) != .ignored;
    }

    pub fn accept(
        self: *Reassembler,
        id: u32,
        flags: u8,
        total_len: u32,
        chunk: []const u8,
        now: std.Io.Timestamp,
    ) types.Error!AcceptResult {
        const total: usize = total_len;
        switch (self.classify(id, flags, total_len, chunk.len)) {
            .ignored => return .ignored,
            .duplicate => return .duplicate,
            .buffered => return switch (flags) {
                2 => self.acceptFirst(id, total, chunk, now),
                3 => self.acceptMiddle(id, total, chunk),
                else => .ignored,
            },
            .complete => return switch (flags) {
                1 => self.acceptSingle(id, total, chunk),
                4 => self.acceptLast(id, total, chunk),
                else => .ignored,
            },
        }
    }

    fn classify(
        self: *const Reassembler,
        id: u32,
        flags: u8,
        total_len: u32,
        chunk_len: usize,
    ) Classification {
        if (chunk_len == 0 or chunk_len > wire.max_encrypted_chunk) return .ignored;

        if (self.last_id) |last_id| {
            if (id == last_id) return .duplicate;
            if (id != last_id +% 1) return .ignored;
        }

        const total: usize = total_len;
        if (total == 0 or total > self.max_message_size or total % 8 != 0 or
            chunk_len > total)
        {
            return .ignored;
        }

        return switch (flags) {
            1 => if (chunk_len == total) .complete else .ignored,
            2 => if (total > wire.max_encrypted_chunk and
                chunk_len == wire.max_encrypted_chunk)
                .buffered
            else
                .ignored,
            3 => {
                if (self.buffer == null or total != self.total_len or
                    chunk_len != wire.max_encrypted_chunk or
                    self.filled + chunk_len >= self.total_len)
                {
                    return .ignored;
                }
                return .buffered;
            },
            4 => if (self.buffer != null and total == self.total_len and
                self.filled + chunk_len == self.total_len)
                .complete
            else
                .ignored,
            else => .ignored,
        };
    }

    fn acceptSingle(
        self: *Reassembler,
        id: u32,
        total_len: usize,
        chunk: []const u8,
    ) types.Error!AcceptResult {
        if (chunk.len != total_len) return .ignored;
        const buffer = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(buffer);
        @memcpy(buffer, chunk);
        return .{ .complete = .{
            .id = id,
            .bytes = buffer,
            .storage = .caller,
        } };
    }

    fn acceptFirst(
        self: *Reassembler,
        id: u32,
        total_len: usize,
        chunk: []const u8,
        now: std.Io.Timestamp,
    ) types.Error!AcceptResult {
        if (total_len <= wire.max_encrypted_chunk or chunk.len != wire.max_encrypted_chunk) {
            return .ignored;
        }

        const buffer = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(buffer);
        @memcpy(buffer[0..chunk.len], chunk);

        const expires_at = try addReassemblyTimeout(now);
        self.clear();
        self.buffer = buffer;
        self.total_len = total_len;
        self.filled = chunk.len;
        self.last_id = id;
        self.expires_at = expires_at;
        return .buffered;
    }

    fn acceptMiddle(
        self: *Reassembler,
        id: u32,
        total_len: usize,
        chunk: []const u8,
    ) types.Error!AcceptResult {
        const buffer = self.buffer orelse return .ignored;
        if (total_len != self.total_len or chunk.len != wire.max_encrypted_chunk) return .ignored;
        if (self.filled + chunk.len >= self.total_len) return .ignored;

        @memcpy(buffer[self.filled..][0..chunk.len], chunk);
        self.filled += chunk.len;
        self.last_id = id;
        return .buffered;
    }

    fn acceptLast(
        self: *Reassembler,
        id: u32,
        total_len: usize,
        chunk: []const u8,
    ) types.Error!AcceptResult {
        const existing = self.buffer orelse return .ignored;
        if (total_len != self.total_len or self.filled + chunk.len != self.total_len) {
            return .ignored;
        }

        @memcpy(existing[self.filled..][0..chunk.len], chunk);
        self.filled = self.total_len;
        return .{ .complete = .{
            .id = id,
            .bytes = existing,
            .storage = .reassembler,
        } };
    }

    fn clear(self: *Reassembler) void {
        if (self.buffer) |buffer| self.allocator.free(buffer);
        self.buffer = null;
        self.total_len = 0;
        self.filled = 0;
        self.expires_at = null;
    }
};

fn addReassemblyTimeout(now: std.Io.Timestamp) types.Error!std.Io.Timestamp {
    const result = @addWithOverflow(now.nanoseconds, 9 * std.time.ns_per_s);
    if (result[1] != 0) return error.TimestampOverflow;
    return .fromNanoseconds(result[0]);
}

test "reassembly reuses its initial buffer for the final fragment" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var value = Reassembler.init(failing.allocator(), 4096);
    defer value.deinit();

    const first: [wire.max_encrypted_chunk]u8 = @splat(0x11);
    const last = [_]u8{ 0x22, 0x22 };
    const total_len = first.len + last.len;
    _ = try value.accept(1, 2, @intCast(total_len), &first, .fromNanoseconds(0));
    const allocations_after_first = failing.alloc_index;

    const completed = try value.accept(2, 4, @intCast(total_len), &last, .fromNanoseconds(0));
    try std.testing.expectEqual(allocations_after_first, failing.alloc_index);
    const complete = completed.complete;
    try std.testing.expectEqual(CompleteStorage.reassembler, complete.storage);
    try std.testing.expectEqual(total_len, complete.bytes.len);
    try std.testing.expectEqualSlices(u8, &first, complete.bytes[0..first.len]);
    try std.testing.expectEqualSlices(u8, &last, complete.bytes[first.len..]);

    value.commitComplete(complete.id, complete.bytes.len);
}

test "reassembly allocation failure leaves delivery progress unchanged" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var value = Reassembler.init(failing.allocator(), 4096);
    defer value.deinit();

    failing.fail_index = failing.alloc_index;
    const first: [wire.max_encrypted_chunk]u8 = @splat(0x11);
    try std.testing.expectError(
        error.OutOfMemory,
        value.accept(1, 2, 1360, &first, .fromNanoseconds(0)),
    );
    try std.testing.expectEqual(@as(?[]u8, null), value.buffer);
    try std.testing.expectEqual(@as(?u32, null), value.last_id);
    try std.testing.expectEqual(@as(?std.Io.Timestamp, null), value.nextDeadline());
}
