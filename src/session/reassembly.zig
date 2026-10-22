//! Strictly ordered single-message Direct reassembly.

const std = @import("std");
const wire = @import("../protocol/direct.zig");
const types = @import("types.zig");

pub const AcceptResult = union(enum) {
    ignored,
    duplicate,
    buffered,
    complete: struct {
        id: u32,
        bytes: []u8,
    },
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

    pub fn accept(
        self: *Reassembler,
        id: u32,
        flags: u8,
        total_len: u32,
        chunk: []const u8,
        now: std.Io.Timestamp,
    ) types.Error!AcceptResult {
        if (chunk.len == 0 or chunk.len > wire.max_encrypted_chunk) return .ignored;

        if (self.last_id) |last_id| {
            if (id == last_id) return .duplicate;
            if (id != last_id +% 1) return .ignored;
        }

        const total: usize = total_len;
        if (total == 0 or total > self.max_message_size or total % 8 != 0 or
            chunk.len > total)
        {
            return .ignored;
        }

        return switch (flags) {
            1 => self.acceptSingle(id, total, chunk),
            2 => self.acceptFirst(id, total, chunk, now),
            3 => self.acceptMiddle(id, total, chunk),
            4 => self.acceptLast(id, total, chunk),
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
        return .{ .complete = .{ .id = id, .bytes = buffer } };
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

        self.clear();
        self.buffer = buffer;
        self.total_len = total_len;
        self.filled = chunk.len;
        self.last_id = id;
        self.expires_at = try addReassemblyTimeout(now);
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

        const buffer = try self.allocator.alloc(u8, self.total_len);
        errdefer self.allocator.free(buffer);
        @memcpy(buffer[0..self.filled], existing[0..self.filled]);
        @memcpy(buffer[self.filled..][0..chunk.len], chunk);
        return .{ .complete = .{ .id = id, .bytes = buffer } };
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
