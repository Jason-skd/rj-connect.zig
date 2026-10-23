//! EAP-PEAPv0 outer payload framing.

const std = @import("std");

pub const start_flag: u8 = 0x20;
pub const more_flag: u8 = 0x40;
pub const length_flag: u8 = 0x80;
pub const known_flags = start_flag | more_flag | length_flag;

pub const Flags = struct {
    start: bool = false,
    more: bool = false,
    length_included: bool = false,

    pub fn decode(byte: u8) Error!Flags {
        if (byte & ~known_flags != 0) return error.InvalidFlags;
        return .{
            .start = byte & start_flag != 0,
            .more = byte & more_flag != 0,
            .length_included = byte & length_flag != 0,
        };
    }

    pub fn encode(self: Flags) u8 {
        return (if (self.start) start_flag else 0) |
            (if (self.more) more_flag else 0) |
            (if (self.length_included) length_flag else 0);
    }
};

pub const Payload = struct {
    flags: Flags,
    tls_message_length: ?u32,
    tls: []const u8,
};

pub const Error = error{
    TruncatedFlags,
    TruncatedLength,
    TruncatedTls,
    InvalidFlags,
    InvalidLength,
    OutputTooSmall,
};

pub fn decode(input: []const u8) Error!Payload {
    if (input.len < 1) return error.TruncatedFlags;
    const flags = try Flags.decode(input[0]);
    var offset: usize = 1;
    var tls_message_length: ?u32 = null;
    if (flags.length_included) {
        if (input.len < 5) return error.TruncatedLength;
        tls_message_length = std.mem.readInt(u32, input[1..5], .big);
        offset = 5;
    }
    if (offset > input.len) return error.TruncatedTls;
    return .{
        .flags = flags,
        .tls_message_length = tls_message_length,
        .tls = input[offset..],
    };
}

pub fn encodedSize(tls_len: usize, include_length: bool) Error!usize {
    const prefix_len: usize = if (include_length) 5 else 1;
    return std.math.add(usize, prefix_len, tls_len) catch error.InvalidLength;
}

pub fn encode(
    flags: Flags,
    tls_message_length: ?u32,
    tls: []const u8,
    output: []u8,
) Error![]const u8 {
    if (flags.length_included != (tls_message_length != null)) return error.InvalidLength;
    const required = try encodedSize(tls.len, flags.length_included);
    if (output.len < required) return error.OutputTooSmall;

    output[0] = flags.encode();
    var offset: usize = 1;
    if (tls_message_length) |value| {
        std.mem.writeInt(u32, output[1..5], value, .big);
        offset = 5;
    }
    @memcpy(output[offset..required], tls);
    return output[0..required];
}

test "PEAP outer payload decodes start, more, and length flags" {
    const encoded = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    const payload = try decode(&encoded);

    try std.testing.expect(payload.flags.start);
    try std.testing.expect(payload.flags.more);
    try std.testing.expect(payload.flags.length_included);
    try std.testing.expectEqual(@as(?u32, 3), payload.tls_message_length);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, payload.tls);
}

test "PEAP outer payload round-trips with and without a length" {
    var output: [16]u8 = undefined;

    const plain = try encode(.{}, null, "tls", &output);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 't', 'l', 's' }, plain);
    const decoded_plain = try decode(plain);
    try std.testing.expectEqual(@as(?u32, null), decoded_plain.tls_message_length);

    const with_length = try encode(.{ .start = true, .length_included = true }, 3, "tls", &output);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xa0, 0x00, 0x00, 0x00, 0x03, 't', 'l', 's' },
        with_length,
    );
}

test "PEAP outer payload rejects invalid and truncated framing" {
    try std.testing.expectError(error.TruncatedFlags, decode(&.{}));
    try std.testing.expectError(error.InvalidFlags, decode(&.{0x01}));
    try std.testing.expectError(error.TruncatedLength, decode(&.{ 0x80, 0, 0, 0 }));

    var output: [4]u8 = undefined;
    try std.testing.expectError(
        error.InvalidLength,
        encode(.{ .length_included = true }, null, &.{}, &output),
    );
    try std.testing.expectError(
        error.InvalidLength,
        encode(.{}, 1, &.{}, &output),
    );
    try std.testing.expectError(
        error.OutputTooSmall,
        encode(.{}, null, "tls", output[0..2]),
    );
}
