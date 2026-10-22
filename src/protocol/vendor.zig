const std = @import("std");

pub const Field = struct {
    code: u8,
    value: []const u8,
};

pub const ParseError = error{
    TruncatedHeader,
    TruncatedValue,
};

pub const WriteError = error{
    ValueTooLong,
    NoSpace,
};

pub const CompactReader = struct {
    remaining: []const u8,

    pub fn init(input: []const u8) CompactReader {
        return .{ .remaining = input };
    }

    pub fn next(self: *CompactReader) ParseError!?Field {
        if (self.remaining.len == 0) return null;
        if (self.remaining[0] == 0x00 or self.remaining[0] == 0xff) {
            self.remaining = &.{};
            return null;
        }
        if (self.remaining.len < 2) return error.TruncatedHeader;

        const value_len = self.remaining[1];
        const field_len = 2 + @as(usize, value_len);
        if (self.remaining.len < field_len) return error.TruncatedValue;

        const field = Field{
            .code = self.remaining[0],
            .value = self.remaining[2..field_len],
        };
        self.remaining = self.remaining[field_len..];
        return field;
    }
};

/// Writes a compact vendor field and returns the number of bytes written.
pub fn writeCompact(output: []u8, field: Field) WriteError!usize {
    if (field.value.len > 0xff) return error.ValueTooLong;

    const field_len = 2 + field.value.len;
    if (output.len < field_len) return error.NoSpace;

    output[0] = field.code;
    output[1] = @intCast(field.value.len);
    @memcpy(output[2..field_len], field.value);
    return field_len;
}

test "compact vendor reader returns ordered fields and terminates" {
    var reader: CompactReader = .init(&.{
        0x05, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x61, 0x01, 0x09, 0xff,
    });

    const version = (try reader.next()) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(@as(u8, 0x05), version.code);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x01 }, version.value);

    const radius_type = (try reader.next()) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqual(@as(u8, 0x61), radius_type.code);
    try std.testing.expectEqualSlices(u8, &.{0x09}, radius_type.value);

    try std.testing.expectEqual(@as(?Field, null), try reader.next());
}

test "compact vendor reader distinguishes truncated headers and values" {
    var header_reader: CompactReader = .init(&.{0x05});
    try std.testing.expectError(error.TruncatedHeader, header_reader.next());

    var value_reader: CompactReader = .init(&.{ 0x05, 0x04, 0x00 });
    try std.testing.expectError(error.TruncatedValue, value_reader.next());
}

test "compact vendor reader accepts either terminator" {
    inline for ([_]u8{ 0x00, 0xff }) |terminator| {
        var reader: CompactReader = .init(&.{terminator});
        try std.testing.expectEqual(@as(?Field, null), try reader.next());
    }
}

test "compact vendor writer encodes a field" {
    var output: [7]u8 = undefined;
    const written = try writeCompact(&output, .{
        .code = 0x05,
        .value = &.{ 0x00, 0x00, 0x00, 0x01 },
    });

    try std.testing.expectEqual(@as(usize, 6), written);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x04, 0x00, 0x00, 0x00, 0x01 },
        output[0..written],
    );
}

test "compact vendor writer rejects oversized values and short buffers" {
    const oversized = @as([256]u8, @splat(0));
    try std.testing.expectError(
        error.ValueTooLong,
        writeCompact(&.{}, .{ .code = 1, .value = &oversized }),
    );

    var output: [3]u8 = undefined;
    try std.testing.expectError(
        error.NoSpace,
        writeCompact(&output, .{ .code = 1, .value = &.{ 0xaa, 0xbb } }),
    );
}
