//! Session-independent inner EAP framing used inside a protected tunnel.

const std = @import("std");

pub const header_size = 4;

pub const Code = enum(u8) {
    request = 1,
    response = 2,
    success = 3,
    failure = 4,
    _,
};

pub const Type = enum(u8) {
    identity = 1,
    notification = 2,
    legacy_nak = 3,
    md5_challenge = 4,
    credential = 7,
    peap = 25,
    mschapv2 = 26,
    _,
};

pub const Packet = struct {
    code: Code,
    identifier: u8,
    type: ?Type,
    data: []const u8,
    encoded_len: usize,
};

pub const DecodeError = error{
    TruncatedHeader,
    InvalidLength,
    MissingType,
    UnexpectedType,
    UnsupportedCode,
};

pub const EncodeError = error{
    LengthTooLarge,
    OutputTooSmall,
    MissingType,
    UnexpectedType,
    UnsupportedCode,
};

pub fn decodePrefix(input: []const u8) DecodeError!Packet {
    if (input.len < header_size) return error.TruncatedHeader;
    const length = std.mem.readInt(u16, input[2..4], .big);
    if (length < header_size or length > input.len) return error.InvalidLength;

    const code: Code = @fromBackingInt(@intCast(input[0]));
    const has_type = switch (code) {
        .request, .response => true,
        .success, .failure => false,
        else => return error.UnsupportedCode,
    };
    if (has_type and length < 5) return error.MissingType;
    if (!has_type and length != header_size) return error.UnexpectedType;

    return .{
        .code = code,
        .identifier = input[1],
        .type = if (has_type) @as(Type, @fromBackingInt(@intCast(input[4]))) else null,
        .data = if (has_type) input[5..length] else &.{},
        .encoded_len = length,
    };
}

pub fn encodedSize(data_len: usize, with_type: bool) EncodeError!usize {
    const length = std.math.add(usize, header_size + @as(usize, @intFromBool(with_type)), data_len) catch
        return error.LengthTooLarge;
    if (length > std.math.maxInt(u16)) return error.LengthTooLarge;
    return length;
}

pub fn encode(
    code: Code,
    identifier: u8,
    eap_type: ?Type,
    data: []const u8,
    output: []u8,
) EncodeError![]const u8 {
    const has_type = switch (code) {
        .request, .response => true,
        .success, .failure => false,
        else => return error.UnsupportedCode,
    };
    if (has_type and eap_type == null) return error.MissingType;
    if (!has_type and eap_type != null) return error.UnexpectedType;

    const required = try encodedSize(data.len, has_type);
    if (output.len < required) return error.OutputTooSmall;

    output[0] = @backingInt(code);
    output[1] = identifier;
    std.mem.writeInt(u16, output[2..4], @intCast(required), .big);
    var offset: usize = header_size;
    if (eap_type) |value| {
        output[offset] = @backingInt(value);
        offset += 1;
    }
    @memcpy(output[offset..required], data);
    return output[0..required];
}

test "inner EAP decodes one packet and reports its encoded length" {
    const encoded = [_]u8{
        2,    0x17, 0, 8, 26, 1, 2, 3,
        0xaa, 0xbb,
    };
    const packet = try decodePrefix(&encoded);

    try std.testing.expectEqual(Code.response, packet.code);
    try std.testing.expectEqual(@as(u8, 0x17), packet.identifier);
    try std.testing.expectEqual(@as(?Type, .mschapv2), packet.type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, packet.data);
    try std.testing.expectEqual(@as(usize, 8), packet.encoded_len);
}

test "inner EAP encodes requests, responses and terminal packets" {
    var output: [16]u8 = undefined;
    const request = try encode(.request, 7, .identity, "", &output);
    try std.testing.expectEqualSlices(u8, &.{ 1, 7, 0, 5, 1 }, request);

    const success = try encode(.success, 8, null, "", &output);
    try std.testing.expectEqualSlices(u8, &.{ 3, 8, 0, 4 }, success);
}

test "inner EAP rejects malformed framing" {
    try std.testing.expectError(error.TruncatedHeader, decodePrefix(&.{ 1, 2, 0 }));
    try std.testing.expectError(error.InvalidLength, decodePrefix(&.{ 1, 2, 0, 3 }));
    try std.testing.expectError(error.InvalidLength, decodePrefix(&.{ 1, 2, 0, 7, 1 }));
    try std.testing.expectError(error.MissingType, decodePrefix(&.{ 1, 2, 0, 4 }));
    try std.testing.expectError(error.UnexpectedType, decodePrefix(&.{ 3, 2, 0, 5, 1 }));
    try std.testing.expectError(error.UnsupportedCode, decodePrefix(&.{ 9, 2, 0, 4 }));

    var output: [8]u8 = undefined;
    try std.testing.expectError(error.MissingType, encode(.request, 1, null, "", &output));
    try std.testing.expectError(error.UnexpectedType, encode(.success, 1, .identity, "", &output));
    try std.testing.expectError(error.OutputTooSmall, encode(.request, 1, .identity, "x", output[0..5]));
}
