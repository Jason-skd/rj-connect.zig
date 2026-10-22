const std = @import("std");

pub const header_size = 42;

pub const Header = struct {
    version: u8,
    code: u8,
    id: u32,
    packet_len: u16,
    authenticator: [16]u8,
    session_id: u32,
    timestamp: u64,
    message_type: u8,
    flags: u8,
    total_len: u32,
};

pub const DecodeError = error{
    UnsupportedVersion,
    InvalidPacketLength,
};

pub const AuthError = error{
    PacketTooShort,
};

/// Encodes the fixed header used before an encrypted SAM/SMP payload.
pub fn encodeHeader(header: Header, output: *[header_size]u8) void {
    output.* = @splat(0);
    output[0] = header.version;
    output[1] = header.code;
    std.mem.writeInt(u32, output[2..6], header.id, .big);
    std.mem.writeInt(u16, output[6..8], header.packet_len, .big);
    output[8..24].* = header.authenticator;
    std.mem.writeInt(u32, output[24..28], header.session_id, .big);
    std.mem.writeInt(u64, output[28..36], header.timestamp, .big);
    output[36] = header.message_type;
    output[37] = header.flags;
    std.mem.writeInt(u32, output[38..42], header.total_len, .big);
}

/// Decodes the fixed header and validates its framing fields.
pub fn decodeHeader(encoded: *const [header_size]u8) DecodeError!Header {
    if (encoded[0] != 1) return error.UnsupportedVersion;

    const packet_len = std.mem.readInt(u16, encoded[6..8], .big);
    if (packet_len < header_size) return error.InvalidPacketLength;

    return .{
        .version = encoded[0],
        .code = encoded[1],
        .id = std.mem.readInt(u32, encoded[2..6], .big),
        .packet_len = packet_len,
        .authenticator = encoded[8..24].*,
        .session_id = std.mem.readInt(u32, encoded[24..28], .big),
        .timestamp = std.mem.readInt(u64, encoded[28..36], .big),
        .message_type = encoded[36],
        .flags = encoded[37],
        .total_len = std.mem.readInt(u32, encoded[38..42], .big),
    };
}

/// Computes the legacy MD5 authenticator over a zeroed header, payload, key, and IV.
pub fn computeAuthenticator(
    packet: []const u8,
    key: [8]u8,
    iv: [8]u8,
) AuthError![16]u8 {
    if (packet.len < header_size) return error.PacketTooShort;

    const Md5 = std.crypto.hash.Md5;
    var hash = Md5.init(.{});
    hash.update(packet[0..8]);
    hash.update(&@as([16]u8, @splat(0)));
    hash.update(packet[24..]);
    hash.update(&key);
    hash.update(&iv);
    return hash.finalResult();
}

/// Verifies a packet authenticator without short-circuiting on the first mismatch.
pub fn verifyAuthenticator(
    packet: []const u8,
    key: [8]u8,
    iv: [8]u8,
) AuthError!bool {
    const expected = try computeAuthenticator(packet, key, iv);
    var difference: u8 = 0;
    for (expected, packet[8..24]) |want, actual| {
        difference |= want ^ actual;
    }
    return difference == 0;
}

test "direct header preserves field order and network byte order" {
    var encoded: [header_size]u8 = undefined;
    encodeHeader(.{
        .version = 1,
        .code = 1,
        .id = 0x0102_0304,
        .packet_len = header_size,
        .authenticator = .{
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        },
        .session_id = 0x1122_3344,
        .timestamp = 0x0102_0304_0506_0708,
        .message_type = 1,
        .flags = 4,
        .total_len = 0x0a0b_0c0d,
    }, &encoded);

    try std.testing.expectEqualSlices(u8, &.{
        0x01, 0x01,
        0x01, 0x02,
        0x03, 0x04,
        0x00, 0x2a,
        0x10, 0x11,
        0x12, 0x13,
        0x14, 0x15,
        0x16, 0x17,
        0x18, 0x19,
        0x1a, 0x1b,
        0x1c, 0x1d,
        0x1e, 0x1f,
        0x11, 0x22,
        0x33, 0x44,
        0x01, 0x02,
        0x03, 0x04,
        0x05, 0x06,
        0x07, 0x08,
        0x01, 0x04,
        0x0a, 0x0b,
        0x0c, 0x0d,
    }, &encoded);
}

test "direct header decodes into the same fields" {
    const expected = Header{
        .version = 1,
        .code = 1,
        .id = 0x0102_0304,
        .packet_len = 42,
        .authenticator = .{
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        },
        .session_id = 0x1122_3344,
        .timestamp = 0x0102_0304_0506_0708,
        .message_type = 1,
        .flags = 4,
        .total_len = 0x0a0b_0c0d,
    };
    var encoded: [header_size]u8 = undefined;
    encodeHeader(expected, &encoded);

    try std.testing.expectEqual(expected, try decodeHeader(&encoded));
}

test "direct header rejects unsupported versions and impossible lengths" {
    var encoded: [header_size]u8 = @splat(0);
    encoded[0] = 2;
    std.mem.writeInt(u16, encoded[6..8], header_size, .big);
    try std.testing.expectError(error.UnsupportedVersion, decodeHeader(&encoded));

    encoded[0] = 1;
    std.mem.writeInt(u16, encoded[6..8], header_size - 1, .big);
    try std.testing.expectError(error.InvalidPacketLength, decodeHeader(&encoded));
}

test "direct authenticator hashes the packet, key, and IV" {
    var packet: [header_size + 3]u8 = undefined;
    var header: [header_size]u8 = undefined;
    encodeHeader(.{
        .version = 1,
        .code = 1,
        .id = 0x0102_0304,
        .packet_len = header_size + 3,
        .authenticator = @splat(0),
        .session_id = 0x1122_3344,
        .timestamp = 0x0102_0304_0506_0708,
        .message_type = 1,
        .flags = 4,
        .total_len = 7,
    }, &header);
    @memcpy(packet[0..header_size], &header);
    packet[header_size..].* = .{ 0xaa, 0xbb, 0xcc };

    const authenticator = try computeAuthenticator(
        &packet,
        .{ 0, 1, 2, 3, 4, 5, 6, 7 },
        .{ 8, 9, 10, 11, 12, 13, 14, 15 },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x5a, 0x04, 0xb1, 0x2c,
            0x8d, 0x43, 0xbf, 0xd7,
            0xc8, 0x77, 0xe7, 0xa7,
            0x25, 0x27, 0xe4, 0xc0,
        },
        &authenticator,
    );
}

test "direct authenticator verification rejects tampering" {
    var packet: [header_size + 1]u8 = undefined;
    var header: [header_size]u8 = undefined;
    encodeHeader(.{
        .version = 1,
        .code = 1,
        .id = 7,
        .packet_len = header_size + 1,
        .authenticator = @splat(0),
        .session_id = 9,
        .timestamp = 11,
        .message_type = 1,
        .flags = 1,
        .total_len = 1,
    }, &header);
    @memcpy(packet[0..header_size], &header);
    packet[header_size] = 0x42;

    const key = [8]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const iv = [8]u8{ 8, 9, 10, 11, 12, 13, 14, 15 };
    const authenticator = try computeAuthenticator(&packet, key, iv);
    @memcpy(packet[8..24], &authenticator);

    try std.testing.expect(try verifyAuthenticator(&packet, key, iv));
    packet[header_size] ^= 1;
    try std.testing.expect(!try verifyAuthenticator(&packet, key, iv));
}

test "direct authenticator rejects a short packet" {
    const short = @as([header_size - 1]u8, @splat(0));
    try std.testing.expectError(
        error.PacketTooShort,
        computeAuthenticator(
            &short,
            @splat(0),
            @splat(0),
        ),
    );
}
