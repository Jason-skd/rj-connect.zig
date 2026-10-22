const std = @import("std");
const wire = @import("wire.zig");

pub const encoded_size = 23;

pub const Ipv4 = [4]u8;

pub const LegacyDhcpInfo = struct {
    dhcp_enabled: bool,
    ip: Ipv4,
    netmask: Ipv4,
    gateway: Ipv4,
    dns: Ipv4,
};

pub const DecodeError = error{
    InvalidVendor,
    InvalidChecksum,
};

/// Encodes the fixed DHCP information block used by the legacy EAP-MD5 path.
pub fn encode(info: LegacyDhcpInfo, output: *[encoded_size]u8) void {
    output.* = @splat(0);
    output[0..4].* = .{ 0x00, 0x00, 0x13, 0x11 };
    output[4] = @intFromBool(info.dhcp_enabled);
    output[5..9].* = info.ip;
    output[9..13].* = info.netmask;
    output[13..17].* = info.gateway;
    output[17..21].* = info.dns;

    const checksum = wire.crc16(output[0..21]);
    output[21] = @truncate(checksum >> 8);
    output[22] = @truncate(checksum);
}

/// Decodes and validates the legacy EAP-MD5 DHCP information block.
pub fn decode(encoded: *const [encoded_size]u8) DecodeError!LegacyDhcpInfo {
    if (!std.mem.eql(u8, encoded[0..4], &.{ 0x00, 0x00, 0x13, 0x11 })) {
        return error.InvalidVendor;
    }

    const expected_checksum = (@as(u16, encoded[21]) << 8) | encoded[22];
    if (wire.crc16(encoded[0..21]) != expected_checksum) {
        return error.InvalidChecksum;
    }

    return .{
        .dhcp_enabled = encoded[4] != 0,
        .ip = encoded[5..9].*,
        .netmask = encoded[9..13].*,
        .gateway = encoded[13..17].*,
        .dns = encoded[17..21].*,
    };
}

test "legacy DHCP information encodes fields and trailing CRC" {
    var encoded: [encoded_size]u8 = undefined;
    encode(.{
        .dhcp_enabled = true,
        .ip = .{ 192, 0, 2, 10 },
        .netmask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 0, 2, 1 },
        .dns = .{ 203, 0, 113, 53 },
    }, &encoded);

    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x13, 0x11,
        0x01, 0xc0, 0x00, 0x02,
        0x0a, 0xff, 0xff, 0xff,
        0x00, 0xc0, 0x00, 0x02,
        0x01, 0xcb, 0x00, 0x71,
        0x35, 0x90, 0xee,
    }, &encoded);
}

test "legacy DHCP information decodes a valid block" {
    const encoded = [encoded_size]u8{
        0x00, 0x00, 0x13, 0x11,
        0x01, 0xc0, 0x00, 0x02,
        0x0a, 0xff, 0xff, 0xff,
        0x00, 0xc0, 0x00, 0x02,
        0x01, 0xcb, 0x00, 0x71,
        0x35, 0x90, 0xee,
    };
    const info = try decode(&encoded);

    try std.testing.expect(info.dhcp_enabled);
    try std.testing.expectEqual(@as(Ipv4, .{ 192, 0, 2, 10 }), info.ip);
    try std.testing.expectEqual(@as(Ipv4, .{ 255, 255, 255, 0 }), info.netmask);
    try std.testing.expectEqual(@as(Ipv4, .{ 192, 0, 2, 1 }), info.gateway);
    try std.testing.expectEqual(@as(Ipv4, .{ 203, 0, 113, 53 }), info.dns);
}

test "legacy DHCP information rejects invalid framing and checksum" {
    var encoded = [encoded_size]u8{
        0x00, 0x00, 0x13, 0x11,
        0x00, 192,  0,    2,
        10,   255,  255,  255,
        0,    192,  0,    2,
        1,    203,  0,    113,
        53,   0,    0,
    };
    encode(.{
        .dhcp_enabled = false,
        .ip = .{ 192, 0, 2, 10 },
        .netmask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 0, 2, 1 },
        .dns = .{ 203, 0, 113, 53 },
    }, &encoded);

    encoded[0] = 0xff;
    try std.testing.expectError(error.InvalidVendor, decode(&encoded));

    encoded[0] = 0x00;
    encoded[22] ^= 0x01;
    try std.testing.expectError(error.InvalidChecksum, decode(&encoded));
}
