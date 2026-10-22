const std = @import("std");

pub const vendor_id: u32 = 0x0000_1311;

/// Decodes one byte from the protected fixed block carried by EAP-MD5.
pub fn decodePropertyByte(encoded: u8) u8 {
    return @bitReverse(encoded ^ 0xff);
}

/// Applies the inverse transform used when placing a fixed block on the wire.
pub fn encodePropertyByte(decoded: u8) u8 {
    return decodePropertyByte(decoded);
}

/// Computes the CRC-16/CCITT variant used by the legacy DHCP information block.
pub fn crc16(bytes: []const u8) u16 {
    var crc: u16 = 0;
    for (bytes) |byte| {
        crc ^= @as(u16, byte) << 8;
        for (0..8) |_| {
            crc = if (crc & 0x8000 != 0)
                (crc << 1) ^ 0x1021
            else
                crc << 1;
        }
    }
    return crc;
}

test "property byte decode removes complement and bit reversal" {
    try std.testing.expectEqual(@as(u8, 0x00), decodePropertyByte(0xff));
    try std.testing.expectEqual(@as(u8, 0x01), decodePropertyByte(0x7f));
    try std.testing.expectEqual(@as(u8, 0x0f), decodePropertyByte(0x0f));
}

test "property byte encode is the inverse of decode" {
    const values = [_]u8{ 0x00, 0x01, 0x0f, 0x7f, 0x80, 0xff };
    for (values) |value| {
        try std.testing.expectEqual(value, encodePropertyByte(decodePropertyByte(value)));
        try std.testing.expectEqual(value, decodePropertyByte(encodePropertyByte(value)));
    }
}

test "DHCP block CRC matches the CCITT known answer" {
    try std.testing.expectEqual(@as(u16, 0x31c3), crc16("123456789"));
}
