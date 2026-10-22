//! SAM business payload codecs.

const std = @import("std");

pub const Error = error{
    OutputTooSmall,
    InvalidLength,
    InvalidTlv,
};

pub const UserInfo = struct {
    username_gbk: []const u8,
    ipv4: [4]u8,
    mac: [6]u8,
    netmask: [4]u8,
    gateway: [4]u8,
    dns: [4]u8,
};

pub const DhcpAuthResult = struct {
    success: bool,
    message_gbk: []const u8,
};

pub fn handshakeSize(username_len: usize, session_parameter_len: usize, endpoint_parameter_len: usize) usize {
    return 3 + 2 + username_len + 2 + session_parameter_len + 2 + endpoint_parameter_len;
}

pub fn encodeHandshake(
    username_gbk: []const u8,
    session_parameter: [4]u8,
    endpoint_parameter: [6]u8,
    output: []u8,
) Error![]const u8 {
    return encodeHandshakeParts(
        username_gbk,
        &session_parameter,
        &endpoint_parameter,
        output,
    );
}

pub fn encodeHandshakeParts(
    username_gbk: []const u8,
    session_parameter: []const u8,
    endpoint_parameter: []const u8,
    output: []u8,
) Error![]const u8 {
    if (username_gbk.len > 255 or session_parameter.len > 255 or endpoint_parameter.len > 255) {
        return error.InvalidLength;
    }
    const required = handshakeSize(
        username_gbk.len,
        session_parameter.len,
        endpoint_parameter.len,
    );
    if (output.len < required) return error.OutputTooSmall;

    output[0..3].* = .{ 0x01, 0x01, 0x02 };
    var offset: usize = 3;
    offset = try appendTlv(output, offset, 0x03, username_gbk);
    offset = try appendTlv(output, offset, 0x04, session_parameter);
    offset = try appendTlv(output, offset, 0x05, endpoint_parameter);
    return output[0..offset];
}

pub fn userInfoSize(info: UserInfo) usize {
    return 3 + 2 + info.username_gbk.len + 2 + info.ipv4.len + 2 + info.mac.len +
        2 + info.netmask.len + 2 + info.gateway.len + 2 + info.dns.len;
}

pub fn encodeUserInfo(info: UserInfo, output: []u8) Error![]const u8 {
    if (info.username_gbk.len > 255) return error.InvalidLength;
    const required = userInfoSize(info);
    if (output.len < required) return error.OutputTooSmall;

    output[0..3].* = .{ 0x01, 0x01, 0x08 };
    var offset: usize = 3;
    offset = try appendTlv(output, offset, 0x03, info.username_gbk);
    offset = try appendTlv(output, offset, 0x04, &info.ipv4);
    offset = try appendTlv(output, offset, 0x05, &info.mac);
    offset = try appendTlv(output, offset, 0x0b, &info.netmask);
    offset = try appendTlv(output, offset, 0x0c, &info.gateway);
    offset = try appendTlv(output, offset, 0x0d, &info.dns);
    return output[0..offset];
}

/// Returns null when the payload does not contain the DHCP result container.
pub fn parseDhcpAuthResult(payload: []const u8) Error!?DhcpAuthResult {
    var offset: usize = if (payload.len >= 3 and payload[0] == 1 and payload[1] == 1) 3 else 0;
    while (offset < payload.len) {
        if (allZero(payload[offset..])) return null;
        if (offset + 2 > payload.len) return error.InvalidTlv;
        const code = payload[offset];
        const length: usize = payload[offset + 1];
        offset += 2;
        if (offset + length > payload.len) return error.InvalidTlv;
        const value = payload[offset..][0..length];
        offset += length;
        if (code == 0x09) return try parseResultTlvs(value);
    }
    return null;
}

fn parseResultTlvs(payload: []const u8) Error!DhcpAuthResult {
    var success = false;
    var message: []const u8 = &.{};
    var offset: usize = 0;
    while (offset < payload.len) {
        if (allZero(payload[offset..])) break;
        if (offset + 2 > payload.len) return error.InvalidTlv;
        const code = payload[offset];
        const length: usize = payload[offset + 1];
        offset += 2;
        if (offset + length > payload.len) return error.InvalidTlv;
        const value = payload[offset..][0..length];
        offset += length;
        switch (code) {
            0x02 => message = value,
            0x13 => {
                if (length != 1) return error.InvalidLength;
                success = value[0] != 0;
            },
            else => {},
        }
    }
    return .{ .success = success, .message_gbk = message };
}

fn appendTlv(output: []u8, offset: usize, code: u8, value: []const u8) Error!usize {
    if (value.len > 255) return error.InvalidLength;
    if (offset + 2 + value.len > output.len) return error.OutputTooSmall;
    output[offset] = code;
    output[offset + 1] = @intCast(value.len);
    @memcpy(output[offset + 2 ..][0..value.len], value);
    return offset + 2 + value.len;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

test "SAM handshake preserves TLVs" {
    var output: [64]u8 = undefined;
    const encoded = try encodeHandshake(
        "alice",
        .{ 1, 2, 3, 4 },
        .{ 5, 6, 7, 8, 9, 10 },
        &output,
    );
    try std.testing.expectEqualSlices(u8, &.{
        1,   1,   2,
        3,   5,   'a',
        'l', 'i', 'c',
        'e', 4,   4,
        1,   2,   3,
        4,   5,   6,
        5,   6,   7,
        8,   9,   10,
    }, encoded);
}

test "SAM user information encodes required address fields" {
    var output: [128]u8 = undefined;
    const encoded = try encodeUserInfo(.{
        .username_gbk = "alice",
        .ipv4 = .{ 192, 0, 2, 10 },
        .mac = .{ 0, 1, 2, 3, 4, 5 },
        .netmask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 0, 2, 1 },
        .dns = .{ 203, 0, 113, 53 },
    }, &output);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 8 }, encoded[0..3]);
    try std.testing.expectEqualSlices(u8, &.{
        3,    5,   'a', 'l', 'i', 'c',  'e',
        4,    4,   192, 0,   2,   10,   5,
        6,    0,   1,   2,   3,   4,    5,
        0x0b, 4,   255, 255, 255, 0,    0x0c,
        4,    192, 0,   2,   1,   0x0d, 4,
        203,  0,   113, 53,
    }, encoded[3..]);
}

test "SAM DHCP result normalizes success and message" {
    const payload = [_]u8{
        1,    1,    12,
        0x22, 1,    0xff,
        0x09, 8,    0x02,
        3,    'b',  'a',
        'd',  0x13, 1,
        0,    0x55, 0,
    };
    const result = (try parseDhcpAuthResult(&payload)).?;
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("bad", result.message_gbk);

    const missing = [_]u8{ 1, 1, 8, 0x22, 1, 1 };
    try std.testing.expectEqual(@as(?DhcpAuthResult, null), try parseDhcpAuthResult(&missing));
}

test "SAM DHCP result rejects malformed TLVs" {
    const truncated_outer = [_]u8{ 0x09, 4, 0x02, 2, 'x' };
    try std.testing.expectError(error.InvalidTlv, parseDhcpAuthResult(&truncated_outer));

    const invalid_success = [_]u8{ 0x09, 4, 0x13, 2, 1, 0 };
    try std.testing.expectError(error.InvalidLength, parseDhcpAuthResult(&invalid_success));
}
