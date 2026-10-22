//! SMP business payload codecs.

const std = @import("std");

pub const hello_command: u8 = 0x23;
pub const user_info_command: u8 = 0x2d;
pub const dhcp_result_command: u8 = 0x2e;

pub const Error = error{
    OutputTooSmall,
    InvalidLength,
    InvalidTlv,
    UnsupportedVersion,
};

pub const UserInfo = struct {
    username_gbk: []const u8,
    ipv4: [4]u8,
    netmask: [4]u8,
    gateway: [4]u8,
    dns: [4]u8,
    alternate_dns: ?[4]u8,
    mac: [6]u8,
};

pub const DhcpAuthResult = struct {
    success: bool,
    message_gbk: []const u8,
};

pub fn helloSize(username_len: usize, session_parameter_len: usize) usize {
    return 4 + 3 + username_len + 3 + session_parameter_len;
}

pub fn encodeHello(
    username_gbk: []const u8,
    session_parameter: []const u8,
    output: []u8,
) Error![]const u8 {
    if (username_gbk.len > std.math.maxInt(u16) or
        session_parameter.len > std.math.maxInt(u16))
    {
        return error.InvalidLength;
    }
    const required = helloSize(username_gbk.len, session_parameter.len);
    if (output.len < required) return error.OutputTooSmall;

    output[0..4].* = .{ 1, 0, 1, hello_command };
    var offset: usize = 4;
    offset = try appendTlv(output, offset, 0x02, username_gbk);
    offset = try appendTlv(output, offset, 0x03, session_parameter);
    return output[0..offset];
}

pub fn userInfoSize(info: UserInfo) usize {
    return 4 + 3 + info.username_gbk.len + 3 + info.ipv4.len + 3 + info.netmask.len +
        3 + info.gateway.len + 3 + info.dns.len + 3 + info.mac.len +
        @as(usize, if (info.alternate_dns == null) 0 else 3 + 4);
}

pub fn encodeUserInfo(info: UserInfo, output: []u8) Error![]const u8 {
    if (info.username_gbk.len > std.math.maxInt(u16)) return error.InvalidLength;
    const required = userInfoSize(info);
    if (output.len < required) return error.OutputTooSmall;

    output[0..4].* = .{ 1, 0, 1, user_info_command };
    var offset: usize = 4;
    offset = try appendTlv(output, offset, 0x03, info.username_gbk);
    offset = try appendTlv(output, offset, 0xc9, &info.ipv4);
    offset = try appendTlv(output, offset, 0xca, &info.netmask);
    offset = try appendTlv(output, offset, 0xcb, &info.gateway);
    offset = try appendTlv(output, offset, 0xcc, &info.dns);
    offset = try appendTlv(output, offset, 0xcd, &info.mac);
    if (info.alternate_dns) |dns| {
        offset = try appendTlv(output, offset, 0xd3, &dns);
    }
    return output[0..offset];
}

pub fn command(payload: []const u8) Error!u8 {
    if (payload.len < 4) return error.InvalidLength;
    if (payload[0] != 1 or std.mem.readInt(u16, payload[1..3], .big) != 1) {
        return error.UnsupportedVersion;
    }
    return payload[3];
}

pub fn isHello(payload: []const u8) bool {
    const value = command(payload) catch return false;
    if (value != hello_command) return false;

    var offset: usize = 4;
    var has_tlv = false;
    while (offset < payload.len) {
        if (allZero(payload[offset..])) break;
        if (payload.len - offset < 3) return false;
        const length: usize = std.mem.readInt(u16, payload[offset + 1 ..][0..2], .big);
        offset += 3;
        if (length > payload.len - offset) return false;
        has_tlv = true;
        offset += length;
    }
    return has_tlv;
}

/// Returns null when the payload is not a DHCP authentication result.
pub fn parseDhcpAuthResult(payload: []const u8) Error!?DhcpAuthResult {
    if (try command(payload) != dhcp_result_command) return null;

    var success = false;
    var message: []const u8 = &.{};
    var offset: usize = 4;
    while (offset < payload.len) {
        if (allZero(payload[offset..])) break;
        if (offset + 3 > payload.len) return error.InvalidTlv;
        const code = payload[offset];
        const length: usize = std.mem.readInt(u16, payload[offset + 1 ..][0..2], .big);
        offset += 3;
        if (offset + length > payload.len) return error.InvalidTlv;
        const value = payload[offset..][0..length];
        offset += length;
        switch (code) {
            0xce => {
                if (length != 1) return error.InvalidLength;
                success = value[0] != 0;
            },
            0xcf => message = value,
            else => {},
        }
    }
    return .{ .success = success, .message_gbk = message };
}

fn appendTlv(output: []u8, offset: usize, code: u8, value: []const u8) Error!usize {
    if (value.len > std.math.maxInt(u16)) return error.InvalidLength;
    if (offset + 3 + value.len > output.len) return error.OutputTooSmall;
    output[offset] = code;
    std.mem.writeInt(u16, output[offset + 1 ..][0..2], @intCast(value.len), .big);
    @memcpy(output[offset + 3 ..][0..value.len], value);
    return offset + 3 + value.len;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

test "SMP hello uses u16 TLV lengths" {
    var output: [64]u8 = undefined;
    const encoded = try encodeHello("alice", &.{ 1, 2, 3, 4 }, &output);
    try std.testing.expectEqualSlices(u8, &.{
        1,    0,   1,   0x23,
        0x02, 0,   5,   'a',
        'l',  'i', 'c', 'e',
        0x03, 0,   4,   1,
        2,    3,   4,
    }, encoded);
}

test "SMP user information encodes address TLVs" {
    var output: [128]u8 = undefined;
    const encoded = try encodeUserInfo(.{
        .username_gbk = "alice",
        .ipv4 = .{ 192, 0, 2, 10 },
        .netmask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 0, 2, 1 },
        .dns = .{ 203, 0, 113, 53 },
        .alternate_dns = .{ 198, 51, 100, 53 },
        .mac = .{ 0, 1, 2, 3, 4, 5 },
    }, &output);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0, 1, 0x2d }, encoded[0..4]);
    try std.testing.expectEqualSlices(u8, &.{ 0xc9, 0, 4, 192, 0, 2, 10 }, encoded[12..19]);
    try std.testing.expectEqualSlices(u8, &.{ 0xd3, 0, 4, 198, 51, 100, 53 }, encoded[encoded.len - 7 ..]);
}

test "SMP DHCP result normalizes success and message" {
    const payload = [_]u8{
        1,    0, 1, 0x2e,
        0xce, 0, 1, 1,
        0xcf, 0, 2, 'o',
        'k',
    };
    const result = (try parseDhcpAuthResult(&payload)).?;
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("ok", result.message_gbk);
}

test "SMP codec rejects malformed framing" {
    const wrong_version = [_]u8{ 2, 0, 1, 0x23 };
    try std.testing.expectError(error.UnsupportedVersion, command(&wrong_version));

    const truncated = [_]u8{ 1, 0, 1, 0x2e, 0xce, 0, 2, 1 };
    try std.testing.expectError(error.InvalidTlv, parseDhcpAuthResult(&truncated));
}

test "SMP hello requires a complete business TLV" {
    try std.testing.expect(!isHello(&.{ 1, 0, 1, hello_command }));
    try std.testing.expect(!isHello(&.{
        1,
        0,
        1,
        hello_command,
        0x02,
        0,
        4,
        'x',
    }));
    try std.testing.expect(isHello(&.{
        1,
        0,
        1,
        hello_command,
        0x02,
        0,
        1,
        'x',
        0,
    }));
}
