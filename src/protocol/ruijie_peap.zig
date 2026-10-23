//! Ruijie compact fields used inside a PEAPv0 tunnel.

const std = @import("std");
const crypto = @import("crypto.zig");
const vendor = @import("vendor.zig");

pub const password_start = [16]u8{
    '!', 'j', 'i', 'e', 'r', 'u', 'i', '9',
    '0', '0', '2', 'p', 'm', 's', 'u', 's',
};

pub const RadiusType = enum(u8) {
    sam = 9,
    smp = 5,
};

pub const ClientFields = struct {
    program_name_gbk: []const u8,
    client_version: [4]u8,
    ipv4: ?[4]u8 = null,
    netmask: ?[4]u8 = null,
    gateway: ?[4]u8 = null,
    dns: ?[4]u8 = null,
    dhcp_enabled: bool = false,
    source_mac: [6]u8,
    dhcp_phase: u8 = 0,
    ipv6_aux_state: ?u8 = null,
    ipv6_addresses: [3]?[16]u8 = .{ null, null, null },
    service_name_gbk: []const u8 = &.{},
    alternate_dns: []const u8 = &.{},
    username_gbk: []const u8,
    password_gbk: []const u8,
    v3_digest: [128]u8,
    disk_serial_ascii: []const u8 = &.{},
    security_domain_ascii: []const u8 = &.{},
    security_check_ok: bool = true,
    ipd_result: []const u8 = &.{},
    direct_max_version: u8 = 2,
};

pub const BuildError = error{
    InvalidField,
    OutputTooSmall,
};

pub fn encodedSize(info: ClientFields) BuildError!usize {
    const encrypted_len = crypto.passwordCiphertextSize(info.password_gbk.len);
    if (info.program_name_gbk.len > 32 or
        info.service_name_gbk.len > 32 or
        info.alternate_dns.len > 247 or
        info.disk_serial_ascii.len > 64 or
        info.security_domain_ascii.len > 255 or
        info.ipd_result.len > 255 or
        info.username_gbk.len == 0 or
        info.username_gbk.len > 255 or
        encrypted_len > 255)
    {
        return error.InvalidField;
    }

    var total: usize = 0;
    total += fieldSize(36); // client version
    total += fieldSize(17); // IPv4 information
    total += fieldSize(6); // source MAC
    total += fieldSize(1); // DHCP authentication phase
    if (info.ipv6_aux_state != null) total += fieldSize(1);
    for (info.ipv6_addresses) |address| {
        if (address != null) total += fieldSize(16);
    }
    if (info.service_name_gbk.len != 0) total += fieldSize(info.service_name_gbk.len);
    if (info.alternate_dns.len != 0) total += fieldSize(info.alternate_dns.len);
    total += fieldSize(encrypted_len);
    total += fieldSize(128);
    if (info.disk_serial_ascii.len != 0) total += fieldSize(info.disk_serial_ascii.len);
    if (info.security_domain_ascii.len != 0) total += fieldSize(info.security_domain_ascii.len);
    total += fieldSize(1);
    if (info.ipd_result.len != 0) total += fieldSize(info.ipd_result.len);
    total += fieldSize(1);
    return total;
}

pub fn buildClientFields(info: ClientFields, output: []u8) BuildError![]const u8 {
    const required = try encodedSize(info);
    if (output.len < required) return error.OutputTooSmall;

    var writer = Writer{ .output = output };

    var version_value: [36]u8 = @splat(0);
    @memcpy(version_value[0..info.program_name_gbk.len], info.program_name_gbk);
    @memcpy(version_value[32..36], &info.client_version);
    try writer.field(0x11, &version_value);

    var ipv4: [17]u8 = @splat(0);
    if (info.ipv4) |value| @memcpy(ipv4[0..4], &value);
    if (info.netmask) |value| @memcpy(ipv4[4..8], &value);
    if (info.gateway) |value| @memcpy(ipv4[8..12], &value);
    if (info.dns) |value| @memcpy(ipv4[12..16], &value);
    ipv4[16] = @intFromBool(info.dhcp_enabled);
    try writer.field(0x50, &ipv4);

    try writer.field(0x2d, &info.source_mac);
    try writer.field(0x63, &.{info.dhcp_phase});

    if (info.ipv6_aux_state) |value| try writer.field(0x35, &.{value});
    const ipv6_codes = [_]u8{ 0x36, 0x38, 0x4e };
    for (ipv6_codes, info.ipv6_addresses) |code, address| {
        if (address) |value| try writer.field(code, &value);
    }

    if (info.service_name_gbk.len != 0) try writer.field(0x39, info.service_name_gbk);
    if (info.alternate_dns.len != 0) try writer.field(0x76, info.alternate_dns);

    const encrypted_len = crypto.passwordCiphertextSize(info.password_gbk.len);
    const password = writer.take(encrypted_len);
    _ = crypto.encryptPassword(
        info.username_gbk,
        password_start,
        info.password_gbk,
        password,
    ) catch return error.InvalidField;

    try writer.field(0x60, &info.v3_digest);
    if (info.disk_serial_ascii.len != 0) try writer.field(0x54, info.disk_serial_ascii);
    if (info.security_domain_ascii.len != 0) try writer.field(0x55, info.security_domain_ascii);
    try writer.field(0x62, &.{@intFromBool(info.security_check_ok)});
    if (info.ipd_result.len != 0) try writer.field(0x64, info.ipd_result);
    try writer.field(0x79, &.{info.direct_max_version});
    return writer.output[0..writer.offset];
}

pub const ServerInfo = struct {
    reauth_interval_seconds: ?u32 = null,
    heartbeat_interval_seconds: ?u32 = null,
    direct_udp_port: ?u16 = null,
    direct_ipv4: ?[4]u8 = null,
    des_key: ?[8]u8 = null,
    initial_iv: ?[8]u8 = null,
    server_utc: ?u64 = null,
    radius_type: ?RadiusType = null,
    local_udp_port: ?u16 = null,
    direct_max_version: ?u8 = null,
    heartbeat_flags: ?u32 = null,
};

pub const ParseError = error{
    TruncatedHeader,
    TruncatedValue,
    InvalidFieldLength,
    InvalidRadiusType,
    InvalidPort,
};

pub fn parseServerInfo(input: []const u8) ParseError!ServerInfo {
    var result: ServerInfo = .{};
    var reader = vendor.CompactReader.init(input);
    while (reader.next() catch |err| switch (err) {
        error.TruncatedHeader => return error.TruncatedHeader,
        error.TruncatedValue => return error.TruncatedValue,
    }) |field| {
        switch (field.code) {
            0x56 => result.reauth_interval_seconds = try readU32(field.value),
            0x59 => result.heartbeat_interval_seconds = try readU32(field.value),
            0x5a => result.direct_udp_port = try readPort(field.value),
            0x5b => result.direct_ipv4 = try readIpv4(field.value),
            0x5c => result.des_key = try decryptKey(field.value),
            0x5d => result.initial_iv = try decryptKey(field.value),
            0x5e => result.server_utc = try readU64(field.value),
            0x61 => {
                if (field.value.len != 1) return error.InvalidFieldLength;
                result.radius_type = switch (field.value[0]) {
                    9 => .sam,
                    5 => .smp,
                    else => return error.InvalidRadiusType,
                };
            },
            0x6e => result.local_udp_port = try readPort(field.value),
            0x79 => {
                if (field.value.len != 1) return error.InvalidFieldLength;
                result.direct_max_version = field.value[0];
            },
            0x80 => result.heartbeat_flags = try readU32(field.value),
            else => {},
        }
    }
    return result;
}

pub fn mergeServerInfo(current: ServerInfo, update: ServerInfo) ServerInfo {
    var result = current;
    inline for (@typeInfo(ServerInfo).@"struct".field_names) |field_name| {
        if (@field(update, field_name)) |value| {
            @field(result, field_name) = value;
        }
    }
    return result;
}

const Writer = struct {
    output: []u8,
    offset: usize = 0,

    fn field(self: *Writer, code: u8, value: []const u8) BuildError!void {
        const start = try self.reserve(fieldSize(value.len));
        _ = vendor.writeCompact(self.output[start..], .{ .code = code, .value = value }) catch
            return error.OutputTooSmall;
    }

    fn take(self: *Writer, len: usize) []u8 {
        const start = self.offset;
        self.offset += 2 + len;
        self.output[start] = 0x5f;
        self.output[start + 1] = @intCast(len);
        return self.output[start + 2 .. self.offset];
    }

    fn reserve(self: *Writer, len: usize) BuildError!usize {
        const start = self.offset;
        if (self.output.len - start < len) return error.OutputTooSmall;
        self.offset += len;
        return start;
    }
};

fn fieldSize(value_len: usize) usize {
    return 2 + value_len;
}

fn readU32(value: []const u8) ParseError!u32 {
    if (value.len != 4) return error.InvalidFieldLength;
    return std.mem.readInt(u32, value[0..4], .big);
}

fn readU64(value: []const u8) ParseError!u64 {
    if (value.len != 8) return error.InvalidFieldLength;
    return std.mem.readInt(u64, value[0..8], .big);
}

fn readPort(value: []const u8) ParseError!u16 {
    const port = try readU32(value);
    return std.math.cast(u16, port) orelse error.InvalidPort;
}

fn readIpv4(value: []const u8) ParseError![4]u8 {
    if (value.len != 4) return error.InvalidFieldLength;
    return value[0..4].*;
}

fn decryptKey(value: []const u8) ParseError![8]u8 {
    if (value.len != 8) return error.InvalidFieldLength;
    var result: [8]u8 = undefined;
    _ = crypto.applyRc4("com.ruijie.www", value, &result) catch unreachable;
    return result;
}

test "PEAP compact fields follow the original order and fixed password start" {
    const digest: [128]u8 = @splat('a');
    const info: ClientFields = .{
        .program_name_gbk = "8021x.exe",
        .client_version = .{ 1, 33, 1, 2 },
        .ipv4 = .{ 192, 0, 2, 10 },
        .netmask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 0, 2, 1 },
        .dns = .{ 203, 0, 113, 53 },
        .dhcp_enabled = true,
        .source_mac = .{ 0, 17, 34, 51, 68, 85 },
        .username_gbk = "alice",
        .password_gbk = "secret",
        .v3_digest = digest,
    };

    var output: [2048]u8 = undefined;
    const encoded = try buildClientFields(info, &output);
    var reader = vendor.CompactReader.init(encoded);

    const version = (try reader.next()).?;
    try std.testing.expectEqual(@as(u8, 0x11), version.code);
    try std.testing.expectEqual(@as(usize, 36), version.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 33, 1, 2 }, version.value[32..36]);

    const ipv4 = (try reader.next()).?;
    try std.testing.expectEqual(@as(u8, 0x50), ipv4.code);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, ipv4.value[0..4]);
    try std.testing.expectEqual(@as(u8, 1), ipv4.value[16]);

    const mac = (try reader.next()).?;
    try std.testing.expectEqual(@as(u8, 0x2d), mac.code);
    const phase = (try reader.next()).?;
    try std.testing.expectEqual(@as(u8, 0x63), phase.code);

    const password = (try reader.next()).?;
    try std.testing.expectEqual(@as(u8, 0x5f), password.code);
    var expected: [16]u8 = undefined;
    _ = try crypto.encryptPassword("alice", password_start, "secret", &expected);
    try std.testing.expectEqualSlices(u8, &expected, password.value);

    const v3 = (try reader.next()).?;
    try std.testing.expectEqual(@as(u8, 0x60), v3.code);
    try std.testing.expectEqualSlices(u8, &digest, v3.value);
}

test "server compact fields parse and atomically expose Direct parameters" {
    var fields: [64]u8 = undefined;
    var offset: usize = 0;
    offset += try vendor.writeCompact(fields[offset..], .{
        .code = 0x56,
        .value = &.{ 0, 0, 0, 30 },
    });
    offset += try vendor.writeCompact(fields[offset..], .{
        .code = 0x5a,
        .value = &.{ 0, 0, 0x1f, 0x90 },
    });
    offset += try vendor.writeCompact(fields[offset..], .{
        .code = 0x5b,
        .value = &.{ 192, 0, 2, 1 },
    });
    const encrypted_key = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    offset += try vendor.writeCompact(fields[offset..], .{ .code = 0x5c, .value = &encrypted_key });
    offset += try vendor.writeCompact(fields[offset..], .{ .code = 0x61, .value = &.{9} });
    offset += try vendor.writeCompact(fields[offset..], .{ .code = 0x79, .value = &.{2} });
    fields[offset] = 0xff;
    offset += 1;

    const parsed = try parseServerInfo(fields[0..offset]);
    try std.testing.expectEqual(@as(?u32, 30), parsed.reauth_interval_seconds);
    try std.testing.expectEqual(@as(?u16, 8080), parsed.direct_udp_port);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &parsed.direct_ipv4.?);
    try std.testing.expectEqual(RadiusType.sam, parsed.radius_type.?);
    try std.testing.expectEqual(@as(?u8, 2), parsed.direct_max_version);

    var expected_key: [8]u8 = undefined;
    _ = try crypto.applyRc4("com.ruijie.www", &encrypted_key, &expected_key);
    try std.testing.expectEqualSlices(u8, &expected_key, &parsed.des_key.?);
}

test "server compact fields reject malformed known fields" {
    try std.testing.expectError(
        error.InvalidFieldLength,
        parseServerInfo(&.{ 0x5a, 3, 0, 0, 1 }),
    );
    try std.testing.expectError(
        error.InvalidPort,
        parseServerInfo(&.{ 0x5a, 4, 0, 1, 0, 0 }),
    );
    try std.testing.expectError(
        error.InvalidRadiusType,
        parseServerInfo(&.{ 0x61, 1, 7 }),
    );
    try std.testing.expectError(
        error.TruncatedValue,
        parseServerInfo(&.{ 0x56, 4, 0, 0 }),
    );
}
