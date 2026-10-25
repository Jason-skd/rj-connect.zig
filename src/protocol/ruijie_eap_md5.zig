//! Target Ruijie EAP-MD5 framing: standard proof, private tail and terminal data.

const std = @import("std");
const dhcp = @import("dhcp.zig");
const wire = @import("wire.zig");

pub const vendor_id: u32 = 0x0000_1311;
pub const prefix_len = 70;
pub const program_name = "8021x.exe";
pub const version = [4]u8{ 1, 35, 2, 2 };
pub const release_text = "RG-SU For Mac V1.35";
pub const service_name_len = 32;
pub const disk_serial_len = 64;
pub const v3_digest_len = 128;
pub const max_chain_len = 240;
pub const max_alternate_dns_len = 247;

pub const EncodeError = error{
    OutputTooSmall,
    LengthTooLarge,
};

/// Which client frame a tail is attached to.
pub const Frame = enum { start, identity, response, logoff };

/// Inputs that vary per frame. The session resolves whether IPv6 facts or
/// zero slots are sent and whether the V3 digest or zero bytes are used.
pub const Params = struct {
    frame: Frame,
    source_mac: [6]u8,
    service_name: []const u8,
    disk_serial: []const u8,
    ipv6_state: u8,
    ipv6_link_local: [16]u8,
    ipv6_global: [16]u8,
    ipv6_third: [16]u8,
    lease: dhcp.LegacyDhcpInfo,
    alternate_dns_text: []const u8,
    os_bits: u8,
    chain: []const u8,
    v3_digest: [v3_digest_len]u8,
    security_ok: bool,
};

const attr_header = 8;

fn attrSize(value_len: usize) usize {
    return attr_header + value_len;
}

pub fn tailSize(self: Params) usize {
    var size = prefix_len + attrSize(32) + attrSize(4) + attrSize(6) + attrSize(self.chain.len);
    size += attrSize(1) + attrSize(16) + attrSize(16) + attrSize(16);
    size += attrSize(v3_digest_len);
    if (self.service_name.len != 0) size += attrSize(service_name_len);
    size += attrSize(disk_serial_len);
    if (self.alternate_dns_text.len != 0) size += attrSize(self.alternate_dns_text.len);
    size += attrSize(1) + attrSize(1) + attrSize(release_text.len + 1) + attrSize(1);
    return size;
}

/// Encodes one private tail. The returned slice is a prefix of `output`.
pub fn encodeTail(self: Params, output: []u8) EncodeError![]const u8 {
    if (self.service_name.len > service_name_len or
        self.disk_serial.len > disk_serial_len or
        self.alternate_dns_text.len > max_alternate_dns_len or
        self.chain.len > max_chain_len)
    {
        return error.LengthTooLarge;
    }
    const size = tailSize(self);
    if (output.len < size) return error.OutputTooSmall;

    writePrefix(self, output[0..prefix_len]);

    var offset: usize = prefix_len;
    const zero_32: [32]u8 = @splat(0);
    offset += writeAttribute(output[offset..], 0x17, &zero_32);
    var dhcp_flag: [4]u8 = undefined;
    std.mem.writeInt(u32, &dhcp_flag, 1, .big);
    offset += writeAttribute(output[offset..], 0x18, &dhcp_flag);
    offset += writeAttribute(output[offset..], 0x2d, &self.source_mac);
    offset += writeAttribute(output[offset..], 0x2f, self.chain);

    const state = [_]u8{self.ipv6_state};
    offset += writeAttribute(output[offset..], 0x35, &state);
    offset += writeAttribute(output[offset..], 0x36, &self.ipv6_third);
    offset += writeAttribute(output[offset..], 0x38, &self.ipv6_link_local);
    offset += writeAttribute(output[offset..], 0x4e, &self.ipv6_global);
    offset += writeAttribute(output[offset..], 0x4d, &self.v3_digest);

    if (self.service_name.len != 0) {
        var service: [service_name_len]u8 = @splat(0);
        @memcpy(service[0..self.service_name.len], self.service_name);
        offset += writeAttribute(output[offset..], 0x39, &service);
    }

    var serial: [disk_serial_len]u8 = @splat(0);
    @memcpy(serial[0..self.disk_serial.len], self.disk_serial);
    offset += writeAttribute(output[offset..], 0x54, &serial);

    if (self.alternate_dns_text.len != 0) {
        offset += writeAttribute(output[offset..], 0x76, self.alternate_dns_text);
    }

    const security = [_]u8{@intFromBool(self.security_ok)};
    offset += writeAttribute(output[offset..], 0x62, &security);
    const os_bits = [_]u8{self.os_bits};
    offset += writeAttribute(output[offset..], 0x70, &os_bits);
    offset += writeAttribute(output[offset..], 0x6f, release_text ++ "\x00");
    const max_direct_version = [_]u8{2};
    offset += writeAttribute(output[offset..], 0x79, &max_direct_version);

    std.debug.assert(offset == size);
    return output[0..offset];
}

fn writePrefix(self: Params, output: []u8) void {
    var block: [dhcp.encoded_size]u8 = undefined;
    dhcp.encode(self.lease, &block);
    for (block, 0..) |byte, index| output[index] = wire.encodePropertyByte(byte);

    const vendor = [4]u8{ 0x00, 0x00, 0x13, 0x11 };
    @memcpy(output[23..27], &vendor);
    @memset(output[27..59], 0);
    @memcpy(output[27 .. 27 + program_name.len], program_name);
    @memcpy(output[59..63], &version);
    output[63] = if (self.frame == .logoff) 1 else 0;
    @memcpy(output[64..68], &vendor);
    output[68] = 0x01;
    output[69] = 0xf0;
}

fn writeAttribute(output: []u8, code: u8, value: []const u8) usize {
    const total = attrSize(value.len);
    output[0] = 0x1a;
    output[1] = @intCast(total);
    output[2] = 0x00;
    output[3] = 0x00;
    output[4] = 0x13;
    output[5] = 0x11;
    output[6] = code;
    output[7] = @intCast(2 + value.len);
    @memcpy(output[8 .. 8 + value.len], value);
    return total;
}

/// Standard EAP-MD5 proof: `MD5(identifier || password || challenge)`.
pub fn proof(identifier: u8, password: []const u8, challenge: [16]u8) [16]u8 {
    const Md5 = std.crypto.hash.Md5;
    var hash = Md5.init(.{});
    hash.update(&.{identifier});
    hash.update(password);
    hash.update(&challenge);
    return hash.finalResult();
}

/// Encodes the standard response data: `value_size=16`, digest, optional name.
pub fn encodeResponseData(
    identifier: u8,
    username: []const u8,
    password: []const u8,
    challenge: [16]u8,
    output: []u8,
) EncodeError![]const u8 {
    const required = 1 + 16 + username.len;
    if (required > std.math.maxInt(u16)) return error.LengthTooLarge;
    if (output.len < required) return error.OutputTooSmall;
    output[0] = 16;
    const digest = proof(identifier, password, challenge);
    @memcpy(output[1..17], &digest);
    @memcpy(output[17..required], username);
    return output[0..required];
}

pub const Terminal = struct {
    /// Private notification text; empty when the length field is zero.
    notification: []const u8,
};

/// Parses the private data carried by Success and Failure, if present.
///
/// Unknown vendor or truncated data yields `null`; terminal codes must not
/// fail authentication merely because the private layout is unfamiliar.
pub fn parseTerminal(data: []const u8) ?Terminal {
    if (data.len < 6) return null;
    if (std.mem.readInt(u32, data[0..4], .big) != vendor_id) return null;
    const notification_len = std.mem.readInt(u16, data[4..6], .big);
    if (6 + notification_len > data.len) return null;
    return .{ .notification = data[6 .. 6 + notification_len] };
}

test "standard EAP-MD5 proof matches the fixed vector" {
    const challenge = [16]u8{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    const digest = proof(0x17, "secret", challenge);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x07, 0x91, 0xb0, 0xbc, 0x38, 0xfa, 0xcd, 0x86,
            0x42, 0xac, 0x55, 0x31, 0x91, 0x22, 0xd6, 0xce,
        },
        &digest,
    );

    var output: [64]u8 = undefined;
    const data = try encodeResponseData(0x17, "alice", "secret", challenge, &output);
    try std.testing.expectEqual(@as(usize, 22), data.len);
    try std.testing.expectEqual(@as(u8, 16), data[0]);
    try std.testing.expectEqualSlices(u8, "alice", data[17..]);
}

test "tail layout matches the target frame shape" {
    const lease: dhcp.LegacyDhcpInfo = .{
        .dhcp_enabled = true,
        .ip = .{ 10, 252, 135, 58 },
        .netmask = .{ 255, 255, 240, 0 },
        .gateway = .{ 10, 252, 128, 1 },
        .dns = .{ 222, 200, 129, 134 },
    };
    const chain: [16]u8 = @splat(0xaa);
    const params: Params = .{
        .frame = .identity,
        .source_mac = .{ 0x00, 0xe0, 0x4c, 0x5f, 0x63, 0x98 },
        .service_name = "students",
        .disk_serial = "",
        .ipv6_state = 5,
        .ipv6_link_local = @splat(0),
        .ipv6_global = @splat(0),
        .ipv6_third = @splat(0),
        .lease = lease,
        .alternate_dns_text = "202.116.32.254",
        .os_bits = 0x40,
        .chain = &chain,
        .v3_digest = @splat(0),
        .security_ok = false,
    };

    var tail: [1024]u8 = undefined;
    const encoded = try encodeTail(params, &tail);
    try std.testing.expectEqual(@as(usize, 566), encoded.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0x02, 0x02 }, encoded[59..63]);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[63]);

    var offset: usize = prefix_len;
    const expected_codes = [_]u8{
        0x17, 0x18, 0x2d, 0x2f, 0x35, 0x36, 0x38, 0x4e,
        0x4d, 0x39, 0x54, 0x76, 0x62, 0x70, 0x6f, 0x79,
    };
    const expected_values = [_]usize{
        32, 4, 6, 16, 1, 16, 16, 16, 128, 32, 64, 14, 1, 1, 20, 1,
    };
    for (expected_codes, expected_values) |code, value_len| {
        try std.testing.expectEqual(@as(u8, 0x1a), encoded[offset]);
        try std.testing.expectEqual(@as(u8, code), encoded[offset + 6]);
        try std.testing.expectEqual(@as(u8, @intCast(value_len + 2)), encoded[offset + 7]);
        try std.testing.expectEqual(
            @as(usize, 8 + value_len),
            @as(usize, encoded[offset + 1]),
        );
        offset += 8 + value_len;
    }
    try std.testing.expectEqual(encoded.len, offset);
}

test "tail omits empty optional attributes and marks Logoff" {
    const chain: [16]u8 = @splat(0);
    const params: Params = .{
        .frame = .logoff,
        .source_mac = @splat(0),
        .service_name = "",
        .disk_serial = "",
        .ipv6_state = 0,
        .ipv6_link_local = @splat(0),
        .ipv6_global = @splat(0),
        .ipv6_third = @splat(0),
        .lease = .{
            .dhcp_enabled = false,
            .ip = @splat(0),
            .netmask = @splat(0),
            .gateway = @splat(0),
            .dns = @splat(0),
        },
        .alternate_dns_text = "",
        .os_bits = 0x40,
        .chain = &chain,
        .v3_digest = @splat(0),
        .security_ok = false,
    };
    var tail: [1024]u8 = undefined;
    const encoded = try encodeTail(params, &tail);
    try std.testing.expectEqual(@as(usize, 566 - 40 - 22), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x01), encoded[63]);
}

test "terminal data parses the target private layout" {
    try std.testing.expectEqual(@as(?Terminal, null), parseTerminal(&.{}));
    try std.testing.expectEqual(@as(?Terminal, null), parseTerminal(&.{ 0, 0, 0x13, 0x11 }));
    try std.testing.expectEqual(@as(?Terminal, null), parseTerminal(&.{ 0, 0, 0x13, 0x11, 0, 4, 'a' }));

    const empty = parseTerminal(&.{ 0, 0, 0x13, 0x11, 0, 0 }).?;
    try std.testing.expectEqual(@as(usize, 0), empty.notification.len);

    const text = parseTerminal(&.{ 0, 0, 0x13, 0x11, 0, 3, 'r', 'j', '!' }).?;
    try std.testing.expectEqualSlices(u8, "rj!", text.notification);
}
