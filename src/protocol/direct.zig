const std = @import("std");

pub const header_size = 42;
pub const ethernet_header_size = 14;
pub const ipv4_header_size = 20;
pub const udp_header_size = 8;
pub const max_encrypted_chunk = 1358;

pub const Endpoint = struct {
    mac: [6]u8,
    ip: [4]u8,
    port: u16,
};

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
    PacketTooShort,
    UnsupportedEtherType,
    UnsupportedIpVersion,
    InvalidIpv4Header,
    UnsupportedIpv4Fragments,
    UnsupportedProtocol,
    InvalidIpv4Length,
    InvalidUdpLength,
    InvalidChecksum,
};

pub const AuthError = error{
    PacketTooShort,
};

pub const EncodeError = error{
    InvalidPacketLength,
    PacketTooLong,
    OutputTooSmall,
};

pub const AuthenticatorFrameError = error{
    PacketTooShort,
    InvalidPacketLength,
};

pub const DecodedFrame = struct {
    header: Header,
    source: Endpoint,
    destination: Endpoint,
    encrypted: []const u8,
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

/// Encodes one complete Ethernet II frame containing IPv4, UDP, and a direct message.
pub fn encodeFrame(
    header: Header,
    encrypted_chunk: []const u8,
    source: Endpoint,
    destination: Endpoint,
    output: []u8,
) EncodeError![]u8 {
    if (encrypted_chunk.len > max_encrypted_chunk) return error.PacketTooLong;

    const ipv4_total_len = ipv4_header_size + udp_header_size + header_size + encrypted_chunk.len;
    if (ipv4_total_len > std.math.maxInt(u16)) return error.PacketTooLong;
    if (header.packet_len != header_size + encrypted_chunk.len) return error.InvalidPacketLength;

    const udp_len = udp_header_size + header_size + encrypted_chunk.len;
    if (udp_len > std.math.maxInt(u16)) return error.PacketTooLong;

    const frame_len = ethernet_header_size + ipv4_total_len;
    if (output.len < frame_len) return error.OutputTooSmall;
    const frame = output[0..frame_len];
    @memset(frame, 0);

    @memcpy(frame[0..6], &destination.mac);
    @memcpy(frame[6..12], &source.mac);
    std.mem.writeInt(u16, frame[12..14], 0x0800, .big);

    const ipv4 = frame[ethernet_header_size..][0..ipv4_header_size];
    ipv4[0] = 0x45;
    std.mem.writeInt(u16, ipv4[2..4], @intCast(ipv4_total_len), .big);
    ipv4[8] = 128;
    ipv4[9] = 17;
    @memcpy(ipv4[12..16], &source.ip);
    @memcpy(ipv4[16..20], &destination.ip);
    std.mem.writeInt(u16, ipv4[10..12], internetChecksum(ipv4), .big);

    const udp_offset = ethernet_header_size + ipv4_header_size;
    const udp = frame[udp_offset..][0..udp_len];
    std.mem.writeInt(u16, udp[0..2], source.port, .big);
    std.mem.writeInt(u16, udp[2..4], destination.port, .big);
    std.mem.writeInt(u16, udp[4..6], @intCast(udp_len), .big);

    var direct_header: [header_size]u8 = undefined;
    encodeHeader(header, &direct_header);
    @memcpy(udp[udp_header_size..][0..header_size], &direct_header);
    @memcpy(udp[udp_header_size + header_size ..], encrypted_chunk);

    const udp_checksum = transportChecksum(source.ip, destination.ip, 17, udp);
    std.mem.writeInt(u16, udp[6..8], udp_checksum, .big);
    return frame;
}

/// Decodes and validates the complete network framing around one direct message.
pub fn decodeFrame(frame: []const u8) DecodeError!DecodedFrame {
    if (frame.len < ethernet_header_size + ipv4_header_size + udp_header_size + header_size) {
        return error.PacketTooShort;
    }
    if (std.mem.readInt(u16, frame[12..14], .big) != 0x0800) {
        return error.UnsupportedEtherType;
    }

    const ipv4_offset = ethernet_header_size;
    const ipv4 = frame[ipv4_offset .. ipv4_offset + ipv4_header_size];
    if (ipv4[0] >> 4 != 4) return error.UnsupportedIpVersion;
    if (ipv4[0] & 0x0f != 5) return error.InvalidIpv4Header;
    if (internetChecksum(ipv4) != 0) return error.InvalidChecksum;
    if (ipv4[9] != 17) return error.UnsupportedProtocol;
    if (std.mem.readInt(u16, ipv4[6..8], .big) != 0) {
        return error.UnsupportedIpv4Fragments;
    }

    const ipv4_total_len = std.mem.readInt(u16, ipv4[2..4], .big);
    if (ipv4_total_len < ipv4_header_size + udp_header_size + header_size) {
        return error.InvalidIpv4Length;
    }
    if (frame.len != ethernet_header_size + ipv4_total_len) {
        return error.InvalidIpv4Length;
    }

    const udp_offset = ethernet_header_size + ipv4_header_size;
    const udp_len = std.mem.readInt(u16, frame[udp_offset + 4 .. udp_offset + 6], .big);
    if (udp_len < udp_header_size + header_size or
        udp_len != ipv4_total_len - ipv4_header_size)
    {
        return error.InvalidUdpLength;
    }
    const source_ip: [4]u8 = ipv4[12..16].*;
    const destination_ip: [4]u8 = ipv4[16..20].*;
    const udp = frame[udp_offset .. udp_offset + udp_len];
    if (transportChecksum(source_ip, destination_ip, 17, udp) != 0xffff) {
        return error.InvalidChecksum;
    }

    const direct_offset = udp_offset + udp_header_size;
    const direct_bytes = frame[direct_offset..];
    const header: [header_size]u8 = direct_bytes[0..header_size].*;
    const decoded_header = try decodeHeader(&header);
    const encrypted = direct_bytes[header_size..];
    if (decoded_header.packet_len != direct_bytes.len) {
        return error.InvalidPacketLength;
    }

    return .{
        .header = decoded_header,
        .source = .{
            .mac = frame[6..12].*,
            .ip = source_ip,
            .port = std.mem.readInt(u16, udp[0..2], .big),
        },
        .destination = .{
            .mac = frame[0..6].*,
            .ip = destination_ip,
            .port = std.mem.readInt(u16, udp[2..4], .big),
        },
        .encrypted = encrypted,
    };
}

/// Writes a direct authenticator into an encoded frame and refreshes the UDP checksum.
pub fn setAuthenticator(
    frame: []u8,
    key: [8]u8,
    iv: [8]u8,
) AuthenticatorFrameError!void {
    const required_len = ethernet_header_size + ipv4_header_size + udp_header_size + header_size;
    if (frame.len < required_len) return error.PacketTooShort;

    const ipv4 = frame[ethernet_header_size..][0..ipv4_header_size];
    const ipv4_total_len = std.mem.readInt(u16, ipv4[2..4], .big);
    if (frame.len != ethernet_header_size + ipv4_total_len) return error.InvalidPacketLength;

    const udp_offset = ethernet_header_size + ipv4_header_size;
    const udp_len = std.mem.readInt(u16, frame[udp_offset + 4 .. udp_offset + 6], .big);
    if (udp_len < udp_header_size + header_size or
        udp_len != ipv4_total_len - ipv4_header_size)
    {
        return error.InvalidPacketLength;
    }

    const packet_offset = udp_offset + udp_header_size;
    const authenticator = try computeAuthenticator(frame[packet_offset..], key, iv);
    @memcpy(frame[packet_offset + 8 .. packet_offset + 24], &authenticator);

    const udp = frame[udp_offset .. udp_offset + udp_len];
    std.mem.writeInt(u16, udp[6..8], 0, .big);
    const source_ip: [4]u8 = ipv4[12..16].*;
    const destination_ip: [4]u8 = ipv4[16..20].*;
    std.mem.writeInt(
        u16,
        udp[6..8],
        transportChecksum(source_ip, destination_ip, 17, udp),
        .big,
    );
}

fn internetChecksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var offset: usize = 0;
    while (offset + 1 < bytes.len) : (offset += 2) {
        sum += std.mem.readInt(u16, bytes[offset..][0..2], .big);
    }
    if (offset < bytes.len) sum += @as(u16, bytes[offset]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

fn transportChecksum(
    source_ip: [4]u8,
    destination_ip: [4]u8,
    protocol: u8,
    payload: []const u8,
) u16 {
    var sum: u32 = 0;
    sum += @as(u16, source_ip[0]) << 8 | source_ip[1];
    sum += @as(u16, source_ip[2]) << 8 | source_ip[3];
    sum += @as(u16, destination_ip[0]) << 8 | destination_ip[1];
    sum += @as(u16, destination_ip[2]) << 8 | destination_ip[3];
    sum += protocol;
    sum += @intCast(payload.len);

    var offset: usize = 0;
    while (offset + 1 < payload.len) : (offset += 2) {
        sum += std.mem.readInt(u16, payload[offset..][0..2], .big);
    }
    if (offset < payload.len) sum += @as(u16, payload[offset]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    const checksum: u16 = @truncate(~sum);
    return if (checksum == 0) 0xffff else checksum;
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

test "direct frame preserves ethernet, ipv4, udp, and direct fields" {
    var output: [256]u8 = undefined;
    const header = Header{
        .version = 1,
        .code = 1,
        .id = 0x0102_0304,
        .packet_len = header_size + 3,
        .authenticator = @splat(0),
        .session_id = 0x1122_3344,
        .timestamp = 0x0102_0304_0506_0708,
        .message_type = 1,
        .flags = 1,
        .total_len = 3,
    };
    const source = Endpoint{
        .mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .ip = .{ 192, 0, 2, 10 },
        .port = 1234,
    };
    const destination = Endpoint{
        .mac = .{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb },
        .ip = .{ 192, 0, 2, 1 },
        .port = 5678,
    };

    const encoded = try encodeFrame(header, &.{ 0xaa, 0xbb, 0xcc }, source, destination, &output);
    try std.testing.expectEqual(@as(usize, 14 + 20 + 8 + header_size + 3), encoded.len);

    const decoded = try decodeFrame(encoded);
    try std.testing.expectEqual(expected: {
        var value = header;
        value.packet_len = header_size + 3;
        break :expected value;
    }, decoded.header);
    try std.testing.expectEqual(source, decoded.source);
    try std.testing.expectEqual(destination, decoded.destination);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, decoded.encrypted);
}
