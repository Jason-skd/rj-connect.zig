//! EAPOL/EAP wire codecs for the deterministic authentication engine.

const std = @import("std");

pub const header_size = 18;
pub const ether_type: u16 = 0x888e;
pub const default_destination = [6]u8{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

/// EAPOL frame types from IEEE 802.1X: EAP-Packet `0`, Start `1`, Logoff `2`.
pub const PacketType = enum(u8) {
    eap = 0,
    start = 1,
    logoff = 2,
    _,
};

pub const EapCode = enum(u8) {
    request = 1,
    response = 2,
    success = 3,
    failure = 4,
    _,
};

pub const EapType = enum(u8) {
    identity = 1,
    notification = 2,
    legacy_nak = 3,
    md5_challenge = 4,
    otp = 5,
    generic_token_card = 6,
    credential = 7,
    peap = 25,
    _,
};

pub const Eap = struct {
    code: EapCode,
    identifier: u8,
    type: ?EapType,
    /// Type-specific payload. For Success and Failure this is server private data.
    data: []const u8,
};

/// The EAP payload is a view into the input slice passed to `decode`.
pub const Frame = struct {
    destination: [6]u8,
    source: [6]u8,
    packet_type: PacketType,
    eap: ?Eap,
};

pub const DecodeError = error{
    TruncatedFrame,
    InvalidEtherType,
    UnsupportedVersion,
    InvalidBodyLength,
    UnsupportedPacketType,
    InvalidEapLength,
    UnsupportedEapCode,
    MissingEapType,
    UnexpectedEapType,
};

pub const Md5Challenge = struct {
    challenge: [16]u8,
    name: []const u8,
};

pub const Md5Error = error{
    TruncatedChallenge,
    InvalidChallengeSize,
    UnexpectedEapType,
    OutputTooSmall,
    LengthTooLarge,
};

/// Encodes a standard EAPOL Start frame for an IEEE 802.1X client.
pub fn encodeStart(destination: [6]u8, source: [6]u8, output: *[header_size]u8) void {
    encodeControl(destination, source, .start, output);
}

/// Encodes an EAPOL Logoff frame with an empty body.
pub fn encodeLogoff(destination: [6]u8, source: [6]u8, output: *[header_size]u8) void {
    encodeControl(destination, source, .logoff, output);
}

fn encodeControl(
    destination: [6]u8,
    source: [6]u8,
    packet_type: PacketType,
    output: *[header_size]u8,
) void {
    @memcpy(output[0..6], &destination);
    @memcpy(output[6..12], &source);
    std.mem.writeInt(u16, output[12..14], ether_type, .big);
    output[14] = 1;
    output[15] = @backingInt(packet_type);
    std.mem.writeInt(u16, output[16..18], 0, .big);
}

/// Encodes one EAP packet inside EAPOL and returns the populated prefix.
pub fn encodeEap(
    destination: [6]u8,
    source: [6]u8,
    code: EapCode,
    identifier: u8,
    eap_type: ?EapType,
    data: []const u8,
    output: []u8,
) error{
    OutputTooSmall,
    LengthTooLarge,
    MissingEapType,
    UnexpectedEapType,
    UnsupportedEapCode,
}![]const u8 {
    const type_len: usize = switch (code) {
        .request, .response => if (eap_type != null) 1 else return error.MissingEapType,
        .success, .failure => if (eap_type == null) 0 else return error.UnexpectedEapType,
        else => return error.UnsupportedEapCode,
    };
    const eap_len = 4 + type_len + data.len;
    const frame_len = header_size + eap_len;
    if (eap_len > std.math.maxInt(u16)) return error.LengthTooLarge;
    if (output.len < frame_len) return error.OutputTooSmall;

    @memcpy(output[0..6], &destination);
    @memcpy(output[6..12], &source);
    std.mem.writeInt(u16, output[12..14], ether_type, .big);
    output[14] = 1;
    output[15] = @backingInt(PacketType.eap);
    std.mem.writeInt(u16, output[16..18], @intCast(eap_len), .big);
    output[18] = @backingInt(code);
    output[19] = identifier;
    std.mem.writeInt(u16, output[20..22], @intCast(eap_len), .big);
    if (eap_type) |value| output[22] = @backingInt(value);
    @memcpy(output[22 + type_len .. frame_len], data);
    return output[0..frame_len];
}

/// Decodes the RFC 3748 EAP-MD5 Challenge payload.
pub fn decodeMd5Challenge(eap: Eap) Md5Error!Md5Challenge {
    if (eap.type != .md5_challenge) return error.UnexpectedEapType;
    if (eap.data.len == 0) return error.TruncatedChallenge;
    if (eap.data[0] != 16) return error.InvalidChallengeSize;
    if (eap.data.len < 17) return error.TruncatedChallenge;

    return .{
        .challenge = eap.data[1..17].*,
        .name = eap.data[17..],
    };
}

/// Builds the EAP-MD5 response type data using the protocol's lowercase proof text.
pub fn encodeMd5ResponseData(
    identifier: u8,
    username: []const u8,
    challenge: [16]u8,
    output: []u8,
) Md5Error![]const u8 {
    if (username.len > std.math.maxInt(u16) - 38) return error.LengthTooLarge;
    const response_len = 33 + username.len;
    if (output.len < response_len) return error.OutputTooSmall;

    const Md5 = std.crypto.hash.Md5;
    var hash = Md5.init(.{});
    hash.update(&.{identifier});
    hash.update(username);
    hash.update(&challenge);
    const digest = hash.finalResult();

    output[0] = 32;
    const hex_digits = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        output[1 + index * 2] = hex_digits[byte >> 4];
        output[2 + index * 2] = hex_digits[byte & 0x0f];
    }
    @memcpy(output[33..response_len], username);
    return output[0..response_len];
}

/// Decodes the common EAPOL framing and validates its length boundaries.
pub fn decode(input: []const u8) DecodeError!Frame {
    if (input.len < header_size) return error.TruncatedFrame;
    if (std.mem.readInt(u16, input[12..14], .big) != ether_type) return error.InvalidEtherType;
    if (input[14] != 1) return error.UnsupportedVersion;

    const body_len = std.mem.readInt(u16, input[16..18], .big);
    if (input.len - header_size < body_len) return error.InvalidBodyLength;

    const packet_type: PacketType = @fromBackingInt(@intCast(input[15]));
    switch (packet_type) {
        .start, .eap, .logoff => {},
        else => return error.UnsupportedPacketType,
    }
    if (packet_type == .start and body_len != 0) return error.InvalidBodyLength;
    if (packet_type == .logoff and body_len != 0) return error.InvalidBodyLength;
    if (packet_type != .eap) {
        return .{
            .destination = input[0..6].*,
            .source = input[6..12].*,
            .packet_type = packet_type,
            .eap = null,
        };
    }
    if (body_len < 4) return error.InvalidEapLength;

    const eap = input[header_size..][0..body_len];
    const eap_len = std.mem.readInt(u16, eap[2..4], .big);
    if (eap_len < 4 or eap_len > body_len) return error.InvalidEapLength;
    const code: EapCode = @fromBackingInt(@intCast(eap[0]));
    switch (code) {
        .request, .response, .success, .failure => {},
        else => return error.UnsupportedEapCode,
    }
    const has_type = code == .request or code == .response;
    if (has_type and eap_len < 5) return error.MissingEapType;

    return .{
        .destination = input[0..6].*,
        .source = input[6..12].*,
        .packet_type = packet_type,
        .eap = .{
            .code = code,
            .identifier = eap[1],
            .type = if (has_type) @as(EapType, @fromBackingInt(@intCast(eap[4]))) else null,
            .data = if (has_type) eap[5..eap_len] else eap[4..eap_len],
        },
    };
}

test "EAPOL Start encodes and decodes the fixed frame layout" {
    const destination = [6]u8{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
    const source = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var encoded: [header_size]u8 = undefined;

    encodeStart(destination, source, &encoded);

    try std.testing.expectEqualSlices(u8, &.{
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x88, 0x8e, 0x01, 0x01, 0x00, 0x00,
    }, &encoded);

    const frame = try decode(&encoded);
    try std.testing.expectEqual(destination, frame.destination);
    try std.testing.expectEqual(source, frame.source);
    try std.testing.expectEqual(PacketType.start, frame.packet_type);
    try std.testing.expectEqual(@as(?Eap, null), frame.eap);
}

test "EAP Identity request decodes and Identity response encodes" {
    const destination = [6]u8{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
    const source = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const request = [header_size + 5]u8{
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x88, 0x8e, 0x01, 0x00, 0x00, 0x05,
        0x01, 0x16, 0x00, 0x05, 0x01,
    };

    const frame = try decode(&request);
    try std.testing.expectEqual(PacketType.eap, frame.packet_type);
    try std.testing.expectEqual(EapCode.request, frame.eap.?.code);
    try std.testing.expectEqual(@as(u8, 0x16), frame.eap.?.identifier);
    try std.testing.expectEqual(@as(?EapType, .identity), frame.eap.?.type);
    try std.testing.expectEqual(@as(usize, 0), frame.eap.?.data.len);

    var response: [header_size + 10]u8 = undefined;
    const encoded = try encodeEap(destination, source, .response, 0x16, .identity, "alice", &response);
    try std.testing.expectEqualSlices(u8, &.{
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x88, 0x8e, 0x01, 0x00, 0x00, 0x0a,
        0x02, 0x16, 0x00, 0x0a, 0x01, 'a',
        'l',  'i',  'c',  'e',
    }, encoded);
}

test "EAP terminal packets and Logoff decode with strict framing checks" {
    const success = [header_size + 4]u8{
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x88, 0x8e, 0x01, 0x00, 0x00, 0x04,
        0x03, 0x17, 0x00, 0x04,
    };
    const success_frame = try decode(&success);
    try std.testing.expectEqual(EapCode.success, success_frame.eap.?.code);
    try std.testing.expectEqual(@as(u8, 0x17), success_frame.eap.?.identifier);
    try std.testing.expectEqual(@as(?EapType, null), success_frame.eap.?.type);

    var logoff: [header_size]u8 = undefined;
    encodeLogoff(success[0..6].*, success[6..12].*, &logoff);
    const logoff_frame = try decode(&logoff);
    try std.testing.expectEqual(PacketType.logoff, logoff_frame.packet_type);
    try std.testing.expectEqual(@as(?Eap, null), logoff_frame.eap);

    var malformed = success;
    malformed[12] = 0x80;
    try std.testing.expectError(error.InvalidEtherType, decode(&malformed));

    malformed = success;
    malformed[14] = 2;
    try std.testing.expectError(error.UnsupportedVersion, decode(&malformed));

    malformed = success;
    malformed[18] = 1;
    try std.testing.expectError(error.MissingEapType, decode(&malformed));

    malformed = success;
    malformed[21] = 5;
    try std.testing.expectError(error.InvalidEapLength, decode(&malformed));
}

test "EAP terminal packets carry server private data without an EAP type" {
    const destination = [6]u8{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
    const source = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const data = [_]u8{ 0x00, 0x00, 0x13, 0x11, 0x00, 0x00, 0xaa, 0xbb };
    inline for ([_]EapCode{ .success, .failure }) |code| {
        var buffer: [header_size + 4 + data.len]u8 = undefined;
        const encoded = try encodeEap(destination, source, code, 0x2a, null, &data, &buffer);
        const frame = try decode(encoded);
        try std.testing.expectEqual(code, frame.eap.?.code);
        try std.testing.expectEqual(@as(u8, 0x2a), frame.eap.?.identifier);
        try std.testing.expectEqual(@as(?EapType, null), frame.eap.?.type);
        try std.testing.expectEqualSlices(u8, &data, frame.eap.?.data);
    }
}

test "EAP-MD5 challenge and response match the protocol known answer" {
    const challenge = [16]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };
    var challenge_data: [19]u8 = undefined;
    challenge_data[0] = 16;
    @memcpy(challenge_data[1..17], &challenge);
    @memcpy(challenge_data[17..19], "rj");

    const decoded = try decodeMd5Challenge(.{
        .code = .request,
        .identifier = 0x17,
        .type = .md5_challenge,
        .data = &challenge_data,
    });
    try std.testing.expectEqual(challenge, decoded.challenge);
    try std.testing.expectEqualSlices(u8, "rj", decoded.name);

    var response_data: [38]u8 = undefined;
    const response = try encodeMd5ResponseData(0x17, "alice", challenge, &response_data);
    try std.testing.expectEqualSlices(u8, &.{
        0x20,
        '2',
        '7',
        '4',
        'e',
        '6',
        '5',
        '5',
        '0',
        '0',
        '1',
        '4',
        '5',
        '6',
        '6',
        'd',
        'f',
        '4',
        '9',
        'b',
        'b',
        '0',
        '7',
        '4',
        '5',
        '7',
        'd',
        '3',
        '3',
        'c',
        'a',
        '3',
        '8',
        'a',
        'l',
        'i',
        'c',
        'e',
    }, response);
}

test "EAP codec rejects unknown protocol values and malformed challenges" {
    const source = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const destination = [6]u8{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
    var terminal: [header_size + 4]u8 = undefined;
    @memcpy(terminal[0..header_size], &eapolHeader(.eap, 4));
    terminal[header_size..].* = .{ 9, 1, 0, 4 };
    try std.testing.expectError(error.UnsupportedEapCode, decode(&terminal));

    var unknown_packet: [header_size]u8 = undefined;
    @memcpy(unknown_packet[0..header_size], &eapolHeader(.start, 0));
    unknown_packet[15] = 9;
    try std.testing.expectError(error.UnsupportedPacketType, decode(&unknown_packet));

    try std.testing.expectError(
        error.InvalidChallengeSize,
        decodeMd5Challenge(.{
            .code = .request,
            .identifier = 1,
            .type = .md5_challenge,
            .data = &.{ 15, 0, 0, 0 },
        }),
    );
    try std.testing.expectError(
        error.TruncatedChallenge,
        decodeMd5Challenge(.{
            .code = .request,
            .identifier = 1,
            .type = .md5_challenge,
            .data = &.{ 16, 0, 0 },
        }),
    );

    var short: [header_size + 4]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        encodeEap(destination, source, .response, 1, .identity, "alice", &short),
    );
    var terminal_output: [header_size + 4]u8 = undefined;
    try std.testing.expectError(
        error.UnexpectedEapType,
        encodeEap(destination, source, .success, 1, .identity, &.{}, &terminal_output),
    );
    try std.testing.expectError(
        error.MissingEapType,
        encodeEap(destination, source, .response, 1, null, &.{}, &terminal_output),
    );
}

fn eapolHeader(packet_type: PacketType, body_len: u16) [header_size]u8 {
    return .{
        0x01, 0x80, 0xc2, 0x00,                     0x00,                    0x03,
        0x00, 0x11, 0x22, 0x33,                     0x44,                    0x55,
        0x88, 0x8e, 0x01, @backingInt(packet_type), @intCast(body_len >> 8), @intCast(body_len),
    };
}

/// Encodes the RFC 3748 password proof: `MD5(identifier || password || challenge)`.
pub fn encodeStandardMd5ResponseData(
    identifier: u8,
    password: []const u8,
    challenge: [16]u8,
    output: []u8,
) Md5Error![]const u8 {
    const response_len = 1 + 16;
    if (output.len < response_len) return error.OutputTooSmall;

    const Md5 = std.crypto.hash.Md5;
    var hash = Md5.init(.{});
    hash.update(&.{identifier});
    hash.update(password);
    hash.update(&challenge);
    const digest = hash.finalResult();

    output[0] = 16;
    @memcpy(output[1..17], &digest);
    return output[0..response_len];
}

test "standard EAP-MD5 password proof matches the fixed vector" {
    const challenge = [16]u8{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    var output: [17]u8 = undefined;
    const data = try encodeStandardMd5ResponseData(0x17, "secret", challenge, &output);
    try std.testing.expectEqualSlices(u8, &.{
        16,
        0x07,
        0x91,
        0xb0,
        0xbc,
        0x38,
        0xfa,
        0xcd,
        0x86,
        0x42,
        0xac,
        0x55,
        0x31,
        0x91,
        0x22,
        0xd6,
        0xce,
    }, data);
}
