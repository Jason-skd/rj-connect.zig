const std = @import("std");

pub const PasswordError = error{
    OutputTooSmall,
};

pub const Rc4Error = error{
    EmptyKey,
    OutputTooSmall,
};

/// Returns the zero-padded ciphertext size for a RADIUS User-Password value.
pub fn passwordCiphertextSize(plain_len: usize) usize {
    return (plain_len + 15) & ~@as(usize, 15);
}

/// Encrypts a password with the chained MD5 form used by the vendor attributes.
/// This is a legacy compatibility primitive, not a general password-storage scheme.
pub fn encryptPassword(
    username: []const u8,
    challenge: [16]u8,
    plaintext: []const u8,
    output: []u8,
) PasswordError!usize {
    const ciphertext_len = passwordCiphertextSize(plaintext.len);
    if (output.len < ciphertext_len) return error.OutputTooSmall;

    @memset(output[0..ciphertext_len], 0);
    @memcpy(output[0..plaintext.len], plaintext);

    const Md5 = std.crypto.hash.Md5;
    var digest: [Md5.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);

    var offset: usize = 0;
    while (offset < ciphertext_len) : (offset += 16) {
        var hash = Md5.init(.{});
        hash.update(username);
        if (offset == 0) {
            hash.update(&challenge);
        } else {
            hash.update(output[offset - 16 .. offset]);
        }
        hash.final(&digest);

        for (digest, output[offset .. offset + 16]) |mask, *byte| {
            byte.* ^= mask;
        }
    }

    return ciphertext_len;
}

/// Applies RC4 to a legacy protocol field.
/// RC4 is retained only for compatibility and must not be used for new security designs.
pub fn applyRc4(key: []const u8, input: []const u8, output: []u8) Rc4Error!usize {
    if (key.len == 0) return error.EmptyKey;
    if (output.len < input.len) return error.OutputTooSmall;

    var state: [256]u8 = undefined;
    for (&state, 0..) |*byte, index| byte.* = @intCast(index);

    var j: u8 = 0;
    for (0..256) |index| {
        j +%= state[index] +% key[index % key.len];
        std.mem.swap(u8, &state[index], &state[@intCast(j)]);
    }

    var i: u8 = 0;
    j = 0;
    for (input, 0..) |byte, index| {
        i +%= 1;
        j +%= state[i];
        std.mem.swap(u8, &state[i], &state[j]);
        const key_byte = state[@as(u8, state[i] +% state[j])];
        output[index] = byte ^ key_byte;
    }

    return input.len;
}

test "password encryption matches the single-block known answer" {
    var encrypted: [16]u8 = undefined;
    const written = try encryptPassword(
        "alice",
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        "secret",
        &encrypted,
    );

    try std.testing.expectEqual(@as(usize, 16), written);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x56, 0x0e, 0x1b, 0xdc,
            0xdf, 0x4a, 0xf3, 0x51,
            0x57, 0xee, 0xad, 0xb5,
            0x32, 0xc7, 0xae, 0x01,
        },
        encrypted[0..written],
    );
}

test "password encryption chains MD5 across blocks" {
    var encrypted: [32]u8 = undefined;
    const written = try encryptPassword(
        "alice",
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        "0123456789abcdefghij",
        &encrypted,
    );

    try std.testing.expectEqual(@as(usize, 32), written);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x15, 0x5a, 0x4a, 0x9d,
            0x8e, 0x0b, 0xc5, 0x66,
            0x6f, 0xd7, 0xcc, 0xd7,
            0x51, 0xa3, 0xcb, 0x67,
            0x3f, 0x24, 0x82, 0xac,
            0xa4, 0xee, 0x88, 0xd8,
            0x4b, 0x37, 0x35, 0x8a,
            0xca, 0xff, 0x12, 0x2a,
        },
        encrypted[0..written],
    );
}

test "password encryption reports the required padded size" {
    try std.testing.expectEqual(@as(usize, 0), passwordCiphertextSize(0));
    try std.testing.expectEqual(@as(usize, 16), passwordCiphertextSize(1));
    try std.testing.expectEqual(@as(usize, 16), passwordCiphertextSize(16));
    try std.testing.expectEqual(@as(usize, 32), passwordCiphertextSize(17));

    var short: [15]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        encryptPassword("alice", @splat(0), "secret", &short),
    );
}

test "RC4 matches the standard test vector" {
    var ciphertext: [9]u8 = undefined;
    const written = try applyRc4("Key", "Plaintext", &ciphertext);

    try std.testing.expectEqual(@as(usize, 9), written);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 },
        &ciphertext,
    );
}

test "RC4 decrypts symmetrically and validates buffers" {
    const ciphertext = [9]u8{ 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 };
    var plaintext: [9]u8 = undefined;
    _ = try applyRc4("Key", &ciphertext, &plaintext);
    try std.testing.expectEqualSlices(u8, "Plaintext", &plaintext);

    try std.testing.expectError(error.EmptyKey, applyRc4(&.{}, "x", &plaintext));

    var short: [1]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, applyRc4("Key", "Plaintext", &short));
}
