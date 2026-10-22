const std = @import("std");

/// Encrypts one legacy DES block for protocol compatibility.
pub fn encryptBlock(key: [8]u8, block: [8]u8) [8]u8 {
    return transformBlock(key, block, false);
}

/// Decrypts one legacy DES block for protocol compatibility.
pub fn decryptBlock(key: [8]u8, block: [8]u8) [8]u8 {
    return transformBlock(key, block, true);
}

pub const CbcError = error{
    InvalidLength,
    OutputTooSmall,
};

/// Encrypts complete blocks with the legacy DES-CBC mode used by direct messages.
pub fn encryptCbc(
    key: [8]u8,
    iv: [8]u8,
    plaintext: []const u8,
    output: []u8,
) CbcError!usize {
    if (plaintext.len % 8 != 0) return error.InvalidLength;
    if (output.len < plaintext.len) return error.OutputTooSmall;

    var previous = iv;
    var offset: usize = 0;
    while (offset < plaintext.len) : (offset += 8) {
        var block: [8]u8 = plaintext[offset..][0..8].*;
        for (&block, previous) |*byte, chain| byte.* ^= chain;
        previous = encryptBlock(key, block);
        output[offset..][0..8].* = previous;
    }
    return plaintext.len;
}

/// Decrypts complete blocks with the legacy DES-CBC mode used by direct messages.
pub fn decryptCbc(
    key: [8]u8,
    iv: [8]u8,
    ciphertext: []const u8,
    output: []u8,
) CbcError!usize {
    if (ciphertext.len % 8 != 0) return error.InvalidLength;
    if (output.len < ciphertext.len) return error.OutputTooSmall;

    var previous = iv;
    var offset: usize = 0;
    while (offset < ciphertext.len) : (offset += 8) {
        const encrypted: [8]u8 = ciphertext[offset..][0..8].*;
        var block = decryptBlock(key, encrypted);
        for (&block, previous) |*byte, chain| byte.* ^= chain;
        output[offset..][0..8].* = block;
        previous = encrypted;
    }
    return ciphertext.len;
}

fn transformBlock(key: [8]u8, block: [8]u8, decrypting: bool) [8]u8 {
    const key_schedule = createSubkeys(key);
    var value = std.mem.readInt(u64, &block, .big);
    value = permute(value, &initial_permutation, 64);

    var left: u32 = @truncate(value >> 32);
    var right: u32 = @truncate(value);
    for (0..16) |round| {
        const subkey = key_schedule[if (decrypting) 15 - round else round];
        const next = left ^ roundFunction(right, subkey);
        left = right;
        right = next;
    }

    const preoutput = (@as(u64, right) << 32) | left;
    const output = permute(preoutput, &final_permutation, 64);
    var result: [8]u8 = undefined;
    std.mem.writeInt(u64, &result, output, .big);
    return result;
}

fn createSubkeys(key: [8]u8) [16]u64 {
    const value = std.mem.readInt(u64, &key, .big);
    const permuted = permute(value, &permuted_choice_1, 64);
    var c: u32 = @intCast(permuted >> 28);
    var d: u32 = @intCast(permuted & 0x0fff_ffff);

    var subkeys: [16]u64 = undefined;
    for (&subkeys, 0..) |*subkey, round| {
        c = rotate28(c, key_shifts[round]);
        d = rotate28(d, key_shifts[round]);
        subkey.* = permute((@as(u64, c) << 28) | d, &permuted_choice_2, 56);
    }
    return subkeys;
}

fn rotate28(value: u32, amount: u5) u32 {
    return ((value << amount) | (value >> (28 - amount))) & 0x0fff_ffff;
}

fn roundFunction(right: u32, subkey: u64) u32 {
    const expanded = permute(right, &expansion, 32) ^ subkey;
    var substituted: u32 = 0;
    for (0..8) |index| {
        const shift: u6 = @intCast((7 - index) * 6);
        const six_bits: u8 = @intCast((expanded >> shift) & 0x3f);
        const row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        const column = (six_bits >> 1) & 0x0f;
        substituted = (substituted << 4) |
            s_boxes[index][@as(usize, row)][@as(usize, column)];
    }
    return @intCast(permute(substituted, &permutation, 32));
}

fn permute(input: u64, table: []const u8, input_bits: u7) u64 {
    var output: u64 = 0;
    for (table) |position| {
        output <<= 1;
        const shift: u6 = @intCast(input_bits - @as(u7, @intCast(position)));
        output |= (input >> shift) & 1;
    }
    return output;
}

const initial_permutation = [_]u8{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

const final_permutation = [_]u8{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25,
};

const expansion = [_]u8{
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

const permutation = [_]u8{
    16, 7,  20, 21,
    29, 12, 28, 17,
    1,  15, 23, 26,
    5,  18, 31, 10,
    2,  8,  24, 14,
    32, 27, 3,  9,
    19, 13, 30, 6,
    22, 11, 4,  25,
};

const permuted_choice_1 = [_]u8{
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4,
};

const permuted_choice_2 = [_]u8{
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

const key_shifts = [_]u5{
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
};

const s_boxes = [8][4][16]u8{
    .{
        .{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
        .{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
        .{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
        .{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    },
    .{
        .{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
        .{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
        .{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
        .{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    },
    .{
        .{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
        .{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
        .{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
        .{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    },
    .{
        .{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
        .{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
        .{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
        .{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    },
    .{
        .{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
        .{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
        .{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
        .{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    },
    .{
        .{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
        .{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
        .{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
        .{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    },
    .{
        .{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
        .{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
        .{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
        .{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    },
    .{
        .{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
        .{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
        .{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
        .{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
    },
};

test "DES encrypts the public known-answer vector" {
    const ciphertext = encryptBlock(
        .{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 },
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 },
        &ciphertext,
    );
}

test "DES decrypts the public known-answer vector" {
    const plaintext = decryptBlock(
        .{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 },
        .{ 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
        &plaintext,
    );
}

test "DES-CBC matches the public multi-block known answer" {
    const plaintext = [_]u8{
        0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
        0x66, 0x6f, 0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20,
    };
    var ciphertext: [plaintext.len]u8 = undefined;
    const written = try encryptCbc(
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
        .{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef },
        &plaintext,
        &ciphertext,
    );

    try std.testing.expectEqual(plaintext.len, written);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c,
            0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f,
            0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6,
        },
        &ciphertext,
    );
}

test "DES-CBC decrypts each block and advances the IV" {
    const ciphertext = [_]u8{
        0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c,
        0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f,
        0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6,
    };
    var plaintext: [ciphertext.len]u8 = undefined;
    _ = try decryptCbc(
        .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
        .{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef },
        &ciphertext,
        &plaintext,
    );

    try std.testing.expectEqualStrings("Now is the time for all ", &plaintext);
}

test "DES-CBC rejects partial blocks and short output buffers" {
    var output: [8]u8 = undefined;
    const one_block = @as([8]u8, @splat(0));
    try std.testing.expectError(
        error.InvalidLength,
        encryptCbc(@splat(0), @splat(0), &.{1}, &output),
    );
    try std.testing.expectError(
        error.OutputTooSmall,
        encryptCbc(@splat(0), @splat(0), &one_block, output[0..7]),
    );
}
