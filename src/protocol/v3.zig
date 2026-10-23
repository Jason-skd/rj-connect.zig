//! Ruijie V3 digest compatibility construction.

const std = @import("std");

pub const digest_text_len = 128;

pub const Error = error{
    OutputTooSmall,
};

const tiger_sbox = loadSbox(@embedFile("v3_tiger_sbox.txt"), 1024);
const whirlpool_sbox = loadSbox(@embedFile("v3_whirlpool_sbox.txt"), 2048);
const ripemd_steps = @import("v3_ripemd_steps.zig").steps;

fn loadSbox(comptime text: []const u8, comptime count: usize) [count]u64 {
    @setEvalBranchQuota(10_000_000);
    var values: [count]u64 = undefined;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var index: usize = 0;
    while (lines.next()) |line| {
        if (index == count) @compileError("S-box has too many entries");
        var value: u64 = 0;
        for (line) |character| {
            const digit: u64 = switch (character) {
                '0'...'9' => character - '0',
                'a'...'f' => character - 'a' + 10,
                'A'...'F' => character - 'A' + 10,
                else => @compileError("invalid S-box entry"),
            };
            value = value * 16 + digit;
        }
        values[index] = value;
        index += 1;
    }
    if (index != count) @compileError("S-box has too few entries");
    return values;
}

pub fn digest(
    application_data: []const u8,
    dll_data: []const u8,
    challenge: [16]u8,
    output: []u8,
) Error![]const u8 {
    if (output.len < digest_text_len) return error.OutputTooSmall;

    const c0: i8 = @bitCast(challenge[0]);
    const c3: i8 = @bitCast(challenge[3]);
    const signed_sum: i32 = @as(i32, c0) + @as(i32, c3);
    const mode = @as(u32, @bitCast(signed_sum)) % 5;

    var input: [256]u8 = undefined;
    const input_len: usize = switch (mode) {
        0 => mode0Input(application_data, dll_data, challenge, &input),
        1 => mode1Input(application_data, dll_data, challenge, &input),
        2 => mode2Input(application_data, dll_data, challenge, &input),
        3 => mode3Input(application_data, dll_data, challenge, &input),
        4 => mode4Input(application_data, dll_data, challenge, &input),
        else => unreachable,
    };

    var raw: [64]u8 = undefined;
    whirlpool(input[0..input_len], &raw);
    const hex = "0123456789abcdef";
    for (raw, 0..) |byte, index| {
        output[index * 2] = hex[byte >> 4];
        output[index * 2 + 1] = hex[byte & 0x0f];
    }
    return output[0..digest_text_len];
}

fn mode0Input(
    application_data: []const u8,
    dll_data: []const u8,
    challenge: [16]u8,
    output: *[256]u8,
) usize {
    var app_hash: [16]u8 = undefined;
    var dll_hash: [16]u8 = undefined;
    md5vz(application_data, &app_hash);
    md5vz(dll_data, &dll_hash);

    var offset: usize = 0;
    offset += hexLower(&app_hash, output[offset..]);
    for (0..8) |index| {
        offset += signedU32Hex(challenge[index * 2], output[offset..]);
    }
    offset += hexLower(&dll_hash, output[offset..]);
    for (0..8) |index| {
        offset += signedU32Hex(challenge[index * 2 + 1], output[offset..]);
    }
    return 96;
}

fn mode1Input(
    application_data: []const u8,
    dll_data: []const u8,
    challenge: [16]u8,
    output: *[256]u8,
) usize {
    var app_hash: [20]u8 = undefined;
    var dll_hash: [20]u8 = undefined;
    sha1vz(application_data, &app_hash);
    sha1vz(dll_data, &dll_hash);
    @memcpy(output[0..20], &dll_hash);
    @memcpy(output[20..26], challenge[0..6]);
    @memcpy(output[26..46], &app_hash);
    @memcpy(output[46..56], challenge[6..16]);
    return 56;
}

fn mode2Input(
    application_data: []const u8,
    dll_data: []const u8,
    challenge: [16]u8,
    output: *[256]u8,
) usize {
    var app_hash: [16]u8 = undefined;
    var dll_hash: [20]u8 = undefined;
    ripemdvz(application_data, &app_hash);
    sha1vz(dll_data, &dll_hash);
    @memcpy(output[0..20], &dll_hash);
    @memcpy(output[20..26], challenge[0..6]);
    @memcpy(output[26..42], &app_hash);
    @memcpy(output[42..52], challenge[6..16]);
    return 52;
}

fn mode3Input(
    application_data: []const u8,
    dll_data: []const u8,
    challenge: [16]u8,
    output: *[256]u8,
) usize {
    var app_hash: [24]u8 = undefined;
    var dll_hash: [16]u8 = undefined;
    tiger(application_data, &app_hash);
    ripemdvz(dll_data, &dll_hash);
    @memcpy(output[0..24], &app_hash);
    @memcpy(output[24..34], challenge[0..10]);
    @memcpy(output[34..50], &dll_hash);
    @memcpy(output[50..56], challenge[10..16]);
    return 56;
}

fn mode4Input(
    application_data: []const u8,
    dll_data: []const u8,
    challenge: [16]u8,
    output: *[256]u8,
) usize {
    var app_hash: [20]u8 = undefined;
    var dll_hash: [24]u8 = undefined;
    tiger(dll_data, &dll_hash);
    sha1vz(application_data, &app_hash);
    @memcpy(output[0..24], &dll_hash);
    @memcpy(output[24..32], challenge[0..8]);
    @memcpy(output[32..52], &app_hash);
    @memcpy(output[52..60], challenge[8..16]);
    return 60;
}

fn hexLower(input: []const u8, output: []u8) usize {
    const hex = "0123456789abcdef";
    for (input, 0..) |byte, index| {
        output[index * 2] = hex[byte >> 4];
        output[index * 2 + 1] = hex[byte & 0x0f];
    }
    return input.len * 2;
}

fn signedU32Hex(byte: u8, output: []u8) usize {
    const signed: i8 = @bitCast(byte);
    const hex = "0123456789abcdef";
    if (signed >= 0) {
        output[0] = hex[byte >> 4];
        output[1] = hex[byte & 0x0f];
        return 2;
    }
    const value: u32 = @bitCast(@as(i32, signed));
    for (0..8) |index| {
        const shift: u5 = @intCast((7 - index) * 4);
        output[index] = hex[(value >> shift) & 0x0f];
    }
    return 8;
}

fn md5vz(input: []const u8, output: *[16]u8) void {
    var state = [4]u32{ 0x50137246, 0x8acf9dbe, 0xc9efaced, 0x25647013 };
    var offset: usize = 0;
    while (input.len - offset >= 64) : (offset += 64) {
        md5vzBlock(&state, input[offset..][0..64]);
    }

    var tail: [128]u8 = @splat(0);
    const remaining = input.len - offset;
    @memcpy(tail[0..remaining], input[offset..]);
    tail[remaining] = 0x80;
    const tail_len: usize = if (remaining < 56) 64 else 128;
    std.mem.writeInt(u64, tail[tail_len - 8 ..][0..8], @as(u64, @intCast(input.len)) * 8, .little);
    md5vzBlock(&state, tail[0..64]);
    if (tail_len == 128) md5vzBlock(&state, tail[64..128]);
    for (state, 0..) |word, index| {
        std.mem.writeInt(u32, output[index * 4 ..][0..4], word, .little);
    }
}

fn md5vzBlock(state: *[4]u32, block: *const [64]u8) void {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, block[index * 4 ..][0..4], .little);
    }
    const shifts = [64]u5{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
        5, 11, 16, 23, 5, 11, 16, 23, 5, 11, 16, 23, 5, 11, 16, 23,
        6, 10, 15, 19, 6, 10, 15, 19, 6, 10, 15, 19, 6, 10, 15, 19,
    };
    const constants = [64]u32{
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987163, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02442453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3492, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655659c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af335, 0x2ad7d2bb, 0xeb866391,
    };
    var words_state = state.*;
    for (0..64) |index| {
        const round = index / 16;
        const target = ([_]usize{ 0, 3, 2, 1 })[index % 4];
        const second = (target + 1) % 4;
        const third = (target + 2) % 4;
        const fourth = (target + 3) % 4;
        const word_index = switch (round) {
            0 => index,
            1 => (5 * index + 1) % 16,
            2 => (3 * index + 5) % 16,
            else => (7 * index) % 16,
        };
        const f = switch (round) {
            0 => (words_state[second] & words_state[third]) |
                (~words_state[second] & words_state[fourth]),
            1 => (words_state[second] & words_state[fourth]) |
                (words_state[third] & ~words_state[fourth]),
            2 => words_state[second] ^ words_state[third] ^ words_state[fourth],
            else => words_state[third] ^
                (words_state[second] | ~words_state[fourth]),
        };
        const constant = if (round == 2 and word_index == 6)
            constants[index] +% (words[2] >> 8 & 0xff)
        else
            constants[index];
        const delta: u32 = switch (round) {
            0 => 2,
            1 => @as(u32, 0) -% 2,
            2 => @as(u32, 0) -% 1,
            else => 1,
        };
        const rotated = std.math.rotl(
            u32,
            words_state[target] +% f +% words[word_index] +% constant,
            shifts[index],
        );
        words_state[target] = rotated +% words_state[second] +% delta;
    }
    for (state, words_state) |*word, value| word.* +%= value;
}

fn sha1vz(input: []const u8, output: *[20]u8) void {
    var state = [5]u32{ 0x32075416, 0xf8dae9bc, 0x73541260, 0x8acb9dfe, 0xfd0c2e1b };
    var offset: usize = 0;
    while (input.len - offset >= 64) : (offset += 64) {
        sha1vzBlock(&state, input[offset..][0..64]);
    }

    var tail: [128]u8 = @splat(0);
    const remaining = input.len - offset;
    @memcpy(tail[0..remaining], input[offset..]);
    tail[remaining] = 0x80;
    const tail_len: usize = if (remaining < 56) 64 else 128;
    std.mem.writeInt(u64, tail[tail_len - 8 ..][0..8], @as(u64, @intCast(input.len)) * 8, .big);
    sha1vzBlock(&state, tail[0..64]);
    if (tail_len == 128) sha1vzBlock(&state, tail[64..128]);
    for (state, 0..) |word, index| {
        std.mem.writeInt(u32, output[index * 4 ..][0..4], word, .big);
    }
}

fn sha1vzBlock(state: *[5]u32, block: *const [64]u8) void {
    var schedule: [80]u32 = undefined;
    for (0..16) |index| {
        schedule[index] = std.mem.readInt(u32, block[index * 4 ..][0..4], .big);
    }
    for (16..80) |index| {
        schedule[index] = std.math.rotl(
            u32,
            schedule[index - 3] ^ schedule[index - 8] ^ schedule[index - 14] ^ schedule[index - 16],
            1,
        );
    }

    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    for (0..80) |index| {
        const f: u32 = switch (index) {
            0...19 => (b & c) | (~b & d),
            20...39 => b ^ c ^ d,
            40...60 => (b & c) | (b & d) | (c & d),
            else => b ^ c ^ d,
        };
        const constant: u32 = switch (index) {
            0...19 => @as(u32, 0) -% 0x5d6aa4d4,
            20...39 => 0x16ae9deb +% @as(u32, block[0]),
            40...60 => @as(u32, 0) -% 0x34032e48,
            else => @as(u32, 0) -% 0x5cd39e93,
        };
        const temp = std.math.rotl(u32, a, 5) +% f +% e +% schedule[index] +% constant;
        e = d;
        d = c;
        c = std.math.rotl(u32, b, 30);
        b = a;
        a = temp;
    }
    state[0] +%= a +% 1;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
    state[4] +%= e;
}

fn tiger(input: []const u8, output: *[24]u8) void {
    var state = [3]u64{ 0x158e427ac96b03df, 0xf025c13b8e9da784, 0xb690ab45c3e21b74 };
    var offset: usize = 0;
    while (input.len - offset >= 64) : (offset += 64) {
        tigerBlock(&state, input[offset..][0..64]);
    }

    var tail: [128]u8 = @splat(0);
    const remaining = input.len - offset;
    @memcpy(tail[0..remaining], input[offset..]);
    tail[remaining] = 0x01;
    const tail_len: usize = if (remaining < 56) 64 else 128;
    std.mem.writeInt(u64, tail[tail_len - 8 ..][0..8], @as(u64, @intCast(input.len)) * 8, .little);
    tigerBlock(&state, tail[0..64]);
    if (tail_len == 128) tigerBlock(&state, tail[64..128]);
    for (state, 0..) |word, index| {
        std.mem.writeInt(u64, output[index * 8 ..][0..8], word, .little);
    }
}

fn tigerBlock(state: *[3]u64, block: *const [64]u8) void {
    var words: [8]u64 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u64, block[index * 8 ..][0..8], .little);
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];

    tigerPass(&a, &b, &c, &words, 5);
    tigerKeySchedule(&words);
    tigerPass(&c, &a, &b, &words, 7);
    tigerKeySchedule(&words);
    tigerPass(&b, &c, &a, &words, 9);

    state[0] = a ^ state[0];
    state[1] = b -% state[1];
    state[2] = c +% state[2];
}

fn tigerPass(a: *u64, b: *u64, c: *u64, words: *const [8]u64, multiplier: u64) void {
    tigerRound(a, b, c, words[0], multiplier);
    tigerRound(b, c, a, words[1], multiplier);
    tigerRound(c, a, b, words[2], multiplier);
    tigerRound(a, b, c, words[3], multiplier);
    tigerRound(b, c, a, words[4], multiplier);
    tigerRound(c, a, b, words[5], multiplier);
    tigerRound(a, b, c, words[6], multiplier);
    tigerRound(b, c, a, words[7], multiplier);
}

fn tigerRound(a: *u64, b: *u64, c: *u64, word: u64, multiplier: u64) void {
    c.* ^= word;
    a.* -%= tiger_sbox[@as(usize, @intCast(c.* & 0xff))] ^
        tiger_sbox[256 + @as(usize, @intCast((c.* >> 16) & 0xff))] ^
        tiger_sbox[512 + @as(usize, @intCast((c.* >> 32) & 0xff))] ^
        tiger_sbox[768 + @as(usize, @intCast((c.* >> 48) & 0xff))];
    b.* +%= tiger_sbox[768 + @as(usize, @intCast((c.* >> 8) & 0xff))] ^
        tiger_sbox[512 + @as(usize, @intCast((c.* >> 24) & 0xff))] ^
        tiger_sbox[256 + @as(usize, @intCast((c.* >> 40) & 0xff))] ^
        tiger_sbox[@as(usize, @intCast((c.* >> 56) & 0xff))];
    b.* *%= multiplier;
}

fn tigerKeySchedule(words: *[8]u64) void {
    words[0] -%= words[7] ^ 0xa5a5b5a5a5a5a7a5;
    words[1] ^= words[0];
    words[2] +%= words[1];
    words[3] -%= words[2] ^ (~words[1] << 19);
    words[4] ^= words[3];
    words[5] +%= words[4];
    words[6] -%= words[5] ^ (~words[4] >> 23);
    words[7] ^= words[6];
    words[0] +%= words[7];
    words[1] -%= words[0] ^ (~words[7] << 19);
    words[2] ^= words[1];
    words[3] +%= words[2];
    words[4] -%= words[3] ^ (~words[2] >> 23);
    words[5] ^= words[4];
    words[6] +%= words[5];
    words[7] -%= words[6] ^ 0x0123456789abcdef;
}

fn whirlpool(input: []const u8, output: *[64]u8) void {
    var state = [8]u64{ 0, 3, 5, 2, 1, 7, 4, 6 };
    var offset: usize = 0;
    while (input.len - offset >= 64) : (offset += 64) {
        whirlpoolBlock(&state, input[offset..][0..64]);
    }

    var tail: [128]u8 = @splat(0);
    const remaining = input.len - offset;
    @memcpy(tail[0..remaining], input[offset..]);
    tail[remaining] = 0x80;
    const next_index = remaining + 1;
    if (next_index > 32) {
        whirlpoolBlock(&state, tail[0..64]);
        @memset(tail[0..64], 0);
    }
    std.mem.writeInt(u64, tail[56..64], @as(u64, @intCast(input.len)) * 8, .big);
    whirlpoolBlock(&state, tail[0..64]);
    for (state, 0..) |word, index| {
        std.mem.writeInt(u64, output[index * 8 ..][0..8], word, .big);
    }
}

fn whirlpoolBlock(hash: *[8]u64, block: *const [64]u8) void {
    const round_constants = [10]u64{
        0x1823c6e887b8014f, 0x36a6d2f5796f9152, 0x60bc9b8ea30c7b35, 0x1de0d7c22e4bfe57,
        0x157737e59ff04ada, 0x58c9290ab1a06b85, 0xbd5d10f4cb3e0567, 0xe427418ba77d95d8,
        0xfbee7c66dd17479e, 0xca2dbf07ad5a8333,
    };
    var key: [2][8]u64 = undefined;
    var state: [2][8]u64 = undefined;
    for (0..8) |index| {
        key[0][index] = hash[index];
        state[0][index] = std.mem.readInt(u64, block[index * 8 ..][0..8], .big) ^ hash[index];
        hash[index] = state[0][index];
    }

    var current: usize = 0;
    for (round_constants) |round_constant| {
        const next = current ^ 1;
        for (0..8) |index| {
            key[next][index] = whirlpoolOp(key[current], index);
        }
        key[next][0] ^= round_constant;
        for (0..8) |index| {
            state[next][index] = whirlpoolOp(state[current], index) ^ key[next][index];
        }
        state[next][2] +%= 1;
        state[next][5] +%= 1;
        state[next][6] +%= 1;
        current = next;
    }
    for (0..8) |index| hash[index] ^= state[current][index];
}

fn whirlpoolOp(source: [8]u64, shift: usize) u64 {
    return whirlpool_sbox[@as(usize, @intCast((source[shift & 7] >> 56) & 0xff))] ^
        whirlpool_sbox[256 + @as(usize, @intCast(source[(shift + 7) & 7] >> 48 & 0xff))] ^
        whirlpool_sbox[512 + @as(usize, @intCast(source[(shift + 6) & 7] >> 40 & 0xff))] ^
        whirlpool_sbox[768 + @as(usize, @intCast(source[(shift + 5) & 7] >> 32 & 0xff))] ^
        whirlpool_sbox[1024 + @as(usize, @intCast(source[(shift + 4) & 7] >> 24 & 0xff))] ^
        whirlpool_sbox[1280 + @as(usize, @intCast(source[(shift + 3) & 7] >> 16 & 0xff))] ^
        whirlpool_sbox[1536 + @as(usize, @intCast(source[(shift + 2) & 7] >> 8 & 0xff))] ^
        whirlpool_sbox[1792 + @as(usize, @intCast(source[(shift + 1) & 7] & 0xff))];
}

fn ripemdvz(input: []const u8, output: *[16]u8) void {
    var state = [4]u32{ 0x10257436, 0xa8bd9cfe, 0x9efcad8b, 0x12375460 };
    var offset: usize = 0;
    while (input.len - offset >= 64) : (offset += 64) {
        ripemdvzBlock(&state, input[offset..][0..64]);
    }

    var tail: [128]u8 = @splat(0);
    const remaining = input.len - offset;
    @memcpy(tail[0..remaining], input[offset..]);
    tail[remaining] = 0x80;
    const tail_len: usize = if (remaining < 56) 64 else 128;
    std.mem.writeInt(u64, tail[tail_len - 8 ..][0..8], @as(u64, @intCast(input.len)) * 8, .little);
    ripemdvzBlock(&state, tail[0..64]);
    if (tail_len == 128) ripemdvzBlock(&state, tail[64..128]);
    for (state, 0..) |word, index| {
        std.mem.writeInt(u32, output[index * 4 ..][0..4], word, .little);
    }
}

fn ripemdvzBlock(state: *[4]u32, block: *const [64]u8) void {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, block[index * 4 ..][0..4], .little);
    }

    var work: [8]u32 = .{
        state[0], state[1], state[2], state[3],
        state[0], state[1], state[2], state[3],
    };
    for (ripemd_steps, 0..) |step, step_index| {
        if (customRipemdStep(step_index + 1, &work, &words)) |value| {
            work[step.a] = value;
        } else {
            const value = ripemdRound(
                step.round,
                work[step.b],
                work[step.c],
                work[step.d],
            ) +% work[step.a] +% words[step.word] +% step.extra;
            work[step.a] = std.math.rotl(u32, value, step.rot);
        }
    }

    const previous = state.*;
    const mixed = work[7] +% work[2] +% previous[1];
    state[1] = previous[2] +% work[3] +% work[4];
    state[2] = previous[3] +% work[0] +% work[5] +% 1;
    state[3] = previous[0] +% work[1] +% work[6];
    state[0] = mixed;
}

fn ripemdRound(round: u4, x: u32, y: u32, z: u32) u32 {
    const base: u32 = switch (round) {
        1 => x ^ y ^ z,
        2 => (x & y) | (~x & z),
        3 => (x | ~y) ^ z,
        4, 5 => (x & z) | (y & ~z),
        6 => (x | ~y) ^ z,
        7 => (x & y) | (~x & z),
        8 => x ^ y ^ z,
        else => unreachable,
    };
    const extra: u32 = switch (round) {
        1, 8 => 2,
        2 => 0x325b99a1,
        3 => 0x1baed69c,
        4 => 0xbcdcb1f9,
        5 => 0x5a82798a,
        6 => 0x41d42d5d,
        7 => 0x30ed3f68,
        else => unreachable,
    };
    return base +% extra;
}

fn customRipemdStep(step: usize, work: *[8]u32, words: *const [16]u32) ?u32 {
    return switch (step) {
        18 => std.math.rotl(
            u32,
            work[3] +% ripemdF(work[0], work[1], work[2]) +% words[4] +% 2,
            6,
        ),
        24 => std.math.rotl(
            u32,
            work[1] +% ripemdF(work[2], work[3], work[0]) +% words[3] -% 0x43234e07,
            15,
        ),
        26 => std.math.rotl(
            u32,
            work[3] +% ripemdF(work[0], work[1], work[2]) +% words[0] +% 2,
            12,
        ),
        32 => std.math.rotl(
            u32,
            work[1] +% ripemdF(work[2], work[3], work[0]) +% words[8] +% 2,
            12,
        ),
        44 => std.math.rotl(
            u32,
            work[1] +% ripemdG1(work[2], work[3], work[0]) +% words[6] +% 0x325b99a1,
            6,
        ),
        46 => std.math.rotl(
            u32,
            work[3] +% ripemdG1(work[0], work[1], work[2]) +% words[11] -% 0x43234e06,
            12,
        ),
        51 => std.math.rotl(
            u32,
            work[2] +% ripemdG2(work[3], work[1], work[0]) +% words[11] +% 0x325b99a1,
            14,
        ),
        58 => std.math.rotl(
            u32,
            work[3] +% ripemdG2(work[0], work[2], work[1]) +% words[3] +% 0x1baed69c,
            14,
        ),
        60 => std.math.rotl(
            u32,
            work[1] +% ripemdG2(work[2], work[0], work[3]) +% words[15] +% 2,
            6,
        ),
        64 => std.math.rotl(
            u32,
            work[1] +% ripemdG2(work[2], work[0], work[3]) +% words[2] -% 0x43234e04,
            12,
        ),
        71 => std.math.rotl(
            u32,
            work[6] +% ripemdG2(work[7], work[5], work[4]) +% words[11] +% 0x325b99a1,
            15,
        ),
        75 => std.math.rotl(
            u32,
            work[6] +% ripemdG2(work[7], work[5], work[4]) +% words[15] -% 0x43234e07,
            8,
        ),
        79 => std.math.rotl(
            u32,
            work[6] +% ripemdG2(work[7], work[5], work[4]) +% words[3] -% 0x43234e04,
            12,
        ),
        87 => std.math.rotl(
            u32,
            work[6] +% ripemdG1(work[7], work[4], work[5]) +% words[5] -% 0x43234e07,
            9,
        ),
        88 => std.math.rotl(
            u32,
            work[5] +% ripemdG1(work[6], work[7], work[4]) +% words[10] -% 0x43234e03,
            11,
        ),
        95 => std.math.rotl(
            u32,
            work[6] +% ripemdG1(work[7], work[4], work[5]) +% words[1] +% 0x325b99a1,
            13,
        ),
        103 => std.math.rotl(
            u32,
            work[6] +% ripemdG3(work[7], work[4], work[5]) +% words[6] -% 0x43234e02,
            6,
        ),
        106 => std.math.rotl(
            u32,
            work[7] +% ripemdG3(work[4], work[5], work[6]) +% words[8] +% 0x5a82798a,
            13,
        ),
        111 => std.math.rotl(
            u32,
            work[6] +% ripemdG3(work[7], work[4], work[5]) +% words[4] +% 0x41d42d5d,
            7,
        ),
        114 => std.math.rotl(
            u32,
            work[7] +% (work[4] ^ work[5] ^ work[6]) +% words[6] -% 0x43234e02,
            5,
        ),
        else => null,
    };
}

fn ripemdF(x: u32, y: u32, z: u32) u32 {
    return (x & (y ^ z)) ^ z;
}

fn ripemdG1(x: u32, y: u32, z: u32) u32 {
    return (x | ~y) ^ z;
}

fn ripemdG2(x: u32, y: u32, z: u32) u32 {
    return (x & y) | (z & ~y);
}

fn ripemdG3(x: u32, y: u32, z: u32) u32 {
    return (x & y) | (~x & z);
}

test "V3 primitive known answers" {
    var md5_digest: [16]u8 = undefined;
    md5vz("abc", &md5_digest);
    var md5_text: [32]u8 = undefined;
    _ = hexLower(&md5_digest, &md5_text);
    try std.testing.expectEqualStrings("d2019111e1f08912b901330e74d0acd6", &md5_text);

    var sha_digest: [20]u8 = undefined;
    sha1vz("abc", &sha_digest);
    var sha_text: [40]u8 = undefined;
    _ = hexLower(&sha_digest, &sha_text);
    try std.testing.expectEqualStrings("131dd5dfa657eee89736f363c24c61a2a4be8969", &sha_text);

    var tiger_digest: [24]u8 = undefined;
    tiger("abc", &tiger_digest);
    var tiger_text: [48]u8 = undefined;
    _ = hexLower(&tiger_digest, &tiger_text);
    try std.testing.expectEqualStrings(
        "874f688f73634ed4b23fadef27302e5b81ba495285d03032",
        &tiger_text,
    );

    var whirlpool_digest: [64]u8 = undefined;
    whirlpool("abc", &whirlpool_digest);
    var whirlpool_text: [128]u8 = undefined;
    _ = hexLower(&whirlpool_digest, &whirlpool_text);
    try std.testing.expectEqualStrings(
        "b3a3ecd0b330ea533e9e563c461d8834207c51aa5b7fc4cc8d831499c1db9347" ++
            "cdbec8311607f33f4492748204c9c4e65339d52c41b25b6f6c5f810c9e9d3de2",
        &whirlpool_text,
    );

    var ripemd_digest: [16]u8 = undefined;
    ripemdvz("abc", &ripemd_digest);
    var ripemd_text: [32]u8 = undefined;
    _ = hexLower(&ripemd_digest, &ripemd_text);
    try std.testing.expectEqualStrings("8c8425440ded3c588454bfa20811e895", &ripemd_text);
}

test "V3 digest matches all five fixed modes" {
    const expected = [5][]const u8{
        "163903b6285195b6a9117643ede31980318d665abd8335f6afafa59de61667cd69678f2e8c87259d0c55f488ac661b82ba5c98667a34f05116e1c4f8ebf7f760",
        "46b67035a2ad5789b40258f49b2760849c4b17f3aad28cbf0152f5dec8bdf8f5e282698bf5359c3bb50665970bb8bc5ae057ac07cd57a057f68e8078eedc862e",
        "2bc247b333e8bf031509894b4f0f417b875ba96998b6da9dd8677fd15001a58e9803c8c63dbc204192491b16ee3d9ac544b0be2aa565e128c8575c612ee81148",
        "d13c41fdbd6601116cbc6ac9c7213a3c2a15ecb9b9d450801f6c31b2836063bd2877ddd4699f7dcdee5fcc0522676e9c2f13fe186c2c825ca4f27b2faf04acf4",
        "aff00dbaab78fdb4f708ddd1f41d2775af501ac2846bc5cedb267e33b5fc1f5da45a0beedc32b342c3f26ef76ff2ce0d7ac5e7811614675c359231dd8f6ecb2e",
    };
    for (expected, 0..) |exact, mode| {
        var selected_challenge: [16]u8 = @splat(0);
        selected_challenge[0] = @intCast(mode);
        var output: [128]u8 = undefined;
        const result = try digest("app-data", "dll-data", selected_challenge, &output);
        try std.testing.expectEqualStrings(exact, result);
    }
}

test "V3 challenge selector interprets bytes as signed" {
    var challenge: [16]u8 = @splat(0);
    challenge[0] = 0xff;
    challenge[3] = 0xff;
    var output: [128]u8 = undefined;
    const result = try digest("app-data", "dll-data", challenge, &output);
    try std.testing.expectEqualStrings(
        "f60cfc782cc3944f3015668381b35d629aa2ba1e47a4f821e0e5a8ef3725dc2d67ae190c7876afa4a9545de289c77486ccf6231c061e164f28a546cfb8102dd4",
        result,
    );
}

test "V3 requires a complete text output buffer" {
    var short: [127]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        digest("app-data", "dll-data", @splat(0), &short),
    );
}
