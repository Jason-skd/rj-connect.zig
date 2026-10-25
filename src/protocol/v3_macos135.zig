//! V3 digest inputs compiled into the macOS 1.35 client build.

const std = @import("std");
const v3 = @import("v3.zig");

/// Application data array embedded in the target client binary.
pub const application_data = @embedFile("v3_macos135_a.bin");
/// Dynamic-library data array embedded in the target client binary.
pub const dll_data = @embedFile("v3_macos135_d.bin");

pub fn digest(challenge: [16]u8, output: []u8) v3.Error![]const u8 {
    return v3.digest(application_data, dll_data, challenge, output);
}

test "macOS 1.35 materials reproduce a captured V3 digest" {
    var challenge: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &challenge,
        "ef8856459d2e42107b57bc25e40f8879",
    );
    var output: [v3.digest_text_len]u8 = undefined;
    const text = try digest(challenge, &output);
    try std.testing.expectEqualSlices(
        u8,
        "5562e31ad473d66ad197870cd134e5984c94ef3ed83e0cda412322ac94c41d7c" ++
            "8ea82238aa6bf1dba586162cf9a39bee952fcedc566a8a462c51f4913bb77299",
        text,
    );
}
