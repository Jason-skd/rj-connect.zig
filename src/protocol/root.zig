//! Wire-level protocol types and codecs.

const std = @import("std");

pub const wire = @import("wire.zig");
pub const eapol = @import("eapol.zig");
pub const eap = @import("eap.zig");
pub const dhcp = @import("dhcp.zig");
pub const crypto = @import("crypto.zig");
pub const v3 = @import("v3.zig");

test {
    _ = wire;
    _ = eapol;
    _ = eap;
    _ = dhcp;
    _ = crypto;
    _ = v3;

    // Research-only protocol modules stay internal to the package.
    _ = @import("peap.zig");
    _ = @import("ruijie_peap.zig");
    _ = @import("vendor.zig");
    _ = @import("direct.zig");
    _ = @import("sam.zig");
    _ = @import("smp.zig");
    _ = @import("des.zig");
    _ = @import("ruijie_eap_md5.zig");
    _ = @import("v3_macos135.zig");
}
