//! Session actions and the ownership boundary for returned results.

const std = @import("std");
const types = @import("types.zig");

pub const Action = union(enum) {
    send_frame: []u8,
    request_credentials: types.CredentialPurpose,
    poll_dhcp,
    tunnel_input: types.TunnelInput,
    authenticate_mschapv2: types.Mschapv2Challenge,
    verify_mschapv2: types.Mschapv2Challenge,
    direct_auth_result: types.DirectAuthResult,
    reauth_required,
};

pub const Outcome = struct {
    /// Sending actions own their frame bytes until `deinit` is called.
    actions: []Action,
    previous_phase: types.ActivePhase,
    phase: types.ActivePhase,
    next_deadline: ?std.Io.Timestamp,
    failure: ?types.FailureReason,
    generation: types.Generation,

    /// Releases every owned frame and the action slice using the allocator passed to `Session.init`.
    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        freeActions(allocator, self.actions);
        self.* = undefined;
    }
};

pub fn freeActions(allocator: std.mem.Allocator, actions: []Action) void {
    for (actions) |action| freeAction(allocator, action);
    allocator.free(actions);
}

fn freeAction(allocator: std.mem.Allocator, action: Action) void {
    switch (action) {
        .send_frame => |frame| allocator.free(frame),
        .tunnel_input => |input| allocator.free(input.bytes),
        .authenticate_mschapv2 => |challenge| allocator.free(challenge.request_data),
        .verify_mschapv2 => |challenge| allocator.free(challenge.request_data),
        .direct_auth_result => |result| {
            if (result.server_message_gbk) |message| allocator.free(message);
        },
        else => {},
    }
}

/// Builds one transaction's actions and owns any frame allocated before commit.
pub const OutcomeBuilder = struct {
    allocator: std.mem.Allocator,
    actions: [32]Action = undefined,
    action_count: usize = 0,
    transferred: bool = false,

    pub fn init(allocator: std.mem.Allocator) OutcomeBuilder {
        return .{ .allocator = allocator };
    }

    pub fn addAction(self: *OutcomeBuilder, action: Action) types.Error!void {
        if (self.action_count == self.actions.len) return error.InvalidState;
        self.actions[self.action_count] = action;
        self.action_count += 1;
    }

    pub fn addFrame(self: *OutcomeBuilder, frame: []u8) types.Error!void {
        self.addAction(.{ .send_frame = frame }) catch |err| {
            self.allocator.free(frame);
            return err;
        };
    }

    pub fn finish(self: *OutcomeBuilder) types.Error![]Action {
        const actions = try self.allocator.dupe(Action, self.actions[0..self.action_count]);
        self.transferred = true;
        return actions;
    }

    pub fn deinit(self: *OutcomeBuilder) void {
        if (!self.transferred) {
            for (self.actions[0..self.action_count]) |action| freeAction(self.allocator, action);
        }
        self.* = undefined;
    }
};
