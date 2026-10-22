//! Session actions and the ownership boundary for returned results.

const std = @import("std");
const types = @import("types.zig");

pub const Action = union(enum) {
    send_frame: []u8,
    request_credentials: types.CredentialPurpose,
    poll_dhcp,
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
        for (self.actions) |action| {
            switch (action) {
                .send_frame => |frame| allocator.free(frame),
                else => {},
            }
        }
        allocator.free(self.actions);
        self.* = undefined;
    }
};

/// Builds one transaction's actions and owns any frame allocated before commit.
pub const OutcomeBuilder = struct {
    allocator: std.mem.Allocator,
    actions: [8]Action = undefined,
    action_count: usize = 0,
    frames: [8][]u8 = undefined,
    frame_count: usize = 0,
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
        if (self.frame_count == self.frames.len) {
            self.allocator.free(frame);
            return error.InvalidState;
        }
        self.frames[self.frame_count] = frame;
        self.frame_count += 1;
        try self.addAction(.{ .send_frame = frame });
    }

    pub fn finish(self: *OutcomeBuilder) types.Error![]Action {
        const actions = try self.allocator.dupe(Action, self.actions[0..self.action_count]);
        self.transferred = true;
        return actions;
    }

    pub fn deinit(self: *OutcomeBuilder) void {
        if (!self.transferred) {
            for (self.frames[0..self.frame_count]) |frame| self.allocator.free(frame);
        }
        self.* = undefined;
    }
};
