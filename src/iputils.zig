const builtin = @import("builtin");
const std = @import("std");
const fmt = std.fmt;
const net = std.net;
const mem = std.mem;
const posix = std.posix;

const native_endian = builtin.target.cpu.arch.endian();
const ipv4_in_ipv6_prefix = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff };
pub const max_ip_str_len = 39; // 39 is the maximum length of an IPv6 address string representation

/// A 16-byte representation of an IP address, which can be either IPv4 or IPv6.
/// This is the common format used by all encryption variants.
pub const Ip16 = struct {
    bytes: [16]u8 = undefined,

    /// Create an Ip16 value from a std.net.Address. The port is ignored.
    /// For IPv4 addresses, uses the IPv4-mapped IPv6 format (::ffff:a.b.c.d).
    pub fn fromAddress(a: net.Address) !Ip16 {
        switch (a.any.family) {
            posix.AF.INET => {
                const b = a.in.sa.addr;
                var c: [16]u8 = ipv4_in_ipv6_prefix ++ [_]u8{ 0, 0, 0, 0 };
                c[12..].* = mem.toBytes(b);
                return Ip16{ .bytes = c };
            },
            posix.AF.INET6 => {
                const b = a.in6.sa.addr;
                return Ip16{ .bytes = mem.toBytes(b) };
            },
            else => {
                return error.InvalidAddress;
            },
        }
    }

    /// Convert the Ip16 value to a std.net.Address. The port is set to 0.
    pub fn toAddress(self: Ip16) !net.Address {
        if (mem.eql(u8, self.bytes[0..12], &ipv4_in_ipv6_prefix)) {
            return net.Address.initIp4(self.bytes[12..].*, 0);
        } else {
            return net.Address.initIp6(self.bytes, 0, 0, 0);
        }
    }

    /// Create an Ip16 value from a string representation of an IP address.
    /// The string can be either an IPv4 or IPv6 address.
    pub fn fromString(ip: []const u8) !Ip16 {
        const a = try std.net.Address.parseIp(ip, 0);
        return try fromAddress(a);
    }

    /// Convert the Ip16 value to a string representation of the IP address.
    /// The string will be in the format of either IPv4 or IPv6.
    /// The caller must provide a buffer of sufficient size to hold the string.
    /// The maximum size of the buffer is defined by `max_ip_str_len`.
    /// The function returns a slice of the buffer containing the string representation.
    pub fn toString(self: Ip16, buf: *[max_ip_str_len]u8) []u8 {
        const a = try self.toAddress();
        if (a.any.family == posix.AF.INET) {
            // For IPv4, we can use the simpler approach since we just need dotted decimal
            const bytes = @as(*const [4]u8, @ptrCast(&a.in.sa.addr));
            return fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3],
            }) catch unreachable;
        }
        const big_endian_parts = @as(*align(1) const [8]u16, @ptrCast(&a.in6.sa.addr));
        const native_endian_parts = switch (native_endian) {
            .big => big_endian_parts.*,
            .little => blk: {
                var buf2: [8]u16 = undefined;
                for (big_endian_parts, 0..) |part, i| buf2[i] = mem.bigToNative(u16, part);
                break :blk buf2;
            },
        };
        var longest_start: usize = 8;
        var longest_len: usize = 0;
        var current_start: usize = 0;
        var current_len: usize = 0;
        for (native_endian_parts, 0..) |part, i| {
            if (part == 0) {
                if (current_len == 0) current_start = i;
                current_len += 1;
                if (current_len > longest_len) {
                    longest_start = current_start;
                    longest_len = current_len;
                }
            } else current_len = 0;
        }
        if (longest_len < 2) {
            longest_start = 8;
            longest_len = 0;
        }

        var pos: usize = 0;
        var i: usize = 0;
        var abbrv = false;
        while (i < native_endian_parts.len) : (i += 1) {
            if (i == longest_start) {
                if (!abbrv) {
                    if (i == 0) {
                        buf[pos] = ':';
                        pos += 1;
                        buf[pos] = ':';
                        pos += 1;
                    } else {
                        buf[pos] = ':';
                        pos += 1;
                    }
                    abbrv = true;
                }
                i += longest_len - 1;
                continue;
            }
            abbrv = false;
            const part_str = fmt.bufPrint(buf[pos..], "{x}", .{native_endian_parts[i]}) catch unreachable;
            pos += part_str.len;
            if (i != native_endian_parts.len - 1) {
                buf[pos] = ':';
                pos += 1;
            }
        }
        return buf[0..pos];
    }
};
