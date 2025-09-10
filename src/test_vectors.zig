const std = @import("std");
const testing = std.testing;
const json = std.json;
const fmt = std.fmt;

const pfx = @import("pfx.zig");
const iputils = @import("iputils.zig");
const root = @import("root.zig");

const Ip16 = iputils.Ip16;
const Pfx = pfx.Pfx;
const Deterministic = root.Deterministic;
const Nd = root.Nd;
const Ndx = root.Ndx;

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, hex.len / 2);
    _ = try fmt.hexToBytes(result, hex);
    return result;
}

test "verify all test vectors from the specification" {
    const file_contents = @embedFile("test_vectors.json");
    const allocator = testing.allocator;
    const parsed = try json.parseFromSlice(json.Value, allocator, file_contents, .{});
    defer parsed.deinit();

    const test_vectors = parsed.value.array.items;
    for (test_vectors) |test_vector| {
        const obj = test_vector.object;
        const variant = obj.get("variant").?.string;

        if (std.mem.eql(u8, variant, "ipcrypt-pfx")) {
            const key_hex = obj.get("key").?.string;
            const ip_str = obj.get("ip").?.string;
            const expected_encrypted = obj.get("encrypted_ip").?.string;

            const key_bytes = try hexToBytes(allocator, key_hex);
            defer allocator.free(key_bytes);

            try testing.expectEqual(@as(usize, 32), key_bytes.len);

            var key_array: [32]u8 = undefined;
            @memcpy(&key_array, key_bytes);

            const cipher = try Pfx.init(key_array);

            const input_ip = try Ip16.fromString(ip_str);
            const encrypted = cipher.encrypt(input_ip);

            var buf: [iputils.max_ip_str_len]u8 = undefined;
            const encrypted_str = encrypted.toString(&buf);

            try testing.expectEqualStrings(expected_encrypted, encrypted_str);
        } else if (std.mem.eql(u8, variant, "ipcrypt-deterministic")) {
            const key_hex = obj.get("key").?.string;
            const ip_str = obj.get("ip").?.string;
            const expected_encrypted = obj.get("encrypted_ip").?.string;

            const key_bytes = try hexToBytes(allocator, key_hex);
            defer allocator.free(key_bytes);

            try testing.expectEqual(@as(usize, 16), key_bytes.len);

            var key_array: [16]u8 = undefined;
            @memcpy(&key_array, key_bytes);

            const cipher = Deterministic.init(key_array);

            const input_ip = try Ip16.fromString(ip_str);
            const encrypted = cipher.encrypt(input_ip);

            var buf: [iputils.max_ip_str_len]u8 = undefined;
            const encrypted_str = encrypted.toString(&buf);

            try testing.expectEqualStrings(expected_encrypted, encrypted_str);
        } else if (std.mem.eql(u8, variant, "ipcrypt-nd")) {
            const key_hex = obj.get("key").?.string;
            const ip_str = obj.get("ip").?.string;
            const tweak_hex = obj.get("tweak").?.string;
            const expected_encrypted = obj.get("output").?.string;

            const key_bytes = try hexToBytes(allocator, key_hex);
            defer allocator.free(key_bytes);

            try testing.expectEqual(@as(usize, 16), key_bytes.len);

            var key_array: [16]u8 = undefined;
            @memcpy(&key_array, key_bytes);

            const cipher = Nd.init(key_array);

            const input_ip = try Ip16.fromString(ip_str);

            const tweak_bytes = try hexToBytes(allocator, tweak_hex);
            defer allocator.free(tweak_bytes);
            try testing.expectEqual(@as(usize, 8), tweak_bytes.len);

            var tweak_array: [8]u8 = undefined;
            @memcpy(&tweak_array, tweak_bytes);

            const encrypted = cipher.encryptWithTweak(input_ip, tweak_array);
            const encrypted_hex = fmt.bytesToHex(encrypted, .lower);

            try testing.expectEqualStrings(expected_encrypted, &encrypted_hex);
        } else if (std.mem.eql(u8, variant, "ipcrypt-ndx")) {
            const key_hex = obj.get("key").?.string;
            const ip_str = obj.get("ip").?.string;
            const tweak_hex = obj.get("tweak").?.string;
            const expected_encrypted = obj.get("output").?.string;

            const key_bytes = try hexToBytes(allocator, key_hex);
            defer allocator.free(key_bytes);

            try testing.expectEqual(@as(usize, 32), key_bytes.len);

            var key_array: [32]u8 = undefined;
            @memcpy(&key_array, key_bytes);

            const cipher = Ndx.init(key_array);

            const input_ip = try Ip16.fromString(ip_str);

            const tweak_bytes = try hexToBytes(allocator, tweak_hex);
            defer allocator.free(tweak_bytes);
            try testing.expectEqual(@as(usize, 16), tweak_bytes.len);

            var tweak_array: [16]u8 = undefined;
            @memcpy(&tweak_array, tweak_bytes);

            const encrypted = cipher.encryptWithTweak(input_ip, tweak_array);
            const encrypted_hex = fmt.bytesToHex(encrypted, .lower);

            try testing.expectEqualStrings(expected_encrypted, &encrypted_hex);
        }
    }
}
