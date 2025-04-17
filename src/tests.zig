const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

const root = @import("root.zig");
const Deterministic = root.Deterministic;
const DeterministicNd = root.DeterministicNd;
const DeterministicNdx = root.DeterministicNdx;
const Ip16 = root.Ip16;
const max_ip_str_len = root.max_ip_str_len;

test "deterministic" {
    var key: [16]u8 = undefined;
    _ = try fmt.hexToBytes(&key, "2b7e151628aed2a6abf7158809cf4f3c");
    const ip = "192.0.2.1";
    const expected = "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777";
    const deterministic = Deterministic.init(key);
    const ip16 = try Ip16.fromString(ip);
    const encrypted = deterministic.encrypt(ip16);
    const decrypted = deterministic.decrypt(encrypted);

    var str_buf: [max_ip_str_len]u8 = undefined;
    const encrypted_str = encrypted.toString(&str_buf);
    try testing.expectEqualSlices(u8, encrypted_str, expected);
    const decrypted_str = decrypted.toString(&str_buf);
    try testing.expectEqualSlices(u8, decrypted_str, ip);
}

test "nd" {
    var key: [16]u8 = undefined;
    _ = try fmt.hexToBytes(&key, "2b7e151628aed2a6abf7158809cf4f3c");
    var tweak: [8]u8 = undefined;
    _ = try fmt.hexToBytes(&tweak, "b4ecbe30b70898d7");
    const ip = "2001:db8::1";
    const expected = "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96";
    const deterministic = DeterministicNd.init(key);
    const ip16 = try Ip16.fromString(ip);
    const encrypted = deterministic.encryptWithTweak(ip16, tweak);
    const decrypted = deterministic.decrypt(encrypted);

    var str_buf: [max_ip_str_len]u8 = undefined;
    const encrypted_str = fmt.bytesToHex(encrypted, .lower);
    try testing.expectEqualSlices(u8, &encrypted_str, expected);
    const decrypted_str = decrypted.toString(&str_buf);
    try testing.expectEqualSlices(u8, decrypted_str, ip);
}

test "ndx" {
    var key: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&key, "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b");
    var tweak: [16]u8 = undefined;
    _ = try fmt.hexToBytes(&tweak, "21bd1834bc088cd2b4ecbe30b70898d7");
    const ip = "2001:db8::1";
    const expected = "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4";
    const deterministic = DeterministicNdx.init(key);
    const ip16 = try Ip16.fromString(ip);
    const encrypted = deterministic.encryptWithTweak(ip16, tweak);
    const decrypted = deterministic.decrypt(encrypted);

    var str_buf: [max_ip_str_len]u8 = undefined;
    const encrypted_str = fmt.bytesToHex(encrypted, .lower);
    try testing.expectEqualSlices(u8, &encrypted_str, expected);
    const decrypted_str = decrypted.toString(&str_buf);
    try testing.expectEqualSlices(u8, decrypted_str, ip);
}
