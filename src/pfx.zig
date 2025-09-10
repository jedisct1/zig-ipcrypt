//! Prefix-preserving encryption for IP addresses using ipcrypt-pfx.
//!
//! This module implements the ipcrypt-pfx variant which preserves network prefix
//! relationships in encrypted IP addresses. Addresses from the same network produce
//! encrypted addresses that share a common encrypted prefix.
//!
//! Key size: 32 bytes (256 bits, split into two AES-128 keys)
//! Output size: 4 bytes for IPv4, 16 bytes for IPv6 (maintains native sizes)

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const iputils = @import("iputils.zig");

const AesBlock = crypto.core.aes.Block;
const Aes128 = crypto.core.aes.Aes128;
const AesEncCtx = crypto.core.aes.AesEncryptCtx(Aes128);
const AesDecCtx = crypto.core.aes.AesDecryptCtx(Aes128);

pub const Ip16 = iputils.Ip16;

/// A prefix-preserving encryption scheme for IP addresses.
/// Uses the XOR of two independently keyed AES-128 encryptions as a PRF.
/// Key size: 32 bytes (256 bits)
pub const Pfx = struct {
    enc1_ctx: AesEncCtx = undefined,
    enc2_ctx: AesEncCtx = undefined,

    /// Create a new Pfx instance with the given key.
    /// The key must be 32 bytes long.
    pub fn init(key: [32]u8) !Pfx {
        // Split the key into two AES-128 keys
        const k1 = key[0..16].*;
        const k2 = key[16..32].*;

        // Check that K1 and K2 are different
        if (crypto.timing_safe.eql([16]u8, k1, k2)) {
            return error.IdenticalKeyHalves;
        }

        const enc1_ctx = AesEncCtx.init(k1);
        const enc2_ctx = AesEncCtx.init(k2);

        return Pfx{
            .enc1_ctx = enc1_ctx,
            .enc2_ctx = enc2_ctx,
        };
    }

    /// Check if a 16-byte array has the IPv4-mapped IPv6 prefix (::ffff:0:0/96).
    fn isIpv4Mapped(bytes16: [16]u8) bool {
        const ipv4_mapped_prefix = @as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff };
        return mem.eql(u8, bytes16[0..12], &ipv4_mapped_prefix);
    }

    /// Get bit at position from 16-byte array.
    /// position: 0 = LSB of byte 15, 127 = MSB of byte 0
    fn getBit(data: [16]u8, position: u8) u1 {
        const byte_index = 15 - (position / 8);
        const bit_index = @as(u3, @intCast(position % 8));
        return @truncate(data[byte_index] >> bit_index);
    }

    /// Set bit at position in 16-byte array if value is 1.
    /// position: 0 = LSB of byte 15, 127 = MSB of byte 0
    fn setBit(data: *[16]u8, position: u8, value: u1) void {
        const byte_index = 15 - (position / 8);
        const bit_index = @as(u3, @intCast(position % 8));
        data[byte_index] |= (@as(u8, value) << bit_index);
    }

    /// Shift a 16-byte array one bit to the left.
    fn shiftLeftOneBit(data: [16]u8) [16]u8 {
        const x = mem.readInt(u128, &data, .big);
        var shifted: [16]u8 = undefined;
        mem.writeInt(u128, &shifted, x << 1, .big);
        return shifted;
    }

    /// Pad prefix for prefix_len_bits=0 (IPv6).
    const padPrefix0 = @as([15]u8, @splat(0)) ++ [_]u8{0x01};
    /// Pad prefix for prefix_len_bits=96 (IPv4-mapped).
    const padPrefix96 = prefix: {
        var padded: [16]u8 = @splat(0);
        padded[3] = 0x01; // Set bit at position 96 (bit 0 of byte 3)
        padded[14] = 0xFF; // IPv4-mapped prefix
        padded[15] = 0xFF; // IPv4-mapped prefix
        break :prefix padded;
    };

    /// Encrypt an IP address using prefix-preserving encryption.
    pub fn encrypt(self: Pfx, ip: Ip16) Ip16 {
        const bytes16 = ip.bytes;
        var encrypted: [16]u8 = @splat(0);

        // Determine starting point
        const is_ipv4 = isIpv4Mapped(bytes16);
        const prefix_start: u8 = if (is_ipv4) 96 else 0;

        // If IPv4-mapped, copy the IPv4-mapped prefix
        if (is_ipv4) {
            @memcpy(encrypted[0..12], bytes16[0..12]);
        }

        // Initialize padded_prefix for the starting prefix length
        var padded_prefix = if (is_ipv4) padPrefix96 else padPrefix0;

        // Process each bit position
        var prefix_len_bits: u8 = prefix_start;
        while (prefix_len_bits < 128) : (prefix_len_bits += 1) {
            // Compute pseudorandom function with dual AES encryption
            var e1: [16]u8 = undefined;
            var e2: [16]u8 = undefined;
            self.enc1_ctx.encrypt(&e1, &padded_prefix);
            self.enc2_ctx.encrypt(&e2, &padded_prefix);

            // XOR the two encryptions
            var e: [16]u8 = undefined;
            for (&e, e1, e2) |*dst, a, b| {
                dst.* = a ^ b;
            }

            // Output of the PRF is the least significant bit
            const cipher_bit: u1 = @truncate(e[15]);

            // Extract the current bit from the original IP
            const current_bit_pos = 127 - prefix_len_bits;
            const original_bit = getBit(bytes16, current_bit_pos);

            // Set the bit in the encrypted result
            setBit(&encrypted, current_bit_pos, cipher_bit ^ original_bit);

            // Prepare padded_prefix for next iteration
            padded_prefix = shiftLeftOneBit(padded_prefix);
            setBit(&padded_prefix, 0, original_bit);
        }

        return Ip16{ .bytes = encrypted };
    }

    /// Decrypt an IP address using prefix-preserving encryption.
    pub fn decrypt(self: Pfx, encrypted_ip: Ip16) Ip16 {
        const encrypted_bytes = encrypted_ip.bytes;
        var decrypted: [16]u8 = @splat(0);

        // Determine if this was originally IPv4-mapped
        const is_ipv4 = isIpv4Mapped(encrypted_bytes);
        const prefix_start: u8 = if (is_ipv4) 96 else 0;

        // If this was originally IPv4, set up the IPv4-mapped IPv6 prefix
        if (is_ipv4) {
            decrypted[10] = 0xff;
            decrypted[11] = 0xff;
        }

        // Initialize padded_prefix for the starting prefix length
        var padded_prefix = if (is_ipv4) padPrefix96 else padPrefix0;

        // Process each bit position
        var prefix_len_bits: u8 = prefix_start;
        while (prefix_len_bits < 128) : (prefix_len_bits += 1) {
            // Compute pseudorandom function with dual AES encryption
            var e1: [16]u8 = undefined;
            var e2: [16]u8 = undefined;
            self.enc1_ctx.encrypt(&e1, &padded_prefix);
            self.enc2_ctx.encrypt(&e2, &padded_prefix);

            // XOR the two encryptions
            var e: [16]u8 = undefined;
            for (&e, e1, e2) |*dst, a, b| {
                dst.* = a ^ b;
            }

            // Output of the PRF is the least significant bit
            const cipher_bit: u1 = @truncate(e[15]);

            // Extract the current bit from the encrypted IP
            const current_bit_pos = 127 - prefix_len_bits;
            const encrypted_bit = getBit(encrypted_bytes, current_bit_pos);

            // Recover the original bit
            const original_bit = cipher_bit ^ encrypted_bit;
            setBit(&decrypted, current_bit_pos, original_bit);

            // Prepare padded_prefix for next iteration
            padded_prefix = shiftLeftOneBit(padded_prefix);
            setBit(&padded_prefix, 0, original_bit);
        }

        return Ip16{ .bytes = decrypted };
    }
};
