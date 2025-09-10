//! IP address encryption and obfuscation library implementing the ipcrypt specification.
//!
//! This library provides four variants of IP address encryption:
//! - `Deterministic`: Format-preserving encryption using AES-128
//! - `Pfx`: Prefix-preserving encryption using dual AES-128
//! - `DeterministicNd`: Non-deterministic encryption using KIASU-BC with 8-byte tweak
//! - `DeterministicNdx`: Non-deterministic encryption using AES-XTS with 16-byte tweak
//!
//! Key Sizes:
//! - `Deterministic`: 16 bytes (128 bits)
//! - `Pfx`: 32 bytes (256 bits, two AES-128 keys)
//! - `DeterministicNd`: 16 bytes (128 bits)
//! - `DeterministicNdx`: 32 bytes (256 bits, two AES-128 keys)
//!
//! Tweak Sizes:
//! - `Deterministic`: No tweak used
//! - `Pfx`: No tweak used
//! - `DeterministicNd`: 8 bytes (64 bits)
//! - `DeterministicNdx`: 16 bytes (128 bits)
//!
//! Output Sizes:
//! - `Deterministic`: 16 bytes (format-preserving)
//! - `Pfx`: 4 bytes for IPv4, 16 bytes for IPv6 (prefix-preserving)
//! - `DeterministicNd`: 24 bytes (8-byte tweak + 16-byte ciphertext)
//! - `DeterministicNdx`: 32 bytes (16-byte tweak + 16-byte ciphertext)

const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;

const iputils = @import("iputils.zig");
const pfx = @import("pfx.zig");

const AesBlock = crypto.core.aes.Block;
const Aes128 = crypto.core.aes.Aes128;
const AesEncCtx = crypto.core.aes.AesEncryptCtx(Aes128);
const AesDecCtx = crypto.core.aes.AesDecryptCtx(Aes128);

/// The maximum length of the string representation of an IP address.
pub const max_ip_str_len = iputils.max_ip_str_len;

/// A 16-byte representation of an IP address, which can be either IPv4 or IPv6.
/// This is the common format used by all encryption variants.
pub const Ip16 = iputils.Ip16;

/// Prefix-preserving encryption scheme.
pub const Pfx = pfx.Pfx;

/// A deterministic, format-preserving encryption scheme for IP addresses.
/// Uses AES-128 in a single-block operation.
/// Key size: 16 bytes (128 bits)
/// Output size: 16 bytes (format-preserving)
pub const Deterministic = struct {
    enc_ctx: AesEncCtx = undefined,
    dec_ctx: AesDecCtx = undefined,

    //// Create a new Deterministic instance with the given key.
    /// The key must be 16 bytes long.
    pub fn init(key: [16]u8) Deterministic {
        const enc_ctx = AesEncCtx.init(key);
        const dec_ctx = AesDecCtx.initFromEnc(enc_ctx);
        return Deterministic{
            .enc_ctx = enc_ctx,
            .dec_ctx = dec_ctx,
        };
    }

    /// Encrypt the given IP address using the deterministic encryption scheme.
    pub fn encrypt(self: Deterministic, ip: Ip16) Ip16 {
        var out: Ip16 = undefined;
        self.enc_ctx.encrypt(&out.bytes, &ip.bytes);
        return out;
    }

    //// Decrypt the given ciphertext using the deterministic decryption scheme.
    pub fn decrypt(self: Deterministic, ip: Ip16) Ip16 {
        var out: Ip16 = undefined;
        self.dec_ctx.decrypt(&out.bytes, &ip.bytes);
        return out;
    }
};

/// A non-deterministic encryption scheme for IP addresses using KIASU-BC.
/// Uses an 8-byte tweak to provide non-deterministic encryption.
/// Key size: 16 bytes (128 bits)
/// Tweak size: 8 bytes (64 bits)
/// Output size: 24 bytes (8-byte tweak + 16-byte ciphertext)
pub const DeterministicNd = struct {
    enc_ctx: AesEncCtx = undefined,

    //// Create a new DeterministicNd instance with the given key.
    pub fn init(key: [16]u8) DeterministicNd {
        const enc_ctx = AesEncCtx.init(key);
        return DeterministicNd{
            .enc_ctx = enc_ctx,
        };
    }

    /// Encrypt the given IP address using a given tweak.
    /// The tweak must be 8 bytes long and randomly generated.
    pub fn encryptWithTweak(self: DeterministicNd, ip: Ip16, tweak: [8]u8) [24]u8 {
        var out: [24]u8 = undefined;
        out[0..8].* = tweak;
        const mask = AesBlock.fromBytes(&[16]u8{
            tweak[0], tweak[1], 0, 0, tweak[2], tweak[3], 0, 0, tweak[4], tweak[5], 0, 0, tweak[6], tweak[7], 0, 0,
        });
        var ctx = self.enc_ctx;
        for (&ctx.key_schedule.round_keys) |*round_key| {
            round_key.* = round_key.xorBlocks(mask);
        }
        ctx.encrypt(out[8..], &ip.bytes);
        return out;
    }

    /// Encrypt the given IP address using a randomly generated tweak.
    pub fn encrypt(self: DeterministicNd, ip: Ip16) [32]u8 {
        var tweak: [8]u8 = undefined;
        crypto.random.bytes(&tweak);
        return self.encryptWithTweak(ip, tweak);
    }

    //// Decrypt the given ciphertext.
    pub fn decrypt(self: DeterministicNd, ciphertext: [24]u8) Ip16 {
        const tweak = ciphertext[0..8];
        const mask = AesBlock.fromBytes(&[16]u8{
            tweak[0], tweak[1], 0, 0, tweak[2], tweak[3], 0, 0, tweak[4], tweak[5], 0, 0, tweak[6], tweak[7], 0, 0,
        });
        var enc_ctx = self.enc_ctx;
        for (&enc_ctx.key_schedule.round_keys) |*round_key| {
            round_key.* = round_key.xorBlocks(mask);
        }
        const ctx = AesDecCtx.initFromEnc(enc_ctx);
        var out: Ip16 = undefined;
        ctx.decrypt(&out.bytes, ciphertext[8..]);
        return out;
    }
};

/// A non-deterministic encryption scheme for IP addresses using AES-XTS.
/// Uses a 16-byte tweak to provide non-deterministic encryption.
/// Key size: 32 bytes (256 bits, two AES-128 keys)
/// Tweak size: 16 bytes (128 bits)
/// Output size: 32 bytes (16-byte tweak + 16-byte ciphertext)
pub const DeterministicNdx = struct {
    enc1_ctx: AesEncCtx = undefined,
    enc2_ctx: AesEncCtx = undefined,
    dec1_ctx: AesDecCtx = undefined,
    dec2_ctx: AesDecCtx = undefined,

    /// Create a new DeterministicNdx instance with the given key.
    pub fn init(key: [32]u8) DeterministicNdx {
        const enc1_ctx = AesEncCtx.init(key[0..16].*);
        const dec1_ctx = AesDecCtx.initFromEnc(enc1_ctx);
        const enc2_ctx = AesEncCtx.init(key[16..].*);
        const dec2_ctx = AesDecCtx.initFromEnc(enc2_ctx);
        return DeterministicNdx{
            .enc1_ctx = enc1_ctx,
            .enc2_ctx = enc2_ctx,
            .dec1_ctx = dec1_ctx,
            .dec2_ctx = dec2_ctx,
        };
    }

    /// Encrypt the given IP address using a given tweak.
    /// The tweak must be 16 bytes long and randomly generated.
    pub fn encryptWithTweak(self: DeterministicNdx, ip: Ip16, tweak: [16]u8) [32]u8 {
        var encrypted_tweak: [16]u8 = undefined;
        self.enc2_ctx.encrypt(&encrypted_tweak, &tweak);
        var ipx = ip.bytes;
        for (&ipx, encrypted_tweak) |*p, x| {
            p.* ^= x;
        }
        var out: [32]u8 = undefined;
        out[0..16].* = tweak;
        self.enc1_ctx.encrypt(out[16..], &ipx);
        for (out[16..], encrypted_tweak) |*p, x| {
            p.* ^= x;
        }
        return out;
    }

    /// Encrypt the given IP address using a randomly generated tweak.
    pub fn encrypt(self: DeterministicNdx, ip: Ip16) [32]u8 {
        var tweak: [16]u8 = undefined;
        crypto.random.bytes(&tweak);
        return self.encryptWithTweak(ip, tweak);
    }

    /// Decrypt the given ciphertext.
    pub fn decrypt(self: DeterministicNdx, ciphertext: [32]u8) Ip16 {
        const tweak = ciphertext[0..16];
        var encrypted_tweak: [16]u8 = undefined;
        self.enc2_ctx.encrypt(&encrypted_tweak, tweak);
        var ipx = ciphertext[16..].*;
        for (&ipx, encrypted_tweak) |*p, x| {
            p.* ^= x;
        }
        var out: Ip16 = undefined;
        self.dec1_ctx.decrypt(&out.bytes, &ipx);
        for (&out.bytes, encrypted_tweak) |*p, x| {
            p.* ^= x;
        }
        return out;
    }
};

test {
    _ = @import("tests.zig");
}
