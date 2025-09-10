# zig-ipcrypt

A Zig implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

## Overview

This library implements four variants of IP address encryption as specified in the ipcrypt draft:

1. **Deterministic** (`Deterministic`): Format-preserving encryption using AES-128
2. **Prefix-preserving** (`Pfx`): Maintains network prefix relationships using dual AES-128
3. **Non-deterministic with KIASU-BC** (`DeterministicNd`): Uses an 8-byte tweak
4. **Non-deterministic with AES-XTS** (`DeterministicNdx`): Uses a 16-byte tweak

## Tradeoffs

Each variant offers different tradeoffs between security, performance, and format preservation:

### Deterministic

- **Pros**:
  - Format-preserving (output is a valid IP address)
  - Smallest output size (16 bytes)
  - Fastest performance (single AES-128 operation)
- **Cons**:
  - Reveals repeated inputs (same input always produces same output)
  - No protection against correlation attacks
  - Network structure is completely scrambled

### Prefix-preserving (ipcrypt-pfx)

- **Pros**:
  - Preserves network prefix relationships (addresses from same subnet share encrypted prefix)
  - Enables network-level analytics while protecting individual addresses
  - Maintains native address sizes (4 bytes for IPv4, 16 bytes for IPv6)
  - Deterministic (allows duplicate detection)
- **Cons**:
  - Reveals network structure (by design, for analytics)
  - Slower than other deterministic methods (bit-by-bit processing)
  - Requires 32-byte key (two AES-128 keys)
  - Same input always produces same output

### Non-deterministic with KIASU-BC

- **Pros**:
  - Resists correlation attacks (same input produces different outputs)
  - Moderate output size (24 bytes)
  - Good performance (AES-128 with tweak modification)
- **Cons**:
  - Not format-preserving
  - 8-byte tweak has lower collision resistance than 16-byte tweak
  - Birthday bound of 2^32 operations per (key,ip)

### Non-deterministic with AES-XTS

- **Pros**:
  - Resists correlation attacks
  - Highest collision resistance (16-byte tweak)
  - Birthday bound of 2^64 operations per (key,ip)
- **Cons**:
  - Not format-preserving
  - Largest output size (32 bytes)
  - Requires two AES-128 keys
  - Slightly slower performance (two sequential AES operations)

## Key and Tweak Sizes

| Variant          | Key Size                              | Tweak Size          | Output Size                                   |
| ---------------- | ------------------------------------- | ------------------- | --------------------------------------------- |
| Deterministic    | 16 bytes (128 bits)                   | None                | 16 bytes (format-preserving)                  |
| Pfx              | 32 bytes (256 bits, two AES-128 keys) | None                | 4 bytes (IPv4) or 16 bytes (IPv6)             |
| DeterministicNd  | 16 bytes (128 bits)                   | 8 bytes (64 bits)   | 24 bytes (8-byte tweak + 16-byte ciphertext)  |
| DeterministicNdx | 32 bytes (256 bits, two AES-128 keys) | 16 bytes (128 bits) | 32 bytes (16-byte tweak + 16-byte ciphertext) |

## Usage

### Deterministic Encryption

```zig
const ipcrypt = @import("ipcrypt");

// Initialize with a 16-byte key
const key = [_]u8{0x2b} ** 16;
const deterministic = ipcrypt.Deterministic.init(key);

// Convert IP address to Ip16 format
const ip = try ipcrypt.Ip16.fromString("192.0.2.1");

// Encrypt
const encrypted = deterministic.encrypt(ip);

// Decrypt
const decrypted = deterministic.decrypt(encrypted);
```

### Prefix-Preserving Encryption

```zig
const ipcrypt = @import("ipcrypt");

// Initialize with a 32-byte key (two AES-128 keys)
const key = [_]u8{0x01, 0x23, ...}; // 32 bytes, K1 != K2
const pfx = try ipcrypt.Pfx.init(key);

// Convert IP address to Ip16 format
const ip = try ipcrypt.Ip16.fromString("10.0.0.47");

// Encrypt - preserves network prefix
const encrypted = pfx.encrypt(ip);
// Result: IPs from same network share encrypted prefix

// Decrypt
const decrypted = pfx.decrypt(encrypted);
```

### Non-deterministic Encryption (KIASU-BC)

```zig
const ipcrypt = @import("ipcrypt");

// Initialize with a 16-byte key
const key = [_]u8{0x2b} ** 16;
const nd = ipcrypt.DeterministicNd.init(key);

// Convert IP address to Ip16 format
const ip = try ipcrypt.Ip16.fromString("2001:db8::1");

// Encrypt with random tweak
const encrypted = nd.encrypt(ip);

// Encrypt with specific tweak
const tweak = [_]u8{0x2b} ** 8;
const encrypted_with_tweak = nd.encryptWithTweak(ip, tweak);

// Decrypt
const decrypted = nd.decrypt(encrypted);
```

### Non-deterministic Encryption (AES-XTS)

```zig
const ipcrypt = @import("ipcrypt");

// Initialize with a 32-byte key
const key = [_]u8{0x2b} ** 32;
const ndx = ipcrypt.DeterministicNdx.init(key);

// Convert IP address to Ip16 format
const ip = try ipcrypt.Ip16.fromString("2001:db8::1");

// Encrypt with random tweak
const encrypted = ndx.encrypt(ip);

// Encrypt with specific tweak
const tweak = [_]u8{0x2b} ** 16;
const encrypted_with_tweak = ndx.encryptWithTweak(ip, tweak);

// Decrypt
const decrypted = ndx.decrypt(encrypted);
```

## Building

Add this to your `build.zig.zon`:

```zig
.{
    .name = "ipcrypt",
    .url = "https://github.com/yourusername/zig-ipcrypt/archive/refs/tags/v0.1.0.tar.gz",
    .hash = "1220...",
}
```

Then in your `build.zig`:

```zig
const ipcrypt = b.dependency("ipcrypt", .{
    .target = target,
    .optimize = optimize,
});
exe.addModule("ipcrypt", ipcrypt.module("ipcrypt"));
```

## License

ISC License

## References

- [ipcrypt specification](https://github.com/jedisct1/draft-denis-ipcrypt)
- [AES-128](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [KIASU-BC](https://eprint.iacr.org/2014/831)
- [AES-XTS](https://standards.ieee.org/ieee/1619/2041/)
- [Sum of PRPs](https://link.springer.com/chapter/10.1007/3-540-45539-6_34) (Security basis for ipcrypt-pfx)
