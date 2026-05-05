# vlmcsd-rs

A Rust reimplementation of [vlmcsd](https://github.com/Wind4/vlmcsd) — a KMS (Key Management Service) emulator originally written in C by Wind4.

## What is this?

vlmcsd is a fully Microsoft-compatible KMS server that provides product activation services for Volume License editions of Windows, Office, and other Microsoft products. This project is a clean-room port of the original C codebase to Rust, preserving full protocol compatibility while benefiting from Rust's memory safety and modern tooling.

## Features

- Full KMS protocol support (V4, V5, V6)
- DCE/RPC framing with NDR32/NDR64 negotiation
- AES-128/160 encryption, SHA-256, HMAC-SHA256, AES-CMAC (all implemented in pure Rust, no external crypto dependencies)
- Embedded KMS database (`vlmcsd.kmd`) with product GUIDs and ePID generation
- Thread-per-connection server model
- Signal handling (SIGINT/SIGTERM) with graceful shutdown
- Daemon mode (Unix) with PID file support
- Client tool for sending activation requests
- C-compatible FFI library (shared + static) with auto-generated header

## Binaries

| Binary | Description |
|--------|-------------|
| `vlmcsd` | KMS server daemon |
| `vlmcs` | KMS client / testing tool |

## Building

```sh
cargo build --release
```

The binaries will be at `target/release/vlmcsd` and `target/release/vlmcs`.

## Usage

### Server

```sh
# Start the KMS server (default: 0.0.0.0:1688)
vlmcsd

# Custom listen address and timeout
vlmcsd -L 192.168.1.100:1688 -t 60

# Run as daemon with PID file
vlmcsd -D -p /var/run/vlmcsd.pid
```

**Server options:**

| Option | Description |
|--------|-------------|
| `-L, --listen <ADDR>` | Listen address (default: `0.0.0.0:1688`) |
| `-t, --timeout <SECS>` | Connection timeout in seconds (default: `30`) |
| `-D, --daemon` | Run as daemon (Unix only) |
| `-p, --pid-file <PATH>` | Write PID to file |
| `-V, --version` | Print version |
| `-h, --help` | Print help |

### Client

```sh
# Activate against localhost
vlmcs

# Activate against a specific server
vlmcs 192.168.1.100:1688

# Force V4 protocol
vlmcs -4 192.168.1.100

# Select a specific product
vlmcs -l 3 192.168.1.100

# List available products
vlmcs -x
```

**Client options:**

| Option | Description |
|--------|-------------|
| `-l <N>` | Product index (use `-x` to list) |
| `-4` / `-5` / `-6` | Force protocol version |
| `-n <COUNT>` | Number of requests to send |
| `-w <NAME>` | Custom workstation name |
| `-t <SECS>` | Connection timeout (default: `30`) |
| `-v` | Verbose output |
| `-x` | Show available products |
| `-V, --version` | Print version |
| `-h, --help` | Print help |

## C FFI Library

The project also builds `libvlmcsd` as both a shared library (`.so`/`.dylib`/`.dll`) and a static library (`.a`/`.lib`), with an auto-generated C header (`vlmcsd.h`).

```c
#include "vlmcsd.h"

// Start a KMS server in a background thread
vlmcsd_start_server(1688);

// Process a raw KMS request
uint8_t *response;
size_t response_len;
vlmcsd_process_request(request, request_len, &response, &response_len);
vlmcsd_free(response, response_len);

// Query the product database
int count = vlmcsd_get_product_count();
char *name = vlmcsd_get_product_name(0);
vlmcsd_free_string(name);
```

## Cross-compilation targets

Pre-built binaries are available via GitHub Actions for:

| Target | Description |
|--------|-------------|
| `aarch64-apple-darwin` | ARM64 macOS (Big Sur+) |
| `x86_64-unknown-linux-gnu` | 64-bit Linux |
| `aarch64-unknown-linux-gnu` | ARM64 Linux |
| `i686-unknown-linux-gnu` | 32-bit Linux |
| `x86_64-pc-windows-msvc` | 64-bit Windows (MSVC) |
| `i686-pc-windows-msvc` | 32-bit Windows (MSVC) |
| `aarch64-pc-windows-msvc` | ARM64 Windows (MSVC) |
| `x86_64-pc-windows-gnu` | 64-bit Windows (MinGW) |

## Project structure

```
vlmcsd-rs/
  crates/
    vlmcsd-types/      # Core types: GUID, FileTime, Request, Response
    vlmcsd-crypto/     # AES, SHA-256, HMAC, CMAC (pure Rust)
    vlmcsd-kmsdata/    # KMD database parser with embedded data
    vlmcsd-protocol/   # KMS V4/V5/V6 protocol, ePID generation
    vlmcsd-rpc/        # DCE/RPC server (bind, request, NDR32/64)
    vlmcsd-network/    # TCP server with graceful shutdown
    vlmcsd-server/     # vlmcsd binary
    vlmcsd-client/     # vlmcs binary
    vlmcsd-ffi/        # C FFI library (cdylib + staticlib)
```

## Credits

This project is a Rust port of [vlmcsd](https://github.com/Wind4/vlmcsd) by Wind4. All protocol logic, cryptographic routines, and the KMS database format are derived from the original C implementation.

## License

MIT
