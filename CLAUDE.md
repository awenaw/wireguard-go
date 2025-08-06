# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go implementation of the WireGuard VPN protocol. It provides a userspace WireGuard daemon that can be used on platforms where kernel module integration is not available or desired.

## Build Commands

- **Build the project**: `make` or `make wireguard-go`
- **Run tests**: `make test` (runs `go test ./...`)
- **Install**: `make install` (installs to `$PREFIX/bin`, defaults to `/usr/bin`)
- **Clean**: `make clean`

## Running the Application

- **Basic usage**: `./wireguard-go wg0`
- **Foreground mode**: `./wireguard-go -f wg0` or `./wireguard-go --foreground wg0`
- **Set log level**: `LOG_LEVEL=debug ./wireguard-go wg0` (options: verbose/debug, error, silent)
- **Version info**: `./wireguard-go --version`

## Architecture Overview

### Core Components

1. **Device (`device/device.go`)**: Central orchestrator managing the entire WireGuard instance
   - Manages network binding, peers, encryption queues, and TUN interface
   - Handles device lifecycle (up/down/close states)
   - Coordinates packet processing pipelines

2. **Peer (`device/peer.go`)**: Represents individual remote WireGuard endpoints
   - Manages connection state, timers, and endpoint information
   - Handles handshakes and key rotation
   - Tracks bandwidth statistics and connection metrics

3. **Network Binding (`conn/`)**: Handles UDP network communication
   - Platform-specific implementations for different operating systems
   - Supports batch packet processing for performance
   - Manages socket options and network features

4. **TUN Interface (`tun/`)**: Manages the virtual network interface
   - Platform-specific implementations (Linux, macOS, Windows, FreeBSD, OpenBSD)
   - Handles packet read/write operations
   - Supports various TUN device creation methods

### Key Packages

- `device/`: Core WireGuard protocol implementation
- `conn/`: Network connection and UDP socket management
- `tun/`: Virtual network interface abstraction
- `ipc/`: UAPI (Userspace API) for configuration
- `ratelimiter/`: Rate limiting for security
- `replay/`: Anti-replay protection
- `tai64n/`: Timestamp format implementation

### Packet Processing Flow

1. Packets received from network via `conn.Bind`
2. Processed through receive pipeline in `device/receive.go`
3. Decrypted and forwarded to TUN interface
4. Outbound packets read from TUN interface
5. Processed through send pipeline in `device/send.go`
6. Encrypted and sent via network binding

## Testing

The project uses Go's standard testing framework:
- Unit tests are present throughout the codebase (files ending with `_test.go`)
- Test coverage includes cryptographic functions, network operations, and protocol logic
- Platform-specific tests exist for different operating systems

## Platform Support

- **Linux**: Recommended to use kernel module instead, but userspace works
- **macOS**: Uses utun driver, interface names must be `utun[0-9]+` or `utun`
- **Windows**: Integrated with WireGuard Windows app
- **FreeBSD/OpenBSD**: Full support with platform-specific adaptations

## Configuration

The daemon is configured via the UAPI (same interface as `wg(8)` command-line tool):
- Configuration socket created at `/var/run/wireguard/<interface>.sock`
- Standard WireGuard configuration format supported
- Interface can be configured using `wg` and `ip` commands

## Chinese Documentation

The `device_comments/` directory contains detailed Chinese documentation:
- `device_commented.go`: Detailed annotations for Device struct and lifecycle
- `peer_commented.go`: Detailed annotations for Peer struct and operations

## Dependencies

- `golang.org/x/crypto`: Cryptographic primitives
- `golang.org/x/net`: Network utilities  
- `golang.org/x/sys`: System call interfaces
- `gvisor.dev/gvisor`: Netstack integration for testing