# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Crypta is a peer-to-peer network providing a distributed, encrypted, and decentralized datastore. It is a fork of
Hyphanet (formerly Freenet), building upon its technology for censorship-resistant communication and publishing. The
repository contains the reference node implementation (the "Crypta reference daemon") written primarily in Java with
some Kotlin components.

## Development Commands

### Building

- Build the node JAR: `./gradlew jar`
- Clean build: `./gradlew clean jar`
- Build with SHA-256 hash: The build automatically displays the SHA-256 hash of the produced cryptad.jar

### Testing

- Run all tests in parallel: `./gradlew --parallel test`
- Run specific test class: `./gradlew --parallel test --tests *TestClassName`
- Run specific test method: `./gradlew --parallel test --tests *TestClassName.methodName`

### Code Quality

- Compile only: `./gradlew compileJava`
- Run without executing tests: The project doesn't appear to have dedicated lint tasks configured

### Running Your Build

1. Build: `./gradlew jar`
2. Stop running node
3. Replace existing node JAR with `build/libs/cryptad.jar`
4. Restart node

## Architecture Overview

### Core Network Layer (`network.crypta.node`)

The heart of the P2P network implementation:

- **Node.java**: Main node class coordinating all subsystems
- **PeerNode/PeerManager**: Manages connections to other nodes in the network
- **PacketSender/FNPPacketMangler**: Handles low-level network communication
- **RequestStarter/RequestScheduler**: Coordinates content requests across the network
- **NodeUpdateManager**: Handles automatic updates (modern JVMs only, legacy EoL JVM support removed)

### Content Storage (`network.crypta.store`)

Distributed content storage system:

- **FreenetStore**: Abstract interface for content storage
- **CHKStore/SSKStore**: Content-Hash Keys and Signed Subspace Keys storage
- **SlashdotStore**: Caching layer to prevent overload

### Cryptography (`network.crypta.crypt`)

Security and encryption primitives:

- **BlockCipher/AES implementation**: Core encryption
- **DSA/ECDSA**: Digital signatures
- **Hash functions**: SHA-256 and other hashing
- **RandomSource/Yarrow**: Cryptographically secure randomness

### Key Management (`network.crypta.keys`)

Content addressing and verification:

- **ClientCHK/ClientSSK**: Client-side key handling
- **FreenetURI**: Universal resource identifiers for content
- **USK (Updatable Subspace Keys)**: Versioned content keys

### Client APIs

- **High-level client (`network.crypta.client`)**: Simplified API for applications
- **FCP (`network.crypta.clients.fcp`)**: Freenet Client Protocol for external applications
- **HTTP interface (`network.crypta.clients.http`)**: Web-based node management

### Plugin System (`network.crypta.pluginmanager`)

Extensible architecture for adding functionality:

- **PluginManager**: Loads and manages plugins
- **FredPlugin interfaces**: Various plugin capability interfaces
- **OfficialPlugins**: Maintains list of officially supported plugins

### Configuration (`network.crypta.config`)

Flexible configuration system supporting various data types and persistence.

### Supporting Infrastructure (`network.crypta.support`)

Utilities including logging, data structures, threading, and various helper classes.

## Key Design Patterns

### Request Routing

Content requests are routed through the network using a sophisticated system:

1. **RequestStarter** initiates requests
2. **RequestScheduler** manages request queuing and priority
3. **SendableRequest** implementations handle different request types
4. Routing uses network location-based algorithms for efficient content discovery

### Update System

The node supports automatic updates through:

- **NodeUpdateManager**: Coordinates update checks and deployment
- **MainJarUpdater**: Handles main application updates
- **PluginJarUpdater**: Manages plugin updates
- Update-over-mandatory (UOM) system for network-wide updates

### Security Model

Multi-layered security approach:

- Content-addressed storage with cryptographic verification
- Onion-style routing for anonymity
- Digital signatures for content authentication
- Multiple encryption layers for data protection

## Build System

Uses Gradle with Kotlin DSL:

- **Java 21+ target**: Modern Java features utilized
- **Kotlin components**: Some newer components written in Kotlin
- **Dependency verification**: Enabled to ensure supply chain security
- **Version generation**: Automatic version file generation from Git
- **YYI versioning**: Custom "Year-Year-Index" versioning scheme converted to public format

## Testing Strategy

Comprehensive test suite covering:

- **Unit tests**: Core functionality and utilities
- **Integration tests**: Network components and protocols
- **Cryptographic tests**: Security primitives verification
- **Client API tests**: FCP and HTTP interface testing

## Development Guidelines

- Primary language: Kotlin/Java
    - New files should be always in Kotlin
- Code style:
    - Kotlin: Official coding convention described [here](https://kotlinlang.org/docs/coding-conventions.html)
    - Java: Google Java Style Guide described [here](https://google.github.io/styleguide/javaguide.html)
- Testing: JUnit and kotlin-test
- Coverage requirement: 80% minimum
- After editing a Java or Kotlin file, please check for any missing or poorly written JavaDoc/KDoc comments. Add or
  improve them as needed.
- Do not use "--no-daemon" for Gradle
- Automatically use context-manager, kotlin-expert, java-pro, architect-reviewer, debugger, error-detective,
  dx-optimizer, frontend-developer, javascript-pro, performance-engineer, search-specialist, security-auditor,
  ui-ux-designer, legacy-modernizer and other subagents based on current tasks.

## Important Notes

- The project requires Java 21+ for compilation and runtime
- Legacy End-of-Life JVM support has been removed from the update system
- Uses custom cryptographic implementations - exercise caution when modifying
- Network protocol changes require careful consideration for backward compatibility
- The project includes simulator components for testing network behavior under various conditions