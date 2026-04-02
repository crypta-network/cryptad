/**
 * Core daemon node runtime: peer coordination, request orchestration, transport handling, and
 * node-owned persistence helpers.
 *
 * <p>This package contains the live daemon body centered on {@code Node} and {@code
 * NodeClientCore}. It owns peer management, packet and handshake processing, request scheduling,
 * insert and fetch execution, security-level handling, statistics export, and the node-local file
 * and key material helpers that still depend directly on a running daemon instance. The package is
 * therefore broader than the future kernel leaves, but it captures the current post-extraction
 * ownership explicitly.
 *
 * <p>For the kernel split preparation baseline, these classes remain in {@code runtime-node}. They
 * are not a stable public extension surface, and this package still mixes transport, routing, and
 * content-adjacent responsibilities that later work will separate into more focused kernel modules.
 * Documenting the boundary here freezes the current structure without moving production code or
 * changing runtime behavior.
 */
package network.crypta.node;
