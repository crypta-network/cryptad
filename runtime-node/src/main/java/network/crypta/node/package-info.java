/**
 * Core daemon-owned node runtime: peer coordination, request orchestration, transport handling, and
 * node-owned persistence helpers.
 *
 * <p>This package now spans a split-package boundary across multiple leaves. The {@code
 * runtime-node} portion contains the live daemon body centered on {@code Node} and {@code
 * NodeClientCore}. It owns peer management, packet and handshake processing, request scheduling,
 * insert and fetch execution, security-level handling, statistics export, and the node-local file
 * and key material helpers that still depend directly on a running daemon instance. The smaller
 * compile-neutral helper slice now lives in {@code :kernel-routing}, while this runtime-owned
 * portion keeps the cyclic request, peer, and transport engines. Lightweight scheduling and
 * shutdown contracts such as {@code FastRunnable}, {@code PrioRunnable}, and {@code
 * SemiOrderedShutdownHook} now live in {@code :foundation-support}.
 *
 * <p>These runtime-owned classes are not a stable public extension surface. They still mix
 * transport, routing, and content-adjacent responsibilities that later work will separate into more
 * focused kernel modules. Documenting the boundary here freezes the current structure without
 * changing runtime behavior.
 */
package network.crypta.node;
