/**
 * Internal node startup subsystems that break daemon initialization into explicit runtime-owned
 * slices.
 *
 * <p>This package groups the subsystem coordinators used while constructing and starting the node:
 * storage, networking, routing, messaging, and the shared crypto or transport parameters that tie
 * those pieces together. The classes exist to keep the large {@code Node} bootstrap sequence
 * readable and testable while preserving the current daemon lifecycle and ordering semantics.
 *
 * <p>These subsystem types are runtime orchestration helpers, not a general plugin or extension
 * surface. They stay inside {@code runtime-node} for now because they still compose daemon-local
 * services directly and provide the current seam for a later kernel extraction.
 */
package network.crypta.node.subsystem;
