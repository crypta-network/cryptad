/**
 * Implements the Freenet Client Protocol (FCP) used by Crypta to communicate with external
 * applications over long-lived TCP connections. This module owns the protocol-side FCP leaf: the
 * message classes, server entry points, and package-local protocol helpers that let clients and the
 * daemon speak the same wire language without exposing storage internals.
 *
 * <p>The API centers around {@link network.crypta.clients.fcp.FCPServer}, which accepts incoming
 * sockets and hands them to {@link network.crypta.clients.fcp.FCPConnectionHandler}. Each request
 * or response is represented by a concrete {@link network.crypta.clients.fcp.FCPMessage} subtype;
 * the hierarchy distinguishes download/insert commands, node stats, and connection control.
 * Persistent requests, bandwidth probes, and peer-management commands maintain explicit identifiers
 * so clients can survive reconnects without duplicating work. The concrete bridge layer that binds
 * this protocol tree to runtime-owned seams now lives in {@code :bridge-fcp-runtime}.
 *
 * <p>Messages are designed for streaming and back-pressure: {@link
 * network.crypta.clients.fcp.FCPConnectionInputHandler} parses frames incrementally, while {@link
 * network.crypta.clients.fcp.FCPConnectionOutputHandler} preserves ordering and throttles per
 * connection. Most operations are asynchronous; clients should watch completion and progress events
 * instead of blocking. Implementations are thread-safe at the connection boundary, but individual
 * message instances are typically single-use and should not be reused across threads.
 *
 * <ul>
 *   <li>Supports transient and persistent download/insert lifecycles with explicit status updates.
 *   <li>Exposes node visibility for peers, bandwidth, and datastore sizing.
 * </ul>
 *
 * @see network.crypta.clients.fcp.FCPServer
 * @see network.crypta.clients.fcp.FCPMessage
 */
package network.crypta.clients.fcp;
