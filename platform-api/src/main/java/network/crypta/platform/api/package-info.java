/**
 * Transport-neutral core for the first Platform API surface.
 *
 * <p>This leaf owns Platform API v1, including the read-only node, peers, config, connectivity, and
 * security-level routes plus the minimal app-management control surface backed by AppHost v1. Code
 * in this package family accepts simple request metadata, routes it to detached runtime ports or
 * AppHost snapshots, and produces JSON payloads without taking dependencies on legacy HTTP
 * toadlets, FCP message types, or daemon-only runtime classes.
 *
 * <p>The API remains intentionally narrow. It exposes small, immediately useful control-plane
 * resources while preserving the extracted runtime boundary.
 */
package network.crypta.platform.api;
