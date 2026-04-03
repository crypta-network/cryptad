/**
 * Transport-neutral core for the first Platform API surface.
 *
 * <p>This leaf owns the read-only Platform API v1 that sits on top of {@code runtime-spi} and below
 * any future web-shell or application-host work. Code in this package family accepts simple request
 * metadata, routes it to detached runtime ports, and produces JSON payloads without taking
 * dependencies on legacy HTTP toadlets, FCP message types, or daemon-only runtime classes.
 *
 * <p>The API is intentionally narrow for the first platform-layer PR. It exposes small, immediately
 * useful read-only resources such as node info, peers, configuration exports, connectivity
 * snapshots, and security levels while preserving the extracted runtime boundary.
 */
package network.crypta.platform.api;
