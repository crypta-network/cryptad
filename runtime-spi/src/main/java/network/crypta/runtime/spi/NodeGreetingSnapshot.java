package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Represents the runtime metadata required to build an outbound node greeting.
 *
 * <p>This value captures the daemon and static metadata currently serialized by the FCP {@code
 * NodeHello} message while keeping daemon-only classes out of the runtime SPI. It is intentionally
 * limited to the existing node-greeting fields and excludes protocol-specific values such as the
 * FCP version or the connection identifier.
 *
 * <p>Instances are detached snapshots. They are meant to be collected once by the runtime adapter
 * and then handed to management-facing protocol code that can serialize the greeting without
 * reaching back into daemon internals. That keeps per-connection response objects simple while
 * preserving the current wire fields and allowing future runtime implementations to source the data
 * differently.
 *
 * @param nodeName human-readable node product name advertised to management clients
 * @param versionString serialized node version descriptor
 * @param buildNumber build number embedded in the running node
 * @param revision Git revision string embedded at build time
 * @param testnetEnabled whether the node currently runs with testnet enabled
 * @param compressionCodecs serialized compressor descriptor for the greeting payload
 * @param nodeLanguage selected node language hint for clients
 */
public record NodeGreetingSnapshot(
    String nodeName,
    String versionString,
    int buildNumber,
    String revision,
    boolean testnetEnabled,
    String compressionCodecs,
    String nodeLanguage) {
  /**
   * Creates an immutable node-greeting snapshot.
   *
   * <p>All string components must already be normalized into their outbound form before
   * construction. The record stores them exactly as supplied and performs only null checks, so
   * adapters remain responsible for deciding which daemon values belong in the greeting.
   *
   * @throws NullPointerException if any string component is {@code null}
   */
  public NodeGreetingSnapshot {
    Objects.requireNonNull(nodeName, "nodeName");
    Objects.requireNonNull(versionString, "versionString");
    Objects.requireNonNull(revision, "revision");
    Objects.requireNonNull(compressionCodecs, "compressionCodecs");
    Objects.requireNonNull(nodeLanguage, "nodeLanguage");
  }
}
