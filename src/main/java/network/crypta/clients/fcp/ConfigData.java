package network.crypta.clients.fcp;

import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.node.Node;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.support.SimpleFieldSet;

/**
 * Server-to-client FCP message that transports slices of the node configuration.
 *
 * <p>This type holds an immutable {@link ConfigSnapshot} produced by the runtime SPI and rebuilds
 * the corresponding {@link SimpleFieldSet} only when the FCP layer serializes the response. The
 * resulting payload mirrors the historical configuration export tree without keeping live daemon
 * objects in the message itself.
 *
 * <p>Each instance is immutable once constructed. Callers decide at construction time which
 * snapshot should be returned and whether an identifier should be attached so that asynchronous
 * responses can be correlated. Empty sections are omitted from the serialized payload, matching the
 * compact wire behavior of earlier implementations.
 *
 * <ul>
 *   <li>Intended consumers are FCP clients that need a snapshot of the configuration state.
 *   <li>Messages are constructed on the server and never accepted from clients.
 *   <li>The produced field set omits empty subsections so payloads stay compact.
 * </ul>
 *
 * <p>Thread-safety: instances are pure immutable values and are safe to share across threads after
 * construction.
 */
public class ConfigData extends FCPMessage {
  static final String NAME = "ConfigData";

  final ConfigSnapshot snapshot;
  final String requestIdentifier;

  /**
   * Creates a configuration snapshot response with a precisely scoped payload.
   *
   * <p>The supplied snapshot is already detached from daemon-only configuration types, so this
   * message becomes a transport value that can be queued and serialized without additional runtime
   * lookups. The identifier is optional but recommended for clients that expect multiple
   * outstanding responses.
   *
   * @param snapshot runtime-exported configuration snapshot to serialize
   * @param identifier identifier echoed into the payload via {@link FCPMessage#IDENTIFIER}; may be
   *     {@code null} when the caller does not need correlation.
   */
  public ConfigData(ConfigSnapshot snapshot, String identifier) {
    this.snapshot = Objects.requireNonNull(snapshot);
    this.requestIdentifier = identifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} payload that will be serialized into the outgoing FCP
   * message.
   *
   * <p>The exporter rebuilds each section under its historical FCP key (for example {@code
   * current}, {@code default}, or {@code shortDescription}). Nested values and subsets are copied
   * recursively into a fresh {@link SimpleFieldSet}. Empty subsections are suppressed to avoid
   * emitting redundant braces. When no sections are enabled, the returned field set is empty unless
   * an identifier is present.
   *
   * <pre>{@code
   * ConfigData data =
   *     new ConfigData(
   *         new ConfigSnapshot(
   *             Map.of(
   *                 ConfigSection.CURRENT,
   *                 new ConfigFieldSet(Map.of("enabled", "true"), Map.of()))),
   *         "cfg-1");
   * SimpleFieldSet payload = data.getFieldSet();
   * }</pre>
   *
   * @return a short-lived field set containing the snapshot subsections and optional identifier
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    for (Map.Entry<ConfigSection, ConfigFieldSet> entry : snapshot.sections().entrySet()) {
      fs.tput(sectionKey(entry.getKey()), toSimpleFieldSet(entry.getValue()));
    }
    if (requestIdentifier != null) {
      fs.putSingle("Identifier", requestIdentifier);
    }
    return fs;
  }

  /**
   * Returns a snapshot of the enabled configuration sections.
   *
   * @return a new {@link Set} containing the exported {@link ConfigSection} values.
   */
  public Set<ConfigSection> getSections() {
    return snapshot.sections().isEmpty()
        ? EnumSet.noneOf(ConfigSection.class)
        : EnumSet.copyOf(snapshot.sections().keySet());
  }

  private static String sectionKey(ConfigSection section) {
    return switch (section) {
      case CURRENT -> "current";
      case DEFAULTS -> "default";
      case SORT_ORDER -> "sortOrder";
      case EXPERT_FLAG -> "expertFlag";
      case FORCE_WRITE_FLAG -> "forceWriteFlag";
      case SHORT_DESCRIPTION -> "shortDescription";
      case LONG_DESCRIPTION -> "longDescription";
      case DATA_TYPES -> "dataType";
    };
  }

  private static SimpleFieldSet toSimpleFieldSet(ConfigFieldSet source) {
    SimpleFieldSet target = new SimpleFieldSet(true);
    for (Map.Entry<String, String> entry : source.directValues().entrySet()) {
      target.putSingle(entry.getKey(), entry.getValue());
    }
    for (Map.Entry<String, ConfigFieldSet> entry : source.directSubsets().entrySet()) {
      target.tput(entry.getKey(), toSimpleFieldSet(entry.getValue()));
    }
    return target;
  }

  /**
   * Returns the protocol-level name for this message.
   *
   * @return the literal {@link #NAME} constant used in the serialized header.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects inbound attempts to invoke this message from clients.
   *
   * <p>{@code ConfigData} is defined as a server-to-client response. If a client emits one, the
   * node reports {@link ProtocolErrorMessage#INVALID_MESSAGE} so the caller can correct its
   * protocol flow. The exception is non-global and does not close the connection automatically.
   *
   * @param handler connection that attempted to process the message; ignored because validation
   *     always fails earlier.
   * @param node node that received the invalid message; provided for interface completeness but not
   *     consulted.
   * @throws MessageInvalidException always thrown to signal the unsupported direction.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "ConfigData goes from server to client not the other way around",
        null,
        false);
  }
}
