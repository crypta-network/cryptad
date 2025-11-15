package network.crypta.clients.fcp;

import network.crypta.config.Config;
import network.crypta.config.PersistentConfig;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Server-to-client FCP message that transports slices of the node configuration.
 *
 * <p>This type assembles a {@link SimpleFieldSet} containing whichever option categories a caller
 * requests (current values, defaults, metadata flags, descriptions, and data types). The resulting
 * tree mirrors the structure returned by {@link PersistentConfig#exportFieldSet(Config.RequestType,
 * boolean)} for each category, letting remote tooling reconstruct the node's configuration dialog
 * without needing multiple round trips.
 *
 * <p>Each instance is immutable once constructed. Callers decide at construction time which
 * sections should be included and whether an identifier should be attached so that asynchronous
 * responses can be correlated. The exporter queries the {@link Node} configuration only if at least
 * one section is requested, preventing unnecessary work when the message would otherwise be empty.
 *
 * <ul>
 *   <li>Intended consumers are FCP clients that need a snapshot of configuration state.
 *   <li>Messages are constructed on the server and never accepted from clients.
 *   <li>The produced field set omits empty subsections so payloads stay compact.
 * </ul>
 *
 * <p>Thread-safety: instances rely on the underlying {@link PersistentConfig}; only construct them
 * in threads that can safely read configuration state, and avoid sharing mutable {@link Node}
 * references across threads without external coordination.
 */
public class ConfigData extends FCPMessage {
  static final String NAME = "ConfigData";

  final Node node;
  final boolean withCurrent;
  final boolean withDefaults;
  final boolean withSortOrder;
  final boolean withExpertFlag;
  final boolean withForceWriteFlag;
  final boolean withShortDescription;
  final boolean withLongDescription;
  final boolean withDataTypes;
  final String requestIdentifier;

  /**
   * Creates a configuration snapshot request with a precisely scoped payload budget.
   *
   * <p>The supplied boolean switches determine which sections are exported, allowing callers to
   * tailor the trade-off between completeness and serialization cost. All flags default to {@code
   * false}, so a caller must explicitly opt in to each exported view. The identifier is optional
   * but recommended for clients that expect multiple outstanding responses.
   *
   * @param node node instance providing the backing {@link PersistentConfig}; must be non-null and
   *     ready for read-only queries.
   * @param withCurrent exports {@link Config.RequestType#CURRENT_SETTINGS} when {@code true}; set
   *     to {@code false} to omit effective values entirely.
   * @param withDefaults exports {@link Config.RequestType#DEFAULT_SETTINGS} when {@code true}; best
   *     used when clients offer reset-to-default UX controls.
   * @param withSortOrder includes {@link Config.RequestType#SORT_ORDER} entries to help UIs order
   *     options consistently; unused interfaces can set this to {@code false}.
   * @param withExpertFlag includes {@link Config.RequestType#EXPERT_FLAG} metadata to annotate
   *     advanced options in downstream tooling when {@code true}.
   * @param withForceWriteFlag exports {@link Config.RequestType#FORCE_WRITE_FLAG} information so
   *     clients know which settings require explicit confirmation.
   * @param withShortDescription exports {@link Config.RequestType#SHORT_DESCRIPTION} strings for
   *     concise UI labels; disable to reduce payload size in automated workflows.
   * @param withLongDescription exports {@link Config.RequestType#LONG_DESCRIPTION} prose for
   *     help-text rich interfaces that surface detailed guidance.
   * @param withDataTypes includes {@link Config.RequestType#DATA_TYPE} tokens describing how values
   *     should be parsed or rendered on the client.
   * @param identifier identifier echoed into the payload via {@link FCPMessage#IDENTIFIER}; may be
   *     {@code null} when the caller does not need correlation.
   */
  public ConfigData(
      Node node,
      boolean withCurrent,
      boolean withDefaults,
      boolean withSortOrder,
      boolean withExpertFlag,
      boolean withForceWriteFlag,
      boolean withShortDescription,
      boolean withLongDescription,
      boolean withDataTypes,
      String identifier) {
    this.node = node;
    this.withCurrent = withCurrent;
    this.withDefaults = withDefaults;
    this.withSortOrder = withSortOrder;
    this.withExpertFlag = withExpertFlag;
    this.withForceWriteFlag = withForceWriteFlag;
    this.withShortDescription = withShortDescription;
    this.withLongDescription = withLongDescription;
    this.withDataTypes = withDataTypes;
    this.requestIdentifier = identifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} payload that will be serialized into the outgoing FCP
   * message.
   *
   * <p>The exporter requests each enabled subsection from {@link PersistentConfig} exactly once and
   * attaches it under a stable key (for example {@code current}, {@code default}, or {@code
   * shortDescription}). Empty subsections are suppressed to avoid emitting redundant braces. When
   * no sections are enabled the returned field set is empty unless an identifier is present.
   *
   * <pre>{@code
   * ConfigData data = new ConfigData(node, true, false, false, false,
   *     false, true, false, false, "cfg-1");
   * SimpleFieldSet payload = data.getFieldSet();
   * }</pre>
   *
   * @return a short-lived field set containing the requested subsections and optional identifier;
   *     callers must not mutate subsets that are also owned by {@link PersistentConfig}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    PersistentConfig config = needsConfigLookup() ? node.getConfig() : null;
    addSection(fs, config, withCurrent, Config.RequestType.CURRENT_SETTINGS, true, "current");
    addSection(fs, config, withDefaults, Config.RequestType.DEFAULT_SETTINGS, false, "default");
    addSection(fs, config, withSortOrder, Config.RequestType.SORT_ORDER, false, "sortOrder");
    addSection(fs, config, withExpertFlag, Config.RequestType.EXPERT_FLAG, false, "expertFlag");
    addSection(
        fs,
        config,
        withForceWriteFlag,
        Config.RequestType.FORCE_WRITE_FLAG,
        false,
        "forceWriteFlag");
    addSection(
        fs,
        config,
        withShortDescription,
        Config.RequestType.SHORT_DESCRIPTION,
        false,
        "shortDescription");
    addSection(
        fs,
        config,
        withLongDescription,
        Config.RequestType.LONG_DESCRIPTION,
        false,
        "longDescription");
    addSection(fs, config, withDataTypes, Config.RequestType.DATA_TYPE, false, "dataType");
    if (requestIdentifier != null) fs.putSingle("Identifier", requestIdentifier);
    return fs;
  }

  /** Returns {@code true} if any section flag is enabled and a configuration lookup is required. */
  private boolean needsConfigLookup() {
    return withCurrent
        || withDefaults
        || withSortOrder
        || withExpertFlag
        || withForceWriteFlag
        || withShortDescription
        || withLongDescription
        || withDataTypes;
  }

  /** Adds a subsection when the flag is enabled and the exported data is non-empty. */
  private static void addSection(
      SimpleFieldSet target,
      PersistentConfig config,
      boolean includeSection,
      Config.RequestType type,
      boolean defaults,
      String subsetKey) {
    if (!includeSection || config == null) {
      return;
    }
    SimpleFieldSet section = config.exportFieldSet(type, defaults);
    if (!section.isEmpty()) {
      target.put(subsetKey, section);
    }
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
