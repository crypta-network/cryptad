package network.crypta.platform.api.peers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiFieldSetJson;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.RemovedPeerSnapshot;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;

/**
 * Peer endpoint family for Platform API v1.
 *
 * <p>The handler preserves the existing raw peer export routes while also exposing a smaller,
 * shell-friendly peer control plane. Reads continue to come from detached runtime snapshots. Peer
 * mutations remain narrowly scoped to add, remove, darknet settings, and private note updates.
 *
 * <p>The handler keeps all request parsing transport-neutral. Callers provide one decoded parameter
 * map plus any path-derived peer identity, and this type performs validation, converts pasted peer
 * references into detached {@link PeerFieldSet} trees, delegates to the existing runtime SPI, and
 * maps runtime failures onto stable Platform API error codes.
 */
public final class PeersApiHandler {
  private static final System.Logger LOG = System.getLogger(PeersApiHandler.class.getName());

  private static final String FIELD_IDENTITY = "identity";
  private static final String FIELD_OPERATION = "operation";
  private static final String FIELD_STATUS = "status";
  private static final String FLAG_OPENNET = "opennet";
  private static final String FLAG_DISABLE_ROUTING_HAS_BEEN_SET_LOCALLY =
      "disableRoutingHasBeenSetLocally";
  private static final String PARAMETER_ALLOW_LOCAL_ADDRESSES = "allowLocalAddresses";
  private static final String PARAMETER_BURST_ONLY = "burstOnly";
  private static final String PARAMETER_DISABLED = "disabled";
  private static final String PARAMETER_FORCE_REMOVAL = "forceRemoval";
  private static final String PARAMETER_IGNORE_SOURCE_PORT = "ignoreSourcePort";
  private static final String PARAMETER_LISTEN_ONLY = "listenOnly";
  private static final String PARAMETER_NOTE_TEXT = "noteText";
  private static final String PARAMETER_PRIVATE_NOTE_TEXT = "privateNoteText";
  private static final String PARAMETER_REFERENCE_TEXT = "referenceText";
  private static final String PARAMETER_ROUTING_ENABLED = "routingEnabled";
  private static final String PARAMETER_TRUST = "trust";
  private static final String PARAMETER_VISIBILITY = "visibility";
  private static final String STATUS_ROUTING_DISABLED = "ROUTING DISABLED";

  /** Detached runtime port that supplies peer reads and mutations. */
  private final PeerPort peerPort;

  /** Detached darknet companion port used for display names and private notes in roster views. */
  private final DarknetConnectionsPort darknetConnectionsPort;

  /**
   * Creates a peer API handler backed by the supplied runtime ports.
   *
   * @param peerPort detached runtime peer port
   * @param darknetConnectionsPort detached darknet peer companion port
   */
  public PeersApiHandler(PeerPort peerPort, DarknetConnectionsPort darknetConnectionsPort) {
    this.peerPort = Objects.requireNonNull(peerPort, "peerPort");
    this.darknetConnectionsPort =
        Objects.requireNonNull(darknetConnectionsPort, "darknetConnectionsPort");
  }

  /**
   * Lists peers as JSON-compatible nested objects.
   *
   * <p>When the query parameters are omitted, both optional export flags default to {@code false}
   * to keep the raw field-set export surface conservative.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return peer list in encounter order
   */
  public List<Map<String, Object>> list(Map<String, List<String>> queryParameters) {
    boolean includeMetadata =
        PlatformApiParameters.readBoolean(queryParameters, "includeMetadata", false);
    boolean includeVolatile =
        PlatformApiParameters.readBoolean(queryParameters, "includeVolatile", false);
    return peerPort.list(includeMetadata, includeVolatile).stream()
        .map(snapshot -> PlatformApiFieldSetJson.toJson(snapshot.root()))
        .toList();
  }

  /**
   * Resolves one peer and returns it as a JSON-compatible nested object.
   *
   * <p>When the query parameters are omitted, both optional export flags default to {@code false}
   * to keep the raw field-set export surface conservative.
   *
   * @param nodeIdentifier detached peer identifier extracted from the request path
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible peer object
   */
  public Map<String, Object> get(String nodeIdentifier, Map<String, List<String>> queryParameters) {
    boolean includeMetadata =
        PlatformApiParameters.readBoolean(queryParameters, "includeMetadata", false);
    boolean includeVolatile =
        PlatformApiParameters.readBoolean(queryParameters, "includeVolatile", false);
    try {
      return PlatformApiFieldSetJson.toJson(
          peerPort.get(nodeIdentifier, includeMetadata, includeVolatile).root());
    } catch (UnknownPeerException _) {
      throw unknownPeer();
    }
  }

  /**
   * Returns a structured peer roster tailored for the Web Shell.
   *
   * <p>The roster is intentionally narrower than the raw field-set export. It surfaces only the
   * fields the shell needs for overview and the currently supported control-plane actions, while
   * still reusing detached runtime exports as the source of truth.
   *
   * @return JSON-compatible roster object containing the structured peer list
   */
  public Map<String, Object> roster() {
    Map<String, DarknetConnectionPeerSnapshot> darknetPeersByIdentity = indexDarknetPeers();
    List<Map<String, Object>> peers =
        peerPort.list(true, true).stream()
            .map(
                snapshot ->
                    toRosterEntry(snapshot, darknetPeersByIdentity.get(identity(snapshot.root()))))
            .toList();

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put("peerCount", peers.size());
    response.put("peers", peers);
    return response;
  }

  /**
   * Adds one peer from pasted peer-reference text.
   *
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible mutation result
   */
  public Map<String, Object> add(Map<String, List<String>> queryParameters) {
    PeerTrust requestedTrust =
        PlatformApiParameters.readOptionalEnum(queryParameters, PARAMETER_TRUST, PeerTrust.class);
    PeerVisibility requestedVisibility =
        PlatformApiParameters.readOptionalEnum(
            queryParameters, PARAMETER_VISIBILITY, PeerVisibility.class);
    String referenceText =
        PlatformApiParameters.requireString(queryParameters, PARAMETER_REFERENCE_TEXT);
    String privateNoteText =
        PlatformApiParameters.readOptionalString(queryParameters, PARAMETER_PRIVATE_NOTE_TEXT);
    PeerFieldSet reference = parsePeerReference(referenceText);
    validateAddOptions(reference, requestedTrust, requestedVisibility, privateNoteText);
    PeerTrust trust = defaultEnum(requestedTrust, PeerTrust.NORMAL);
    PeerVisibility visibility = defaultEnum(requestedVisibility, PeerVisibility.YES);

    PeerSnapshot addedPeer;
    try {
      addedPeer = peerPort.add(reference, trust, visibility);
    } catch (PeerAddRejectedException e) {
      throw mapPeerAddRejected(e);
    }

    String addedPeerIdentity = directValue(addedPeer.root(), FIELD_IDENTITY);
    boolean addedPeerIsOpennet = directFlag(addedPeer.root().directValues(), FLAG_OPENNET);
    boolean privateNoteStored =
        !addedPeerIsOpennet
            && maybeWritePrivateDarknetCommentByIdentity(addedPeerIdentity, privateNoteText);

    DarknetConnectionPeerSnapshot darknetPeer = lookupDarknetPeer(addedPeerIdentity);
    if (darknetPeer != null && privateNoteStored) {
      darknetPeer =
          new DarknetConnectionPeerSnapshot(
              darknetPeer.selectionToken(),
              darknetPeer.nodeIdentifier(),
              darknetPeer.displayName(),
              privateNoteText,
              darknetPeer.removableWithoutForce());
    }

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put(FIELD_OPERATION, "add");
    response.put("peer", toRosterEntry(addedPeer, darknetPeer));
    return response;
  }

  /**
   * Applies one exact-identity darknet settings update.
   *
   * @param peerIdentity exact peer identity extracted from the request path
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible mutation result
   */
  public Map<String, Object> updateSettings(
      String peerIdentity, Map<String, List<String>> queryParameters) {
    DarknetPeerSettingsUpdate update =
        new DarknetPeerSettingsUpdate(
            PlatformApiParameters.readOptionalBoolean(queryParameters, PARAMETER_DISABLED),
            PlatformApiParameters.readOptionalBoolean(queryParameters, PARAMETER_LISTEN_ONLY),
            PlatformApiParameters.readOptionalBoolean(queryParameters, PARAMETER_BURST_ONLY),
            PlatformApiParameters.readOptionalBoolean(
                queryParameters, PARAMETER_IGNORE_SOURCE_PORT),
            PlatformApiParameters.readOptionalBoolean(
                queryParameters, PARAMETER_ALLOW_LOCAL_ADDRESSES),
            PlatformApiParameters.readOptionalBoolean(queryParameters, PARAMETER_ROUTING_ENABLED),
            PlatformApiParameters.readOptionalEnum(
                queryParameters, PARAMETER_TRUST, PeerTrust.class),
            PlatformApiParameters.readOptionalEnum(
                queryParameters, PARAMETER_VISIBILITY, PeerVisibility.class));
    if (update.isEmpty()) {
      throw invalidQuery("At least one peer setting parameter is required.");
    }

    try {
      PeerSnapshot updatedPeer = peerPort.updateDarknetPeerByIdentity(peerIdentity, update);
      LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
      response.put(FIELD_OPERATION, "update_settings");
      response.put("peer", toRosterEntry(updatedPeer, lookupDarknetPeer(peerIdentity)));
      return response;
    } catch (UnknownPeerException _) {
      throw unknownPeer();
    } catch (DarknetPeerRequiredException e) {
      throw darknetPeerRequired(e);
    }
  }

  /**
   * Writes the private darknet comment note for one exact-identity peer.
   *
   * @param peerIdentity exact peer identity extracted from the request path
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible mutation result
   */
  public Map<String, Object> updateNote(
      String peerIdentity, Map<String, List<String>> queryParameters) {
    String noteText =
        PlatformApiParameters.requirePresentString(queryParameters, PARAMETER_NOTE_TEXT);
    try {
      String storedNote = peerPort.writePrivateDarknetCommentByIdentity(peerIdentity, noteText);
      LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(3);
      response.put(FIELD_OPERATION, "update_note");
      response.put(FIELD_IDENTITY, peerIdentity);
      response.put(PARAMETER_NOTE_TEXT, storedNote);
      return response;
    } catch (UnknownPeerException _) {
      throw unknownPeer();
    } catch (DarknetPeerRequiredException e) {
      throw darknetPeerRequired(e);
    }
  }

  /**
   * Removes one peer using its exact detached identity.
   *
   * @param peerIdentity exact peer identity extracted from the request path
   * @return JSON-compatible mutation result
   */
  public Map<String, Object> remove(
      String peerIdentity, Map<String, List<String>> queryParameters) {
    boolean forceRemoval =
        Boolean.TRUE.equals(
            PlatformApiParameters.readOptionalBoolean(queryParameters, PARAMETER_FORCE_REMOVAL));
    DarknetConnectionPeerSnapshot darknetPeer = lookupDarknetPeer(peerIdentity);
    if (darknetPeer != null && !darknetPeer.removableWithoutForce() && !forceRemoval) {
      throw forceRemovalRequired();
    }
    try {
      RemovedPeerSnapshot removedPeer = peerPort.removeByIdentity(peerIdentity);
      LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(3);
      response.put(FIELD_OPERATION, "remove");
      response.put(FIELD_IDENTITY, removedPeer.identity());
      response.put("nodeIdentifier", removedPeer.nodeIdentifier());
      return response;
    } catch (UnknownPeerException _) {
      throw unknownPeer();
    }
  }

  private Map<String, DarknetConnectionPeerSnapshot> indexDarknetPeers() {
    List<DarknetConnectionPeerSnapshot> peers = darknetConnectionsPort.listPeers();
    if (peers == null || peers.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, DarknetConnectionPeerSnapshot> indexed = new LinkedHashMap<>();
    for (DarknetConnectionPeerSnapshot peer : peers) {
      indexed.put(peer.nodeIdentifier(), peer);
    }
    return indexed;
  }

  private DarknetConnectionPeerSnapshot lookupDarknetPeer(String peerIdentity) {
    if (peerIdentity == null || peerIdentity.isBlank()) {
      return null;
    }
    List<DarknetConnectionPeerSnapshot> peers = darknetConnectionsPort.listPeers();
    if (peers == null) {
      return null;
    }
    for (DarknetConnectionPeerSnapshot peer : peers) {
      if (peerIdentity.equals(peer.nodeIdentifier())) {
        return peer;
      }
    }
    return null;
  }

  private static Map<String, Object> toRosterEntry(
      PeerSnapshot snapshot, DarknetConnectionPeerSnapshot darknetPeer) {
    PeerFieldSet root = snapshot.root();
    PeerFieldSet metadata = root.directSubsets().get("metadata");
    PeerFieldSet volatileState = root.directSubsets().get("volatile");
    String identity = identity(root);
    boolean opennet = directFlag(root.directValues(), FLAG_OPENNET);

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put(FIELD_IDENTITY, identity);
    json.put("nodeIdentifier", darknetPeer == null ? identity : darknetPeer.nodeIdentifier());
    json.put("displayName", displayName(root, darknetPeer));
    json.put("family", opennet ? FLAG_OPENNET : "darknet");
    json.put(FIELD_STATUS, directValue(volatileState, FIELD_STATUS));
    json.put(PARAMETER_TRUST, directValue(metadata, "trustLevel"));
    json.put(PARAMETER_VISIBILITY, directValue(metadata, "ourVisibility"));
    json.put("theirVisibility", directValue(metadata, "theirVisibility"));
    json.put(PARAMETER_DISABLED, directFlag(metadata, "isDisabled"));
    json.put(PARAMETER_LISTEN_ONLY, directFlag(metadata, "isListenOnly"));
    json.put(PARAMETER_BURST_ONLY, directFlag(metadata, "isBurstOnly"));
    json.put(PARAMETER_ROUTING_ENABLED, routingEnabled(metadata, volatileState));
    json.put(PARAMETER_IGNORE_SOURCE_PORT, directFlag(metadata, PARAMETER_IGNORE_SOURCE_PORT));
    json.put(
        PARAMETER_ALLOW_LOCAL_ADDRESSES, directFlag(metadata, PARAMETER_ALLOW_LOCAL_ADDRESSES));
    json.put("hasPrivateNote", darknetPeer != null && !darknetPeer.privateNoteText().isBlank());
    if (darknetPeer != null) {
      json.put(PARAMETER_PRIVATE_NOTE_TEXT, darknetPeer.privateNoteText());
      json.put("removableWithoutForce", darknetPeer.removableWithoutForce());
    }
    return json;
  }

  private static String displayName(PeerFieldSet root, DarknetConnectionPeerSnapshot darknetPeer) {
    if (darknetPeer != null && !darknetPeer.displayName().isBlank()) {
      return darknetPeer.displayName();
    }
    String name = root.directValues().get("myName");
    if (name != null && !name.isBlank()) {
      return name;
    }
    return identity(root);
  }

  private static String identity(PeerFieldSet root) {
    String identity = root.directValues().get(FIELD_IDENTITY);
    return identity == null || identity.isBlank() ? "<unknown-peer>" : identity;
  }

  private boolean maybeWritePrivateDarknetCommentByIdentity(String peerIdentity, String noteText) {
    if (noteText == null || noteText.isBlank()) {
      return false;
    }
    if (peerIdentity == null || peerIdentity.isBlank()) {
      LOG.log(
          System.Logger.Level.WARNING,
          "Added darknet peer without identity in snapshot; skipping private note write");
      return false;
    }

    try {
      peerPort.writePrivateDarknetCommentByIdentity(peerIdentity, noteText);
      return true;
    } catch (UnknownPeerException | DarknetPeerRequiredException | RuntimeException e) {
      LOG.log(
          System.Logger.Level.WARNING,
          "Added darknet peer "
              + peerIdentity
              + " but failed to write private note; keeping peer addition",
          e);
      return false;
    }
  }

  private static String directValue(PeerFieldSet fieldSet, String key) {
    if (fieldSet == null) {
      return null;
    }
    return fieldSet.directValues().get(key);
  }

  private static boolean directFlag(PeerFieldSet fieldSet, String key) {
    return fieldSet != null && directFlag(fieldSet.directValues(), key);
  }

  private static boolean directFlag(Map<String, String> values, String key) {
    String value = values.get(key);
    return Boolean.parseBoolean(value);
  }

  private static boolean routingEnabled(PeerFieldSet metadata, PeerFieldSet volatileState) {
    return !directFlag(metadata, FLAG_DISABLE_ROUTING_HAS_BEEN_SET_LOCALLY)
        && !STATUS_ROUTING_DISABLED.equals(directValue(volatileState, FIELD_STATUS));
  }

  private static <E> E defaultEnum(E value, E defaultValue) {
    return value == null ? defaultValue : value;
  }

  private static void validateAddOptions(
      PeerFieldSet reference,
      PeerTrust requestedTrust,
      PeerVisibility requestedVisibility,
      String privateNoteText) {
    if (!directFlag(reference.directValues(), FLAG_OPENNET)) {
      return;
    }
    if (!usesDarknetOnlyAddOptions(requestedTrust, requestedVisibility, privateNoteText)) {
      return;
    }
    throw invalidQuery(
        "Opennet peer references do not support trust, visibility, or privateNoteText add"
            + " options.");
  }

  private static boolean usesDarknetOnlyAddOptions(
      PeerTrust requestedTrust, PeerVisibility requestedVisibility, String privateNoteText) {
    return (requestedTrust != null && requestedTrust != PeerTrust.NORMAL)
        || (requestedVisibility != null && requestedVisibility != PeerVisibility.YES)
        || (privateNoteText != null && !privateNoteText.isBlank());
  }

  private static PeerFieldSet parsePeerReference(String referenceText) {
    List<String> references = extractReferenceBlocks(cleanReferenceText(referenceText));
    if (references.isEmpty()) {
      throw invalidPeerReference("Peer reference text is empty.");
    }
    if (references.size() != 1) {
      throw invalidPeerReference("Exactly one peer reference is required.");
    }

    String candidate = references.getFirst().concat("\nEnd");
    try {
      SimpleFieldSet parsed = parseNoderefLiberally(candidate);
      if (!parsed.getEndMarker().endsWith("End")) {
        throw invalidPeerReference("Peer reference is missing a valid End marker.");
      }
      parsed.setEndMarker("End");
      return toPeerFieldSet(parsed);
    } catch (IOException e) {
      throw invalidPeerReference("Peer reference could not be parsed: " + e.getMessage());
    }
  }

  private static List<String> extractReferenceBlocks(String referenceText) {
    String normalized = referenceText.replace("\r\n", "\n").replace('\r', '\n').trim();
    if (normalized.isEmpty()) {
      return List.of();
    }

    String[] rawReferences = normalized.split("\nEnd\n");
    List<String> references = new ArrayList<>(rawReferences.length);
    for (String rawReference : rawReferences) {
      String normalizedReference = normalizeReferenceBlock(rawReference);
      if (!normalizedReference.isBlank()) {
        references.add(normalizedReference);
      }
    }
    return List.copyOf(references);
  }

  private static String normalizeReferenceBlock(String rawReference) {
    StringBuilder builder = new StringBuilder(rawReference.length());
    boolean first = true;
    for (String line : rawReference.split("\n")) {
      String trimmed = line.trim();
      if (!trimmed.isEmpty()) {
        if ("End".equals(trimmed)) {
          break;
        }
        if (trimmed.indexOf('=') >= 0 && !first) {
          builder.append('\n');
        }
        builder.append(trimmed);
        first = false;
      }
    }
    return builder.toString();
  }

  private static String cleanReferenceText(String referenceText) {
    StringBuilder builder = new StringBuilder(referenceText.length());
    for (String line : referenceText.replace('\r', '\n').split("\n")) {
      String trimmed = line.trim();
      if (trimmed.isEmpty()) {
        continue;
      }
      if (trimmed.indexOf('=') >= 0 || "End".equals(trimmed)) {
        builder.append(trimmed).append('\n');
      }
    }
    return builder.toString();
  }

  private static SimpleFieldSet parseNoderefLiberally(String nodeReference) throws IOException {
    SimpleFieldSet parsed = new SimpleFieldSet(nodeReference, false, true, true);
    if (parsed.directKeys().contains("lastGoodVersion")) {
      return parsed;
    }
    return new SimpleFieldSet(nodeReference.replace(" ", "\n"), false, true, true);
  }

  private static PeerFieldSet toPeerFieldSet(SimpleFieldSet source) {
    if (source.isEmpty()) {
      return PeerFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(source.directKeyValues());
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : source.directSubsets().entrySet()) {
      PeerFieldSet subset = toPeerFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new PeerFieldSet(directValues, directSubsets);
  }

  private static PlatformApiException mapPeerAddRejected(PeerAddRejectedException e) {
    return switch (e.reason()) {
      case REF_PARSE_ERROR, REF_SIGNATURE_INVALID ->
          new PlatformApiException(400, "invalid_peer_reference", e.getMessage());
      case CANNOT_PEER_WITH_SELF ->
          new PlatformApiException(409, "cannot_peer_with_self", e.getMessage());
      case DUPLICATE_PEER_REF -> new PlatformApiException(409, "duplicate_peer", e.getMessage());
      case OPENNET_DISABLED -> new PlatformApiException(409, "opennet_disabled", e.getMessage());
    };
  }

  private static PlatformApiException unknownPeer() {
    return new PlatformApiException(404, "unknown_peer", "Peer not found.");
  }

  private static PlatformApiException darknetPeerRequired(DarknetPeerRequiredException e) {
    return new PlatformApiException(409, "darknet_peer_required", e.getMessage());
  }

  @SuppressWarnings("SameParameterValue")
  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }

  private static PlatformApiException invalidPeerReference(String message) {
    return new PlatformApiException(400, "invalid_peer_reference", message);
  }

  private static PlatformApiException forceRemovalRequired() {
    return new PlatformApiException(
        409, "force_removal_required", "Peer removal requires forceRemoval=true.");
  }
}
