package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable trusted-key registry used during bundle verification.
 *
 * <p>The registry maps stable signature key ids to explicit public keys. It is passed into {@link
 * AppBundleVerifier} rather than read from global state, which keeps app-host policy construction
 * deterministic and testable. Instances are immutable snapshots; adding a direct key returns a new
 * registry and duplicate key ids are rejected instead of silently overriding trust material.
 *
 * <p>The local file format is intentionally small and line-oriented. It supports only version
 * {@code 1}, contiguous {@code key.N.*} entries, and Ed25519 public keys encoded as X.509 base64.
 * Remote catalog trust and key discovery are outside this module.
 */
public final class TrustedAppKeys {
  private static final Pattern KEY_PROPERTY_PATTERN =
      Pattern.compile("key\\.(\\d+)\\.(id|algorithm|public\\.key\\.base64)");
  private static final TrustedAppKeys EMPTY = new TrustedAppKeys(Map.of());

  private final Map<String, TrustedAppKey> keysById;

  private TrustedAppKeys(Map<String, TrustedAppKey> keysById) {
    this.keysById = Map.copyOf(keysById);
  }

  /**
   * Creates a trusted-key registry from a collection.
   *
   * <p>The collection is copied immediately, null entries are rejected, and duplicate key ids fail
   * fast. Iteration order is preserved only for deterministic construction; lookup behavior is by
   * key id.
   *
   * @param keys trusted public keys indexed by their stable key ids
   * @return immutable trusted-key registry
   * @throws IllegalArgumentException if two entries use the same key id
   */
  public static TrustedAppKeys of(Collection<TrustedAppKey> keys) {
    Objects.requireNonNull(keys, "keys");
    Map<String, TrustedAppKey> keysById = new LinkedHashMap<>();
    for (TrustedAppKey key : keys) {
      TrustedAppKey trustedKey = Objects.requireNonNull(key, "key");
      TrustedAppKey previous = keysById.putIfAbsent(trustedKey.keyId(), trustedKey);
      if (previous != null) {
        throw new IllegalArgumentException("duplicate trusted key id: " + trustedKey.keyId());
      }
    }
    return new TrustedAppKeys(keysById);
  }

  /**
   * Creates a trusted-key registry from individual entries.
   *
   * @param keys trusted public keys indexed by their stable key ids
   * @return immutable trusted-key registry
   * @throws IllegalArgumentException if two entries use the same key id
   */
  public static TrustedAppKeys of(TrustedAppKey... keys) {
    return of(Arrays.asList(keys));
  }

  /**
   * Returns an empty trusted-key registry.
   *
   * <p>An empty registry is useful for development policies that allow fully unsigned bundles but
   * still need to reject partially signed bundles or bundles signed by unknown keys.
   *
   * @return shared empty trusted-key registry
   */
  public static TrustedAppKeys empty() {
    return EMPTY;
  }

  /**
   * Loads trusted public keys from a local properties-style sidecar.
   *
   * <p>The supported format is:
   *
   * <pre>{@code
   * trusted.keys.version=1
   * key.0.id=test-ed25519
   * key.0.algorithm=Ed25519
   * key.0.public.key.base64=<base64-x509-public-key>
   * }</pre>
   *
   * <p>A leading UTF-8 byte-order mark is tolerated so operator-edited files saved by common text
   * editors remain usable. Unknown properties, non-contiguous indexes, incomplete entries,
   * unsupported algorithms, and duplicate ids are rejected.
   *
   * @param trustedKeysFile local trusted-key sidecar path
   * @return parsed trusted-key registry
   * @throws IOException if the sidecar is missing, malformed, or contains unsupported algorithms
   */
  public static TrustedAppKeys load(Path trustedKeysFile) throws IOException {
    String content =
        AppDistributionSidecars.readRequiredUtf8File(trustedKeysFile, "trusted keys file");
    Map<String, String> properties =
        AppDistributionSidecars.parseKeyValueSidecar(content, "trusted keys file");
    validateTrustedKeysVersion(properties.remove("trusted.keys.version"));
    Map<Integer, TrustedKeyBuilder> builders = readTrustedKeyBuilders(properties);
    return buildTrustedKeys(builders);
  }

  private static void validateTrustedKeysVersion(String versionText)
      throws AppDistributionException {
    if (versionText == null) {
      throw new AppDistributionException("missing trusted.keys.version");
    }
    int version;
    try {
      version = Integer.parseInt(versionText);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid trusted.keys.version: " + versionText, exception);
    }
    if (version != 1) {
      throw new AppDistributionException("unsupported trusted.keys.version: " + version);
    }
  }

  private static Map<Integer, TrustedKeyBuilder> readTrustedKeyBuilders(
      Map<String, String> properties) throws AppDistributionException {
    Map<Integer, TrustedKeyBuilder> builders = new TreeMap<>();
    for (Map.Entry<String, String> property : properties.entrySet()) {
      TrustedKeyProperty trustedKeyProperty = parseTrustedKeyProperty(property.getKey());
      TrustedKeyBuilder builder =
          builders.computeIfAbsent(trustedKeyProperty.index(), ignored -> new TrustedKeyBuilder());
      setTrustedKeyField(builder, trustedKeyProperty.field(), property.getValue());
    }
    return builders;
  }

  private static TrustedKeyProperty parseTrustedKeyProperty(String propertyName)
      throws AppDistributionException {
    Matcher matcher = KEY_PROPERTY_PATTERN.matcher(propertyName);
    if (!matcher.matches()) {
      throw new AppDistributionException("unsupported trusted keys property: " + propertyName);
    }
    return new TrustedKeyProperty(parseIndex(matcher.group(1), propertyName), matcher.group(2));
  }

  private static void setTrustedKeyField(TrustedKeyBuilder builder, String field, String value) {
    switch (field) {
      case "id" -> builder.id = value;
      case "algorithm" -> builder.algorithm = value;
      case "public.key.base64" -> builder.publicKeyBase64 = value;
      default -> throw new IllegalArgumentException("unsupported trusted key field: " + field);
    }
  }

  private static TrustedAppKeys buildTrustedKeys(Map<Integer, TrustedKeyBuilder> builders)
      throws IOException {
    if (builders.isEmpty()) {
      return empty();
    }

    List<TrustedAppKey> keys = new ArrayList<>(builders.size());
    for (int expectedIndex = 0; expectedIndex < builders.size(); expectedIndex++) {
      TrustedKeyBuilder builder = requireTrustedKeyBuilder(builders, expectedIndex);
      keys.add(buildTrustedKey(builder, expectedIndex));
    }
    return of(keys);
  }

  private static TrustedKeyBuilder requireTrustedKeyBuilder(
      Map<Integer, TrustedKeyBuilder> builders, int expectedIndex) throws AppDistributionException {
    TrustedKeyBuilder builder = builders.get(expectedIndex);
    if (builder == null) {
      throw new AppDistributionException("trusted keys must use contiguous indexes");
    }
    return builder;
  }

  private static TrustedAppKey buildTrustedKey(TrustedKeyBuilder builder, int expectedIndex)
      throws IOException {
    if (builder.id == null || builder.algorithm == null || builder.publicKeyBase64 == null) {
      throw new AppDistributionException("trusted key " + expectedIndex + " is incomplete");
    }
    if (!AppBundleSignature.SIGNATURE_ALGORITHM.equals(builder.algorithm)) {
      throw new AppDistributionException("unsupported trusted key algorithm: " + builder.algorithm);
    }
    return TrustedAppKey.ed25519(builder.id, builder.publicKeyBase64);
  }

  /**
   * Looks up a trusted key by id.
   *
   * @param keyId stable signature key identifier from a bundle signature sidecar
   * @return matching trusted key, when configured
   */
  public Optional<TrustedAppKey> find(String keyId) {
    return Optional.ofNullable(keysById.get(keyId));
  }

  /**
   * Returns a new trusted-key registry with one additional key.
   *
   * <p>This is used by runtime configuration when an operator supplies both a trusted-keys file and
   * one direct key. A duplicate key id is treated as configuration ambiguity and rejected.
   *
   * @param key trusted key to add
   * @return combined trusted-key registry
   * @throws IllegalArgumentException if the key id already exists in this registry
   */
  public TrustedAppKeys plus(TrustedAppKey key) {
    Map<String, TrustedAppKey> combined = new LinkedHashMap<>(keysById);
    TrustedAppKey trustedKey = Objects.requireNonNull(key, "key");
    TrustedAppKey previous = combined.putIfAbsent(trustedKey.keyId(), trustedKey);
    if (previous != null) {
      throw new IllegalArgumentException("duplicate trusted key id: " + trustedKey.keyId());
    }
    return new TrustedAppKeys(combined);
  }

  private static int parseIndex(String rawIndex, String propertyName)
      throws AppDistributionException {
    try {
      return Integer.parseInt(rawIndex);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException(
          "invalid trusted key entry index in " + propertyName, exception);
    }
  }

  private record TrustedKeyProperty(int index, String field) {}

  private static final class TrustedKeyBuilder {
    private String id;
    private String algorithm;
    private String publicKeyBase64;
  }
}
