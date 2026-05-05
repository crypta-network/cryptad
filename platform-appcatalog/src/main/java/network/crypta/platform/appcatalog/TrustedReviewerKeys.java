package network.crypta.platform.appcatalog;

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
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable registry of reviewer public keys trusted by the current node.
 *
 * <p>The registry is the lookup table used by {@link AppReviewReceiptVerifier} after a receipt has
 * passed catalog-entry binding and expiry checks. It maps reviewer key ids from receipt payloads to
 * {@link TrustedReviewerKey} values that can verify Ed25519 signatures over canonical receipt
 * payload bytes.
 *
 * <p>This is a review trust registry only. It does not trust catalog publishers, app bundle
 * signers, or artifact digests, and it does not make a receipt positive by itself. A trusted
 * reviewer can sign a {@code reviewed}, {@code caution}, or {@code rejected} receipt; the verifier
 * and local {@link AppReviewPolicy} convert that evidence into install and update decisions.
 *
 * <p>The registry is immutable and fail-closed. Duplicate key ids, unsupported algorithms,
 * incomplete property blocks, and non-contiguous file entries are rejected at load time so callers
 * cannot accidentally verify a receipt against an ambiguous or partially configured trust source.
 * Public key bytes remain inside this verification layer and are not included in API summaries.
 */
public final class TrustedReviewerKeys {
  private static final Pattern REVIEWER_PROPERTY_PATTERN =
      Pattern.compile(
          "reviewer\\.(\\d+)\\.(id|algorithm|public\\.key\\.base64|display\\.name|policy\\.id)");
  private static final TrustedReviewerKeys EMPTY = new TrustedReviewerKeys(Map.of());

  private final Map<String, TrustedReviewerKey> keysById;

  private TrustedReviewerKeys(Map<String, TrustedReviewerKey> keysById) {
    this.keysById = Map.copyOf(keysById);
  }

  /**
   * Creates a trusted reviewer registry from a collection.
   *
   * <p>The input order is preserved for deterministic diagnostics, but lookup semantics are by
   * reviewer key id. Two keys with the same id are rejected even if their public key bytes are
   * identical, because duplicate ids would make receipt verification and audit output ambiguous.
   *
   * @param keys reviewer keys to index by id
   * @return immutable reviewer-key registry
   */
  public static TrustedReviewerKeys of(Collection<TrustedReviewerKey> keys) {
    Objects.requireNonNull(keys, "keys");
    Map<String, TrustedReviewerKey> byId = new LinkedHashMap<>();
    for (TrustedReviewerKey key : keys) {
      TrustedReviewerKey trustedKey = Objects.requireNonNull(key, "key");
      TrustedReviewerKey previous = byId.putIfAbsent(trustedKey.keyId(), trustedKey);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry(
            "duplicate trusted reviewer key id: " + trustedKey.keyId());
      }
    }
    return new TrustedReviewerKeys(byId);
  }

  /**
   * Creates a registry from individual reviewer keys.
   *
   * <p>This convenience factory is used by tests and direct configuration paths that construct one
   * or a few keys in memory. It applies the same duplicate-id checks as {@link #of(Collection)}.
   *
   * @param keys reviewer keys to trust
   * @return immutable reviewer-key registry
   */
  public static TrustedReviewerKeys of(TrustedReviewerKey... keys) {
    return of(Arrays.asList(keys));
  }

  /**
   * Returns an empty reviewer-key registry.
   *
   * <p>An empty registry is a valid local configuration. It causes review receipt evaluation to
   * report {@link AppReviewTrustStatus#NOT_CONFIGURED} instead of treating publisher advisory
   * metadata as trusted review evidence.
   *
   * @return shared empty registry
   */
  public static TrustedReviewerKeys empty() {
    return EMPTY;
  }

  /**
   * Loads trusted reviewer keys from a local properties sidecar.
   *
   * <p>The file supports {@code trusted.reviewers.version=1} and contiguous {@code reviewer.N.*}
   * entries with {@code id}, {@code algorithm}, {@code public.key.base64}, and optional {@code
   * display.name} and {@code policy.id} fields. Indexes may start at either {@code 0} or {@code 1}
   * so operator examples can use human-friendly numbering while tests can mirror existing app-key
   * fixtures.
   *
   * <p>Only the Ed25519 review receipt algorithm is accepted. Unknown properties, unsupported
   * algorithms, duplicate ids, and incomplete key entries fail the whole load rather than producing
   * a partially trusted registry. The file contains public key material only; private reviewer keys
   * belong in offline signing workflows and are never read here.
   *
   * @param trustedReviewerKeysFile local reviewer-key properties file
   * @return parsed reviewer-key registry
   * @throws IOException if the file cannot be read
   */
  public static TrustedReviewerKeys load(Path trustedReviewerKeysFile) throws IOException {
    byte[] bytes =
        AppCatalogSidecars.readRequiredBytes(
            trustedReviewerKeysFile,
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "trusted reviewer keys file",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    Map<String, String> properties =
        AppCatalogSidecars.parseKeyValueSidecar(
            AppCatalogSidecars.utf8(bytes), "trusted reviewer keys file");
    validateVersion(properties.remove("trusted.reviewers.version"));
    SortedMap<Integer, TrustedReviewerKeyBuilder> builders = readBuilders(properties);
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported trusted reviewer keys property: " + properties.keySet().iterator().next());
    }
    return buildKeys(builders);
  }

  /**
   * Looks up a reviewer key by id.
   *
   * <p>A missing result is a trust decision input, not an exceptional parser failure. The verifier
   * reports it as an unknown reviewer so API, Web Shell, CLI, and release-certification surfaces
   * can explain that the receipt may be well-formed but is not trusted by this node.
   *
   * @param keyId reviewer key id from a receipt payload
   * @return matching trusted reviewer key, when configured
   */
  public Optional<TrustedReviewerKey> find(String keyId) {
    return Optional.ofNullable(keysById.get(keyId));
  }

  /**
   * Returns whether no reviewer keys are configured.
   *
   * <p>This distinguishes "no local review trust configured" from "a receipt named an unknown key."
   * Both are untrusted outcomes, but they are reported differently so operators know whether to add
   * a trust registry or investigate an unexpected reviewer id.
   *
   * @return {@code true} when this registry is empty
   */
  public boolean isEmpty() {
    return keysById.isEmpty();
  }

  /**
   * Returns a new registry with one additional reviewer key.
   *
   * <p>The existing registry is not modified. This is used by configuration loading to combine a
   * properties-file registry with one direct key from system properties or environment variables
   * while preserving duplicate-id validation.
   *
   * @param key reviewer key to add
   * @return combined immutable registry
   */
  public TrustedReviewerKeys plus(TrustedReviewerKey key) {
    Map<String, TrustedReviewerKey> combined = new LinkedHashMap<>(keysById);
    TrustedReviewerKey trustedKey = Objects.requireNonNull(key, "key");
    TrustedReviewerKey previous = combined.putIfAbsent(trustedKey.keyId(), trustedKey);
    if (previous != null) {
      throw AppCatalogSidecars.invalidEntry(
          "duplicate trusted reviewer key id: " + trustedKey.keyId());
    }
    return new TrustedReviewerKeys(combined);
  }

  private static void validateVersion(String versionText) {
    if (versionText == null) {
      throw AppCatalogSidecars.invalidEntry("missing trusted.reviewers.version");
    }
    try {
      int version = Integer.parseInt(versionText);
      if (version != 1) {
        throw AppCatalogSidecars.invalidEntry("unsupported trusted.reviewers.version: " + version);
      }
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid trusted.reviewers.version: " + versionText,
          exception);
    }
  }

  private static SortedMap<Integer, TrustedReviewerKeyBuilder> readBuilders(
      Map<String, String> properties) {
    SortedMap<Integer, TrustedReviewerKeyBuilder> builders = new TreeMap<>();
    List<String> keys = properties.keySet().stream().toList();
    for (String propertyName : keys) {
      Matcher matcher = REVIEWER_PROPERTY_PATTERN.matcher(propertyName);
      if (!matcher.matches()) {
        continue;
      }
      int index = parseIndex(matcher.group(1), propertyName);
      TrustedReviewerKeyBuilder builder =
          builders.computeIfAbsent(index, _ -> new TrustedReviewerKeyBuilder());
      setField(builder, matcher.group(2), properties.remove(propertyName));
    }
    return builders;
  }

  private static TrustedReviewerKeys buildKeys(
      SortedMap<Integer, TrustedReviewerKeyBuilder> builders) {
    if (builders.isEmpty()) {
      return empty();
    }
    int start = builders.firstKey();
    if (start != 0 && start != 1) {
      throw AppCatalogSidecars.invalidEntry("trusted reviewer keys must start at index 0 or 1");
    }
    List<TrustedReviewerKey> keys = new ArrayList<>(builders.size());
    for (int offset = 0; offset < builders.size(); offset++) {
      int index = start + offset;
      TrustedReviewerKeyBuilder builder = builders.get(index);
      if (builder == null) {
        throw AppCatalogSidecars.invalidEntry("trusted reviewer keys must use contiguous indexes");
      }
      keys.add(buildKey(builder, index));
    }
    return of(keys);
  }

  private static TrustedReviewerKey buildKey(TrustedReviewerKeyBuilder builder, int index) {
    if (builder.id == null || builder.algorithm == null || builder.publicKeyBase64 == null) {
      throw AppCatalogSidecars.invalidEntry("trusted reviewer key " + index + " is incomplete");
    }
    if (!TrustedReviewerKey.SIGNATURE_ALGORITHM.equals(builder.algorithm)) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported trusted reviewer key algorithm: " + builder.algorithm);
    }
    return TrustedReviewerKey.ed25519(
        builder.id, builder.publicKeyBase64, builder.displayName, builder.policyId);
  }

  private static int parseIndex(String rawIndex, String propertyName) {
    try {
      return Integer.parseInt(rawIndex);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid trusted reviewer key entry index in " + propertyName,
          exception);
    }
  }

  private static void setField(TrustedReviewerKeyBuilder builder, String field, String value) {
    switch (field) {
      case "id" -> builder.id = value;
      case "algorithm" -> builder.algorithm = value;
      case "public.key.base64" -> builder.publicKeyBase64 = value;
      case "display.name" -> builder.displayName = value;
      case "policy.id" -> builder.policyId = value;
      default -> throw new IllegalArgumentException("unsupported trusted reviewer key field");
    }
  }

  private static final class TrustedReviewerKeyBuilder {
    private String id;
    private String algorithm;
    private String publicKeyBase64;
    private String displayName;
    private String policyId;
  }
}
