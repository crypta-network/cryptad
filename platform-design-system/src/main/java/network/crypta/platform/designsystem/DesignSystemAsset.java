package network.crypta.platform.designsystem;

/**
 * Immutable metadata for one canonical Crypta app UI asset.
 *
 * <p>The bundle path is always relative to a staged app bundle root and uses forward slashes. It is
 * suitable for reports, CLI output, and deterministic linter comparisons; callers that need a file
 * system path should resolve it under a validated bundle directory instead of treating the value as
 * host-specific input.
 *
 * <p>Instances are value objects produced by {@link DesignSystemAssets}. The size and digest refer
 * to the canonical classpath resource bytes, not to any later copy staged inside an app bundle.
 * Devtools can therefore compare a bundle-local file against this metadata without reaching the
 * network or depending on a running node. The record is intentionally transport-neutral: it does
 * not expose a {@link java.nio.file.Path}, does not cache resource bytes, and carries no mutable
 * state. That keeps UI lint output deterministic across operating systems while still giving
 * staging code enough information to copy, serve, and verify the canonical assets.
 *
 * @param name stable asset filename, without bundle directory segments
 * @param resourcePath absolute classpath resource path for reading the canonical bytes
 * @param bundlePath normalized bundle-relative destination, such as {@code
 *     static/crypta-ui/crypta-ui.css}
 * @param mimeType deterministic MIME type used when the asset is served from app UI routes
 * @param sizeBytes canonical asset size in bytes, computed from the classpath resource
 * @param sha256Hex lowercase SHA-256 digest of the canonical resource bytes
 */
public record DesignSystemAsset(
    String name,
    String resourcePath,
    String bundlePath,
    String mimeType,
    long sizeBytes,
    String sha256Hex) {}
