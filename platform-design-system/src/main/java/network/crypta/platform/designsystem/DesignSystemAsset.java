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
 * network or depending on a running node.
 *
 * <p>The record is intentionally transport-neutral. It does not expose a {@link
 * java.nio.file.Path}, cache resource bytes, or carry mutable state. Callers can persist it in
 * reports, compare it in tests, or use it while staging bundles without binding those operations to
 * the host operating system's path syntax. Treat the values as metadata about the platform-shipped
 * asset set; a staged app file with the same bundle path still needs an explicit byte comparison
 * before it is trusted as canonical.
 *
 * @param name stable asset filename without bundle directory segments, suitable for display and
 *     deterministic ordering
 * @param resourcePath absolute classpath resource path used to read the platform-shipped resource
 *     bytes
 * @param bundlePath normalized bundle-relative destination, such as {@code
 *     static/crypta-ui/crypta-ui.css}, using forward slashes
 * @param mimeType deterministic MIME type expected when the asset is served from app UI routes
 * @param sizeBytes canonical asset size in bytes, computed from the classpath resource contents
 * @param sha256Hex lowercase SHA-256 digest of the canonical resource bytes for integrity checks
 * @see DesignSystemAssets#list()
 * @see DesignSystemAssets#copyIntoBundle(java.nio.file.Path)
 */
public record DesignSystemAsset(
    String name,
    String resourcePath,
    String bundlePath,
    String mimeType,
    long sizeBytes,
    String sha256Hex) {}
