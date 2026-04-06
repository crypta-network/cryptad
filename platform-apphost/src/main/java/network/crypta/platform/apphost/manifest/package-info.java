/**
 * Strict v1 manifest parsing and validation for {@code cryptad-app.properties}.
 *
 * <p>The parser accepts only the small properties-style format used by the AppHost core. It
 * normalizes the manifest into immutable values and rejects unsupported schema versions, malformed
 * identifiers, unsafe executable paths, and invalid quota metadata.
 */
package network.crypta.platform.apphost.manifest;
