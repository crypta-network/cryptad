/**
 * Strict v1 manifest parsing and validation for {@code cryptad-app.properties}.
 *
 * <p>This package owns the immutable manifest model and the parser that converts raw {@code
 * cryptad-app.properties} files into validated AppHost metadata. The implementation accepts only
 * the small properties-style surface used by the AppHost core rather than the broader Java
 * properties feature set.
 *
 * <p>The package is responsible for schema version checks, app identity normalization, executable
 * path confinement, permission parsing, and optional quota metadata. By rejecting malformed input
 * here, the rest of the AppHost runtime can work with a smaller and safer manifest surface.
 */
package network.crypta.platform.apphost.manifest;
