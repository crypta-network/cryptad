package network.crypta.config;

/**
 * Marks configuration callbacks whose value represents a directory path handled by the existing
 * directory-selection UI flow.
 *
 * <p>This interface keeps the classification contract in {@code network.crypta.config} so admin and
 * other configuration-facing code can recognize directory-backed options without importing a
 * concrete runtime-owned callback implementation. Callers normally encounter the marker through a
 * {@link ConfigCallback} instance and use it only for presentation or routing decisions, such as
 * deciding whether to offer the legacy directory browser.
 *
 * <p>The marker is intentionally narrow. It identifies participation in the directory-selection
 * flow, but it does not define path validation, normalization, or write access. Callers must still
 * use {@link ConfigCallback#isReadOnly()} to determine mutability and rely on the surrounding
 * callback family for get/set behavior.
 *
 * <ul>
 *   <li>Use this marker to detect directory-selection options in detached UI code.
 *   <li>Do not treat this marker as proof that the option is writable.
 *   <li>Do not infer filesystem semantics beyond participation in the directory chooser flow.
 * </ul>
 *
 * @see ConfigCallback
 */
public interface DirectorySelectionCallback {}
