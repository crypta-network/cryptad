package network.crypta.platform.devtools;

import network.crypta.platform.appdist.AppBundleManifest;

/**
 * Developer validation result for one staged app bundle.
 *
 * <p>The validation command needs both the production appdist result and developer-facing lint
 * findings. The manifest component is the parsed, normalized model returned after the staged bundle
 * passes structure checks. The permission lint component reports capability names that are
 * syntactically valid in a manifest but not known to the current Platform API registry. CLI code
 * can therefore print a successful validation summary while still surfacing warnings, or fail in
 * strict mode when the lint result is not clean.
 *
 * @param manifest parsed and normalized bundle manifest from the production parser
 * @param permissionLint permission-name lint result for the manifest capabilities
 */
public record BundleValidation(AppBundleManifest manifest, PermissionLintResult permissionLint) {}
