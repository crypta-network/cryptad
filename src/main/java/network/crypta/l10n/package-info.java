/**
 * Localization (l10n) utilities and translation resources for the Crypta node and its plugins.
 *
 * <p>This package provides the components that load, resolve, and format localized strings used by
 * the application and by plugins.
 *
 * <p>Core types:
 *
 * <ul>
 *   <li>{@link network.crypta.l10n.BaseL10n} — Core resolver. Loads language files, applies
 *       variable substitution, exposes string and HTML helpers, and supports on-disk overrides.
 *   <li>{@link network.crypta.l10n.NodeL10n} — Application-wide façade that exposes a single shared
 *       {@code BaseL10n}. Lazily initialized on the first access or re-initialized via its
 *       constructors.
 *   <li>{@link network.crypta.l10n.PluginL10n} — Per-plugin bridge that wires a {@code BaseL10n}
 *       using paths, masks, and class loader provided by the plugin.
 *   <li>{@link network.crypta.l10n.BaseL10n.LANGUAGE} — Supported language registry with ISO-style
 *       short codes and display names.
 * </ul>
 *
 * <h2>Resource format and lookup</h2>
 *
 * <ul>
 *   <li>Language files live under a base path (default {@code "network/crypta/l10n/"}) and follow a
 *       mask (default {@code "crypta.l10n.${lang}.properties"}), where {@code ${lang}} is the
 *       {@link network.crypta.l10n.BaseL10n.LANGUAGE#shortCode short code} of the selected
 *       language.
 *   <li>Files use the {@link network.crypta.support.SimpleFieldSet} text format (key/value pairs
 *       with dot‑separated keys). UTF‑8 is used when reading bundled resources.
 *   <li>Lookup order is: override file for the selected language → selected language resource →
 *       fallback language ({@link network.crypta.l10n.BaseL10n.LANGUAGE#getDefault()}) → the key
 *       itself (as a last resort). Missing entries are logged.
 *   <li>On-disk overrides use the same language mask; the default {@link
 *       network.crypta.l10n.NodeL10n} configuration resolves {@code
 *       crypta.l10n.${lang}.override.properties} in the working directory.
 * </ul>
 *
 * <h2>Substitution and HTML helpers</h2>
 *
 * <ul>
 *   <li>String substitution replaces {@code ${name}} tokens with caller-provided values (see {@link
 *       network.crypta.l10n.BaseL10n#getString(String, String[], String[])}). Replacement values
 *       are safely escaped for use with {@link java.lang.String#replaceAll(String, String)}.
 *   <li>HTML helpers ({@link network.crypta.l10n.BaseL10n#getHTMLNode(String)} and {@link
 *       network.crypta.l10n.BaseL10n#addL10nSubstitution(network.crypta.support.HTMLNode, String,
 *       String[], network.crypta.support.HTMLNode[])}) treat {@code ${name}...${/name}} as a range
 *       to wrap with a provided {@link network.crypta.support.HTMLNode} while preserving nested
 *       substitutions.
 * </ul>
 *
 * <h2>Threading and state</h2>
 *
 * <ul>
 *   <li>{@code BaseL10n} instances are stateful (selected language and overrides). Only fallback
 *       loading is synchronized; coordinate externally if sharing an instance across threads.
 *   <li>{@code NodeL10n} holds a lazily created, shared {@code BaseL10n}. Concurrent
 *       re-initialization is last‑writer‑wins.
 * </ul>
 *
 * <h2>Examples</h2>
 *
 * <pre>{@code
 * // Application code
 * BaseL10n l10n = NodeL10n.getBase();
 * String title = l10n.getString("wizard.title");
 *
 * // With HTML substitution: wizard.link=See ${link}help${/link}
 * HTMLNode container = new HTMLNode("div");
 * l10n.addL10nSubstitution(
 *     container,
 *     "wizard.link",
 *     new String[]{"link"},
 *     new HTMLNode[]{HTMLNode.link("/help")});
 * }</pre>
 *
 * @see network.crypta.l10n.BaseL10n
 * @see network.crypta.l10n.NodeL10n
 * @see network.crypta.l10n.PluginL10n
 * @see network.crypta.l10n.BaseL10n.LANGUAGE
 * @see network.crypta.support.HTMLNode
 */
package network.crypta.l10n;
