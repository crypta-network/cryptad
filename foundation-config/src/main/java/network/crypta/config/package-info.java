/**
 * Configuration framework for Crypta node settings.
 *
 * <p>The framework organizes settings under a root {@link network.crypta.config.Config}, which owns
 * multiple {@link network.crypta.config.SubConfig} sections identified by a prefix (for example,
 * {@code node.}). Each section registers typed {@link network.crypta.config.Option} instances
 * backed by a {@link network.crypta.config.ConfigCallback}. Specialized callbacks live in this
 * package (e.g., {@link network.crypta.config.StringCallback}) and may be accompanied by helper
 * contracts such as {@link network.crypta.config.EnumerableOptionCallback} when a finite set of
 * values is supported.
 *
 * <p>Many options apply immediately at runtime. If a change is accepted but cannot take effect
 * until restart, implementations signal this with {@link
 * network.crypta.config.NodeNeedRestartException}. Invalid values are rejected with {@link
 * network.crypta.config.InvalidConfigValueException}. Where unit semantics are relevant, options
 * may indicate a logical {@link network.crypta.config.Dimension} (for example, {@code SIZE} or
 * {@code DURATION}).
 *
 * <p>Some callbacks also carry narrow UI markers such as {@link
 * network.crypta.config.DirectorySelectionCallback} so HTTP admin code can classify special input
 * flows without importing concrete runtime implementations.
 *
 * <p>Persistence is environment-specific. {@link network.crypta.config.PersistentConfig} consumes
 * an initial {@link network.crypta.support.SimpleFieldSet} and exports the current state back to a
 * field set for storage. {@link network.crypta.config.WrapperConfig} provides limited support for
 * editing {@code wrapper.conf} when running under the Tanuki Wrapper, subject to filesystem and
 * runtime constraints.
 */
package network.crypta.config;
