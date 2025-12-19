package network.crypta.pluginmanager;

/**
 * Marks a plugin as eligible to be loaded more than once.
 *
 * <p>This is a marker interface (it has no methods) used by the node's plugin infrastructure to
 * distinguish plugins that may safely have multiple live instances. A plugin that implements this
 * interface communicates that it is designed to tolerate being instantiated and registered more
 * than once (for example, from different plugin files or with different configuration), without
 * assuming global uniqueness of its main class.
 *
 * <p>Because the interface provides no additional hooks, the correctness burden remains with the
 * plugin implementation: instances should avoid relying on process-wide singletons for mutable
 * state, and they should ensure any shared resources (files, ports, caches) are coordinated or
 * namespaced. Whether and how multiple instances are actually supported depends on the plugin
 * manager's policies.
 *
 * <ul>
 *   <li><b>Intent signal:</b> Indicates that multiple instances are acceptable by design.
 *   <li><b>Isolation:</b> Encourage instance-scoped state rather than global mutable state.
 *   <li><b>Lifecycle:</b> Expect multiple independent start/stop cycles over time.
 * </ul>
 *
 * @author David &lsquo;Bombe&rsquo; Roden &lt;bombe@freenetproject.org&gt;
 * @see PluginManager
 * @see PluginInfoWrapper#isMultiplePlugin()
 */
public interface FredPluginMultiple {}
