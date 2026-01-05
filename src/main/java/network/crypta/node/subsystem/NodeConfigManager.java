package network.crypta.node.subsystem;

import java.util.Locale;
import java.util.MissingResourceException;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.SubConfig;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.ProgramDirectory;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.StringCallback;

/**
 * Registers node configuration keys and supplies callback implementations for core options.
 *
 * <p>This class wires the {@link SubConfig} entries that the node exposes to users and plugins, and
 * it owns small callback classes that translate configuration changes into live node actions.
 * Typical call sites create one instance per {@link Node} and invoke the configuration setup during
 * startup, before subsystems begin serving requests. The callbacks intentionally keep the logic
 * close to the node so that validation, side effects, and alert updates are performed in a
 * consistent order.
 *
 * <p>Thread safety is constrained to the callback methods themselves. Several callbacks synchronize
 * on their instance to coordinate with the {@link Node} state they mutate. Callers should treat
 * these callbacks as mutable, stateful adapters rather than as reusable stateless helpers.
 *
 * <p><b>Responsibilities:</b>
 *
 * <ul>
 *   <li>Register user-facing configuration options and their defaults.
 *   <li>Bridge configuration updates to node storage and localization subsystems.
 *   <li>Emit side effects such as alerts or broadcasts when values change.
 * </ul>
 *
 * @see SubConfig
 * @see Node
 * @see NodeL10n
 */
public final class NodeConfigManager {
  private final Node node;

  /**
   * Creates a configuration manager bound to the provided node instance.
   *
   * <p>The manager does not register anything by itself; callers should still invoke the
   * configuration methods they need during startup. The supplied node is stored and used by all
   * nested callbacks, so it must remain valid for the lifetime of this manager. No defensive copy
   * is made, and the constructor performs no side effects beyond capturing the reference.
   *
   * @param node the node whose configuration entries and callbacks are managed and mutated
   */
  public NodeConfigManager(Node node) {
    this.node = node;
  }

  /**
   * Registers localization-related configuration entries and initializes the locale fallback chain.
   *
   * <p>The method registers the {@code l10n} option in the provided configuration and wires it to a
   * callback that applies language changes. It then attempts to create a {@link NodeL10n} instance
   * using the configured language, falling back to the option default and then to the hardcoded
   * base default when resources are missing. The returned sort order should be used by the caller
   * for subsequent registrations to preserve deterministic configuration ordering.
   *
   * @param nodeConfig the node configuration object that receives the localization option
   * @param cfgDir the program directory used to locate localization resources on disk
   * @param sortOrder the current ordering index to assign to the registered option
   * @return the next sort order value after this method's registration increments
   */
  public int configureLocalization(SubConfig nodeConfig, ProgramDirectory cfgDir, int sortOrder) {
    nodeConfig.register(
        "l10n",
        Locale.getDefault().getLanguage().toLowerCase(),
        sortOrder++,
        false,
        true,
        "Node.l10nLanguage",
        "Node.l10nLanguageLong",
        new L10nCallback());

    try {
      new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getString("l10n")), cfgDir.dir());
    } catch (MissingResourceException _) {
      try {
        new NodeL10n(
            BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getOption("l10n").getDefault()),
            cfgDir.dir());
      } catch (MissingResourceException _) {
        new NodeL10n(
            BaseL10n.LANGUAGE.mapToLanguage(BaseL10n.LANGUAGE.getDefault().shortCode),
            cfgDir.dir());
      }
    }
    return sortOrder;
  }

  /**
   * Handles validation and side effects for the node's display name configuration.
   *
   * <p>The callback exposes the node name as a string option and reacts to changes by updating
   * alerts and broadcasting the new name to peers. It also normalizes an empty name to a sentinel
   * value and enforces a maximum length. Callers should treat this callback as stateful and use the
   * {@link #get()} method to refresh alert state after external changes.
   */
  public final class NodeNameCallback extends StringCallback {
    /**
     * Creates a node name callback bound to the enclosing manager's node.
     *
     * <p>The constructor performs no work beyond linking the callback to the outer instance. It is
     * safe to create as part of configuration registration and does not mutate the node until
     * {@link #get()} or {@link #set(String)} is invoked.
     */
    public NodeNameCallback() {
      // Intentionally empty: callback has no independent state beyond the outer instance.
    }

    /**
     * Returns the current node display name while refreshing the alert state.
     *
     * <p>The method retrieves the name from the node, then checks for default or placeholder values
     * that indicate the user has not chosen a meaningful label. When such values are detected, it
     * registers the user-facing alert; otherwise it removes that alert. The returned string
     * reflects the node's current internal value and should be treated as a snapshot rather than a
     * live view.
     *
     * @return the current node name after alert state has been updated accordingly
     */
    @Override
    public String get() {
      String name;
      synchronized (this) {
        name = node.getMyName();
      }
      if (name.startsWith("Node id|")
          || name.equals("MyFirstCryptaNode")
          || name.startsWith("Crypta node with no name #")) {
        node.services().clientCore().getAlerts().register(node.services().nodeNameUserAlert());
      } else {
        node.services().clientCore().getAlerts().unregister(node.services().nodeNameUserAlert());
      }
      return name;
    }

    /**
     * Updates the node display name after validating length and normalizing empty input.
     *
     * <p>If the provided value matches the existing name, the method is a no-op. Names longer than
     * 128 characters are rejected with a configuration error. An empty string is normalized to a
     * sentinel value so the node always has a non-empty internal name. After updating the node, the
     * method broadcasts the new name and invokes {@link #get()} to refresh alert status.
     *
     * @param val the proposed node name, where empty strings are normalized and length is limited
     * @throws InvalidConfigValueException when the proposed name exceeds the allowed length
     */
    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      else if (val.length() > 128)
        throw new InvalidConfigValueException("The given node name is too long (" + val + ')');
      else if (val.isEmpty()) val = "~none~";
      synchronized (this) {
        node.setMyNameInternal(val);
      }
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.putSingle("myName", node.getMyName());
      node.network().peers().messenger().locallyBroadcastDiffNodeRef(fs, true, false);
      get();
    }
  }

  /**
   * Exposes and validates the store type option for the node's primary datastore.
   *
   * <p>The callback presents the current store type as a string option and constrains updates to a
   * small set of supported identifiers. Changes from the in-memory store to another type are
   * applied immediately; all other changes require a restart and are surfaced through a restart
   * exception after persisting the configured value. Callers should expect this callback to enforce
   * valid choices and to signal when a live transition is not supported.
   */
  public final class StoreTypeCallback extends StringCallback implements EnumerableOptionCallback {
    /**
     * Creates a store type callback bound to the enclosing manager's node.
     *
     * <p>The constructor performs no side effects. Callers typically instantiate this callback
     * during configuration registration and then let the configuration system invoke its methods.
     */
    public StoreTypeCallback() {
      // Intentionally empty: configuration system instantiates and calls the methods directly.
    }

    /**
     * Returns the currently configured primary store type identifier.
     *
     * <p>The returned value is the node's current storage setting and is intended for display or
     * comparison against {@link #getPossibleValues()}. It does not create or modify any store
     * instance; it simply reflects the stored configuration at the time of the call.
     *
     * @return the active store type identifier as a string
     */
    @Override
    public String get() {
      return node.storage().getStoreType();
    }

    /**
     * Validates and applies a new store type selection.
     *
     * <p>The value must be one of the allowed identifiers from {@link #getPossibleValues()}. When
     * the current store type is in-memory ({@code ram}), the change is applied immediately. For any
     * other current store type, the method records the new type and throws a restart exception to
     * signal that a live transition is unsupported. This method is not idempotent if the underlying
     * store type changes concurrently.
     *
     * @param val the requested store type identifier, matching one of the supported values
     * @throws InvalidConfigValueException when the value is not one of the supported identifiers
     * @throws NodeNeedRestartException when the change requires a node restart to take effect
     */
    @Override
    public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
      boolean found = false;
      for (String p : getPossibleValues()) {
        if (p.equals(val)) {
          found = true;
          break;
        }
      }
      if (!found) throw new InvalidConfigValueException("Invalid store type");

      String type = node.storage().getStoreType();
      if (type.equals("ram")) {
        synchronized (this) {
          node.storage().makeStore(val);
        }
      } else {
        node.storage().setStoreType(val);
        throw new NodeNeedRestartException("Store type cannot be changed on the fly");
      }
    }

    /**
     * Lists the supported store type identifiers for the primary datastore.
     *
     * <p>The returned array is a snapshot of the supported values and may be used by configuration
     * UIs or validators. Callers should treat the contents as case-sensitive identifiers and avoid
     * modifying the returned array.
     *
     * @return the supported store type identifiers in display order
     */
    @Override
    public String[] getPossibleValues() {
      return new String[] {Node.TYPE_SALT_HASH, "ram"};
    }
  }

  /**
   * Exposes and validates the client cache store type option.
   *
   * <p>The callback mirrors the node's client cache configuration. It verifies requested values
   * against a fixed list and applies changes in-place. Although the method signature allows a
   * restart exception, this implementation performs an immediate switch and does not request a
   * restart for supported values. Callers should still be prepared to handle a restart exception
   * for forward compatibility.
   */
  public final class ClientCacheTypeCallback extends StringCallback
      implements EnumerableOptionCallback {
    /**
     * Creates a client cache type callback bound to the enclosing manager's node.
     *
     * <p>The constructor itself is inert and defers all work to {@link #get()} and {@link
     * #set(String)} when invoked by the configuration system.
     */
    public ClientCacheTypeCallback() {
      // Intentionally empty: all behavior lives in get/set invoked by configuration wiring.
    }

    /**
     * Returns the currently configured client cache type identifier.
     *
     * <p>This value reflects the node's active client cache configuration. It is intended for
     * presentation in configuration UIs and for comparison against {@link #getPossibleValues()}.
     *
     * @return the active client cache type identifier as a string
     */
    @Override
    public String get() {
      return node.storage().getClientCacheType();
    }

    /**
     * Validates and applies a new client cache type selection.
     *
     * <p>The value must match one of the supported identifiers from {@link #getPossibleValues()}.
     * Unsupported values are rejected with a configuration error. Supported values are applied
     * immediately by delegating to the node's storage subsystem. This implementation does not
     * trigger a restart, but the signature allows for it if future implementations require one.
     *
     * @param val the requested client cache type identifier from the supported list
     * @throws InvalidConfigValueException when the value is not a supported identifier
     * @throws NodeNeedRestartException reserved for future implementations that require restart
     */
    @Override
    public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
      boolean found = false;
      for (String p : getPossibleValues()) {
        if (p.equals(val)) {
          found = true;
          break;
        }
      }
      if (!found) throw new InvalidConfigValueException("Invalid store type");

      synchronized (this) {
        node.storage().changeClientCacheType(val);
      }
    }

    /**
     * Lists the supported client cache type identifiers.
     *
     * <p>The returned array is intended for configuration UIs and validation logic. Identifiers are
     * case-sensitive and should be treated as opaque tokens rather than user-facing labels.
     *
     * @return the supported client cache type identifiers in display order
     */
    @Override
    public String[] getPossibleValues() {
      return new String[] {Node.TYPE_SALT_HASH, "ram", "none"};
    }
  }

  private static final class L10nCallback extends StringCallback
      implements EnumerableOptionCallback {
    @Override
    public String get() {
      return NodeL10n.getBase().getSelectedLanguage().fullName;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (val == null || get().equalsIgnoreCase(val)) return;
      try {
        NodeL10n.getBase().setLanguage(BaseL10n.LANGUAGE.mapToLanguage(val));
      } catch (MissingResourceException e) {
        throw new InvalidConfigValueException(e.getLocalizedMessage());
      }
      PluginManager.setLanguage(NodeL10n.getBase().getSelectedLanguage());
    }

    @Override
    public String[] getPossibleValues() {
      return BaseL10n.LANGUAGE.valuesWithFullNames();
    }
  }
}
