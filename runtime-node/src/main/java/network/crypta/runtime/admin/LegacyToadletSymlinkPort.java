package network.crypta.runtime.admin;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.StringArrCallback;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ToadletSymlinkEntry;
import network.crypta.runtime.spi.ToadletSymlinkPort;

/**
 * Adapts the symlinker persistence SPI to the legacy daemon runtime.
 *
 * <p>This adapter bridges {@link ToadletSymlinkPort} to the existing {@code
 * toadletsymlinker.symlinks} node configuration. It lazily registers the legacy string array option
 * the first time a caller loads or persists aliases, parses stored {@code alias#target} entries
 * into detached DTOs, and writes full snapshots back through the node config store. That lets
 * {@code SymlinkerToadlet} keep owning the live alias map and redirect semantics while the daemon
 * module continues to own persistence across restarts.
 *
 * <p>The current persisted snapshot is stored separately from the toadlet's runtime map, so config
 * callbacks and request threads can exchange detached values without pulling daemon config classes
 * into the HTTP layer.
 */
final class LegacyToadletSymlinkPort implements ToadletSymlinkPort {
  private static final String CONFIG_PREFIX = "toadletsymlinker";
  private static final String OPTION_SYMLINKS = "symlinks";
  private static final Option.Meta SYMLINK_OPTION_META =
      new Option.Meta(9, true, false, "SymlinkerToadlet.symlinks", "SymlinkerToadlet.symlinksLong");

  private final Node node;
  private final NodeClientCore core;

  private volatile boolean initialized;
  private final AtomicReference<List<ToadletSymlinkEntry>> configuredEntries =
      new AtomicReference<>(List.of());

  /**
   * Creates a lazy adapter for the node's persisted symlink configuration.
   *
   * <p>Construction does not immediately register the legacy subconfig. Initialization is deferred
   * until the first load or persist operation, so runtime-port assembly does not eagerly mutate the
   * node configuration tree.
   *
   * @param node live node that owns the {@code toadletsymlinker} configuration subtree
   * @param core client-core instance used to request config persistence after updates
   */
  LegacyToadletSymlinkPort(Node node, NodeClientCore core) {
    this.node = Objects.requireNonNull(node, "node");
    this.core = Objects.requireNonNull(core, "core");
  }

  @Override
  public List<ToadletSymlinkEntry> loadConfiguredSymlinks() {
    ensureInitialized();
    return configuredEntries.get();
  }

  @Override
  public void persistConfiguredSymlinks(List<ToadletSymlinkEntry> entries) {
    ensureInitialized();
    configuredEntries.set(List.copyOf(entries));
    core.storeConfig();
  }

  private void ensureInitialized() {
    if (initialized) {
      return;
    }

    synchronized (this) {
      if (initialized) {
        return;
      }

      SubConfig symlinkConfig = node.getConfig().createSubConfig(CONFIG_PREFIX);
      symlinkConfig.register(OPTION_SYMLINKS, null, SYMLINK_OPTION_META, new Callback());
      configuredEntries.set(parseConfiguredEntries(symlinkConfig.getStringArr(OPTION_SYMLINKS)));
      symlinkConfig.finishedInitialization();
      initialized = true;
    }
  }

  private static List<ToadletSymlinkEntry> parseConfiguredEntries(String[] rawEntries) {
    if (rawEntries == null) {
      return List.of();
    }

    List<ToadletSymlinkEntry> parsedEntries = new ArrayList<>();
    for (String rawEntry : rawEntries) {
      int hashIndex = rawEntry.indexOf('#');
      if (hashIndex > 0
          && hashIndex == rawEntry.lastIndexOf('#')
          && hashIndex < rawEntry.length() - 1) {
        parsedEntries.add(
            new ToadletSymlinkEntry(
                rawEntry.substring(0, hashIndex), rawEntry.substring(hashIndex + 1)));
      }
    }
    return List.copyOf(parsedEntries);
  }

  private final class Callback extends StringArrCallback {
    @Override
    public String[] get() {
      return serializeConfiguredEntries();
    }

    private String[] serializeConfiguredEntries() {
      List<ToadletSymlinkEntry> entries = configuredEntries.get();
      String[] serialized = new String[entries.size()];
      for (int i = 0; i < entries.size(); i++) {
        ToadletSymlinkEntry entry = entries.get(i);
        serialized[i] = entry.alias() + '#' + entry.target();
      }
      return serialized;
    }

    @Override
    public void set(String[] value) throws InvalidConfigValueException {
      throw new InvalidConfigValueException("Cannot set loaded symlinks directly.");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }
}
