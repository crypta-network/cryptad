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

/** Node configuration registration and callbacks. */
public final class NodeConfigManager {
  private final Node node;

  public NodeConfigManager(Node node) {
    this.node = node;
  }

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

  /** Config callback for the node's display name. */
  public final class NodeNameCallback extends StringCallback {
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

  public final class StoreTypeCallback extends StringCallback implements EnumerableOptionCallback {
    @Override
    public String get() {
      return node.storage().getStoreType();
    }

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

    @Override
    public String[] getPossibleValues() {
      return new String[] {Node.TYPE_SALT_HASH, "ram"};
    }
  }

  public final class ClientCacheTypeCallback extends StringCallback
      implements EnumerableOptionCallback {
    @Override
    public String get() {
      return node.storage().getClientCacheType();
    }

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
