package network.crypta.node;

import java.util.ArrayList;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.StringCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Centralizes security level configuration for the node.
 *
 * <p>The node exposes three categories of security levels. The user selects initial values in the
 * first-time wizard and can reconfigure them later. Changing a level adjusts defaults for several
 * other configuration options and notifies listeners; users can still override individual options
 * explicitly. The UI provides per-level explanations and a dedicated configuration subpage. A
 * summary is also shown on the homepage as a user alert.
 *
 * <p>Thread-safety: public mutators synchronize on the instance and notify listeners outside the
 * critical section.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public final class SecurityLevels {
  private static final Logger LOG = LoggerFactory.getLogger(SecurityLevels.class);

  private static final String KEY_NETWORK_THREAT_LEVEL = "networkThreatLevel";
  private static final String KEY_PHYSICAL_THREAT_LEVEL = "physicalThreatLevel";
  private static final String L10N_PREFIX = "SecurityLevels.";
  private static final String TYPE_CHECKBOX = "checkbox";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String L10N_MAXIMUM_WARNING =
      "SecurityLevels.maximumNetworkThreatLevelWarning";

  private final Node node;

  /**
   * Network exposure and routing posture. Influences whether opennet is allowed and what hardening
   * is applied by default.
   */
  public enum NETWORK_THREAT_LEVEL {
    /** Favor performance; enable opennet; disable the most costly hardening. */
    LOW,
    /** Default hybrid mode; both darknet and opennet allowed. */
    NORMAL,
    /** Darknet only; otherwise standard defaults. */
    HIGH,
    /**
     * Most restrictive posture; darknet only and additional restrictions (for example, disable
     * friend-of-a-friend style discovery).
     */
    MAXIMUM;

    /**
     * Returns levels that permit opennet participation.
     *
     * @return an array containing {@link #LOW} and {@link #NORMAL}
     */
    public static NETWORK_THREAT_LEVEL[] getOpennetValues() {
      return new NETWORK_THREAT_LEVEL[] {LOW, NORMAL};
    }

    /**
     * Returns levels that require darknet-only operation.
     *
     * @return an array containing {@link #HIGH} and {@link #MAXIMUM}
     */
    public static NETWORK_THREAT_LEVEL[] getDarknetValues() {
      return new NETWORK_THREAT_LEVEL[] {HIGH, MAXIMUM};
    }
  }

  /**
   * Information-sharing posture toward friends (legacy option). Used to derive a default friend
   * trust when present.
   */
  public enum FRIENDS_THREAT_LEVEL {
    /** Friends are strongly trusted. */
    LOW,
    /** Share a limited amount of information. */
    NORMAL,
    /**
     * Share minimal information and prefer settings that reduce potential harm if friends are
     * compromised.
     */
    HIGH
  }

  /**
   * Protection level for data at rest on the local machine (temporary files, caches, and related
   * keys). Higher levels prefer stronger protections with functional trade-offs.
   */
  public enum PHYSICAL_THREAT_LEVEL {
    /** Do not encrypt temporary files and similar artifacts. */
    LOW,
    /**
     * Encrypt temporary files; centralize client cache keys in {@code master.keys}. If the key file
     * is deleted, the client cache becomes unreadable.
     */
    NORMAL,
    /** Require a password for {@code master.keys}. */
    HIGH,
    /** Use transient encryption; disable features that require persistent decrypted state. */
    MAXIMUM
  }

  volatile NETWORK_THREAT_LEVEL networkThreatLevel;
  FRIENDS_THREAT_LEVEL friendsThreatLevel;
  PHYSICAL_THREAT_LEVEL physicalThreatLevel;

  private final MyCallback<NETWORK_THREAT_LEVEL> networkThreatLevelCallback;
  private final MyCallback<PHYSICAL_THREAT_LEVEL> physicalThreatLevelCallback;

  /**
   * Creates a new holder for security levels and wires it to persistent configuration.
   *
   * <p>Registers options under the {@code security-levels} sub-config, initializes values from the
   * stored configuration, and invokes callbacks so dependent configuration remains consistent with
   * the selected levels.
   *
   * @param node the owning {@link Node}; used for peer counts when building warnings
   * @param config the persistent configuration root used to create the {@code security-levels}
   *     namespace
   */
  public SecurityLevels(Node node, PersistentConfig config) {
    this.node = node;
    SubConfig myConfig = config.createSubConfig("security-levels");
    int sortOrder = 0;
    networkThreatLevelCallback =
        new MyCallback<>() {

          @Override
          public String get() {
            synchronized (SecurityLevels.this) {
              return networkThreatLevel.name();
            }
          }

          @Override
          public String[] getPossibleValues() {
            NETWORK_THREAT_LEVEL[] values = NETWORK_THREAT_LEVEL.values();
            String[] names = new String[values.length];
            for (int i = 0; i < names.length; i++) {
              names[i] = values[i].name();
            }
            return names;
          }

          @Override
          protected NETWORK_THREAT_LEVEL getValue() {
            return networkThreatLevel;
          }

          @Override
          protected void setValue(String val) throws InvalidConfigValueException {
            NETWORK_THREAT_LEVEL newValue = parseNetworkThreatLevel(val);
            if (newValue == null) {
              throw new InvalidConfigValueException(
                  "Invalid value for network threat level: " + val);
            }
            synchronized (SecurityLevels.this) {
              networkThreatLevel = newValue;
            }
          }
        };
    myConfig.register(
        KEY_NETWORK_THREAT_LEVEL,
        "HIGH",
        new Option.Meta(
            sortOrder++,
            false,
            true,
            "SecurityLevels.networkThreatLevelShort",
            "SecurityLevels.networkThreatLevel"),
        networkThreatLevelCallback);
    NETWORK_THREAT_LEVEL netLevel =
        NETWORK_THREAT_LEVEL.valueOf(myConfig.getString(KEY_NETWORK_THREAT_LEVEL));
    if (myConfig.getRawOption(KEY_NETWORK_THREAT_LEVEL) != null) {
      networkThreatLevel = netLevel;
    } else {
      // Ensure dependent configuration aligns with the initial threat level.
      setThreatLevel(netLevel);
    }
    // Backward compatibility: read the legacy "friendsThreatLevel" option when present.
    String s = myConfig.getRawOption("friendsThreatLevel");
    if (s != null) {
      friendsThreatLevel = parseFriendsThreatLevel(s);
    } else {
      friendsThreatLevel = null;
    }
    physicalThreatLevelCallback =
        new MyCallback<>() {

          @Override
          public String get() {
            synchronized (SecurityLevels.this) {
              return physicalThreatLevel.name();
            }
          }

          @Override
          public String[] getPossibleValues() {
            PHYSICAL_THREAT_LEVEL[] values = PHYSICAL_THREAT_LEVEL.values();
            String[] names = new String[values.length];
            for (int i = 0; i < names.length; i++) {
              names[i] = values[i].name();
            }
            return names;
          }

          @Override
          protected PHYSICAL_THREAT_LEVEL getValue() {
            return physicalThreatLevel;
          }

          @Override
          protected void setValue(String val) throws InvalidConfigValueException {
            // Validate early to return a consistent error for invalid strings.
            try {
              PHYSICAL_THREAT_LEVEL.valueOf(val);
            } catch (IllegalArgumentException _) {
              throw new InvalidConfigValueException(
                  "Invalid value for physical threat level: " + val);
            }
            // Preserve behavior: this option is not settable directly via config callbacks.
            throw new InvalidConfigValueException(
                "Invalid value for physical threat level: " + val);
          }
        };
    myConfig.register(
        KEY_PHYSICAL_THREAT_LEVEL,
        "NORMAL",
        new Option.Meta(
            sortOrder,
            false,
            true,
            "SecurityLevels.physicalThreatLevelShort",
            "SecurityLevels.physicalThreatLevel"),
        physicalThreatLevelCallback);
    PHYSICAL_THREAT_LEVEL physLevel =
        PHYSICAL_THREAT_LEVEL.valueOf(myConfig.getString(KEY_PHYSICAL_THREAT_LEVEL));
    if (myConfig.getRawOption(KEY_PHYSICAL_THREAT_LEVEL) != null) {
      physicalThreatLevel = physLevel;
    } else {
      // Ensure dependent configuration aligns with the initial threat level.
      setThreatLevel(physLevel);
    }

    myConfig.finishedInitialization();
  }

  /**
   * Registers a listener for network threat level changes.
   *
   * <p>Duplicate registrations are ignored and logged. Thread-safe.
   *
   * @param listener callback invoked with old and new levels after a change
   */
  public synchronized void addNetworkThreatLevelListener(
      SecurityLevelListener<NETWORK_THREAT_LEVEL> listener) {
    networkThreatLevelCallback.addListener(listener);
  }

  /**
   * Registers a listener for physical threat level changes.
   *
   * <p>Duplicate registrations are ignored and logged. Thread-safe.
   *
   * @param listener callback invoked with old and new levels after a change
   */
  public synchronized void addPhysicalThreatLevelListener(
      SecurityLevelListener<PHYSICAL_THREAT_LEVEL> listener) {
    physicalThreatLevelCallback.addListener(listener);
  }

  private abstract static class MyCallback<T> extends StringCallback
      implements EnumerableOptionCallback {

    private final ArrayList<SecurityLevelListener<T>> listeners;

    MyCallback() {
      listeners = new ArrayList<>();
    }

    public void addListener(SecurityLevelListener<T> listener) {
      if (listeners.contains(listener)) {
        LOG.error("Duplicate listener registration: listener={} callback={}", listener, this);
        return;
      }
      listeners.add(listener);
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      T oldLevel = getValue();
      setValue(val);
      T newLevel = getValue();
      onSet(oldLevel, newLevel);
    }

    void onSet(T oldLevel, T newLevel) {
      for (SecurityLevelListener<T> listener : listeners) {
        listener.onChange(oldLevel, newLevel);
      }
    }

    protected abstract void setValue(String val) throws InvalidConfigValueException;

    protected abstract T getValue();
  }

  /**
   * Returns the current network threat level.
   *
   * @return non-null current value
   */
  public NETWORK_THREAT_LEVEL getNetworkThreatLevel() {
    return networkThreatLevel;
  }

  /**
   * Returns the current physical threat level.
   *
   * @return non-null current value
   */
  public PHYSICAL_THREAT_LEVEL getPhysicalThreatLevel() {
    return physicalThreatLevel;
  }

  /**
   * Parses a {@link NETWORK_THREAT_LEVEL} from its {@code name()}.
   *
   * @param arg exact enum name (case-sensitive)
   * @return the parsed level, or {@code null} when the string is not a valid value
   */
  public static NETWORK_THREAT_LEVEL parseNetworkThreatLevel(String arg) {
    try {
      return NETWORK_THREAT_LEVEL.valueOf(arg);
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  private static FRIENDS_THREAT_LEVEL parseFriendsThreatLevel(String arg) {
    try {
      return FRIENDS_THREAT_LEVEL.valueOf(arg);
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  /**
   * Parses a {@link PHYSICAL_THREAT_LEVEL} from its {@code name()}.
   *
   * @param arg exact enum name (case-sensitive)
   * @return the parsed level, or {@code null} when the string is not a valid value
   */
  public static PHYSICAL_THREAT_LEVEL parsePhysicalThreatLevel(String arg) {
    try {
      return PHYSICAL_THREAT_LEVEL.valueOf(arg);
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  /**
   * Builds a localized warning and confirmation UI when a level change may degrade connectivity.
   *
   * <p>If the requested {@code newThreatLevel} is more restrictive (for example, switching to
   * darknet-only) and the node has too few or no connected friends, the returned HTML contains a
   * warning paragraph and a confirmation checkbox named {@code checkboxName}. Returns {@code null}
   * when no warning is necessary (including when the level does not change or when switching to
   * {@link NETWORK_THREAT_LEVEL#NORMAL}).
   *
   * @param newThreatLevel the desired network level
   * @param checkboxName the HTML {@code input} name for the confirmation checkbox
   * @return a container {@link HTMLNode} with warnings and a checkbox, or {@code null} to indicate
   *     no confirmation is required
   */
  public HTMLNode getConfirmWarning(NETWORK_THREAT_LEVEL newThreatLevel, String checkboxName) {
    if (newThreatLevel == networkThreatLevel) {
      return null; // Not going to be changed.
    }
    HTMLNode parent = new HTMLNode("div");
    if (isHighOrMaximumTransition(newThreatLevel)) {
      HTMLNode res = handleHighOrMaximum(parent, newThreatLevel, checkboxName);
      if (res != null) return res;
    } else if (newThreatLevel == NETWORK_THREAT_LEVEL.LOW) {
      parent.addChild("p", l10n("networkThreatLevelLowWarning"));
      parent.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_CHECKBOX, checkboxName, "off"},
          l10n("networkThreatLevelLowCheckbox"));
      return parent;
    }
    // Don't warn on switching to NORMAL.
    if (newThreatLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
      HTMLNode p = parent.addChild("p");
      NodeL10n.getBase()
          .addL10nSubstitution(
              p, L10N_MAXIMUM_WARNING, new String[] {"bold"}, new HTMLNode[] {HTMLNode.STRONG});
      p.addChild("#", " ");
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "SecurityLevels.maxSecurityYouNeedFriends",
              new String[] {"bold"},
              new HTMLNode[] {HTMLNode.STRONG});
      parent.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_CHECKBOX, checkboxName, "off"},
          l10n("maximumNetworkThreatLevelCheckbox"));
      return parent;
    }
    return null;
  }

  private boolean isHighOrMaximumTransition(NETWORK_THREAT_LEVEL newThreatLevel) {
    return (newThreatLevel == NETWORK_THREAT_LEVEL.HIGH
            && networkThreatLevel != NETWORK_THREAT_LEVEL.MAXIMUM)
        || newThreatLevel == NETWORK_THREAT_LEVEL.MAXIMUM;
  }

  private HTMLNode handleHighOrMaximum(
      HTMLNode parent, NETWORK_THREAT_LEVEL newThreatLevel, String checkboxName) {
    if (node.network().peers().roster().getDarknetPeers().length == 0) {
      parent.addChild("p", l10n("noFriendsWarning"));
      if (newThreatLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
        HTMLNode p = parent.addChild("p");
        NodeL10n.getBase()
            .addL10nSubstitution(
                p, L10N_MAXIMUM_WARNING, new String[] {"bold"}, new HTMLNode[] {HTMLNode.STRONG});
      }
      parent.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_CHECKBOX, checkboxName, "off"},
          l10n("noFriendsCheckbox"));
      return parent;
    }
    if (node.network().peers().countConnectedDarknetPeers() == 0) {
      parent.addChild(
          "p",
          l10n(
              "noConnectedFriendsWarning",
              new String[] {"added"},
              new String[] {
                Integer.toString(node.network().peers().roster().getDarknetPeers().length)
              }));
      if (newThreatLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
        HTMLNode p = parent.addChild("p");
        NodeL10n.getBase()
            .addL10nSubstitution(
                p, L10N_MAXIMUM_WARNING, new String[] {"bold"}, new HTMLNode[] {HTMLNode.STRONG});
      }
      parent.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_CHECKBOX, checkboxName, "off"},
          l10n("noConnectedFriendsCheckbox"));
      return parent;
    }
    if (node.network().peers().countConnectedDarknetPeers() < 10) {
      parent.addChild(
          "p",
          l10n(
              "fewConnectedFriendsWarning",
              new String[] {"connected", "added"},
              new String[] {
                Integer.toString(node.network().peers().countConnectedDarknetPeers()),
                Integer.toString(node.network().peers().roster().getDarknetPeers().length)
              }));
      if (newThreatLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
        HTMLNode p = parent.addChild("p");
        NodeL10n.getBase()
            .addL10nSubstitution(
                p, L10N_MAXIMUM_WARNING, new String[] {"bold"}, new HTMLNode[] {HTMLNode.STRONG});
      }
      parent.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {TYPE_CHECKBOX, checkboxName, "off"},
          l10n("fewConnectedFriendsCheckbox"));
      return parent;
    }
    return null;
  }

  private String l10n(String string) {
    return NodeL10n.getBase().getString(L10N_PREFIX + string);
  }

  private String l10n(String string, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(L10N_PREFIX + string, patterns, values);
  }

  /**
   * Sets the network threat level and notifies listeners.
   *
   * <p>No-ops when the level is unchanged. Throws {@link NullPointerException} for {@code null}.
   * Thread-safe.
   *
   * @param newThreatLevel the new network level
   * @throws NullPointerException if {@code newThreatLevel} is {@code null}
   */
  public void setThreatLevel(NETWORK_THREAT_LEVEL newThreatLevel) {
    if (newThreatLevel == null) {
      throw new NullPointerException();
    }
    NETWORK_THREAT_LEVEL oldLevel;
    synchronized (this) {
      if (networkThreatLevel == newThreatLevel) {
        return;
      }
      oldLevel = networkThreatLevel;
      networkThreatLevel = newThreatLevel;
    }
    networkThreatLevelCallback.onSet(oldLevel, newThreatLevel);
  }

  /**
   * Sets the physical threat level and notifies listeners.
   *
   * <p>No-ops when the level is unchanged. Throws {@link NullPointerException} for {@code null}.
   * Thread-safe.
   *
   * @param newThreatLevel the new physical level
   * @throws NullPointerException if {@code newThreatLevel} is {@code null}
   */
  public void setThreatLevel(PHYSICAL_THREAT_LEVEL newThreatLevel) {
    if (newThreatLevel == null) {
      throw new NullPointerException();
    }
    PHYSICAL_THREAT_LEVEL oldLevel;
    synchronized (this) {
      if (physicalThreatLevel == newThreatLevel) {
        return;
      }
      oldLevel = physicalThreatLevel;
      physicalThreatLevel = newThreatLevel;
    }
    physicalThreatLevelCallback.onSet(oldLevel, newThreatLevel);
  }

  /**
   * Resets the stored physical threat level without notifying listeners.
   *
   * <p>Intended for internal synchronization with external state when the caller will explicitly
   * handle notifications.
   *
   * @param level the physical level to store
   */
  public void resetPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL level) {
    physicalThreatLevel = level;
  }

  /**
   * Returns a localized display name for the given network level.
   *
   * @param newThreatLevel the level to format
   * @return non-null localized name from {@link NodeL10n}
   */
  public static String localisedName(NETWORK_THREAT_LEVEL newThreatLevel) {
    return NodeL10n.getBase()
        .getString("SecurityLevels.networkThreatLevel.name." + newThreatLevel.name());
  }

  /**
   * Returns a localized display name for the given physical level.
   *
   * @param newPhysicalLevel the level to format
   * @return non-null localized name from {@link NodeL10n}
   */
  public static String localisedName(PHYSICAL_THREAT_LEVEL newPhysicalLevel) {
    return NodeL10n.getBase()
        .getString("SecurityLevels.physicalThreatLevel.name." + newPhysicalLevel.name());
  }

  /**
   * Derives the default {@link FRIEND_TRUST} from {@link #friendsThreatLevel}.
   *
   * <p>When the legacy friends threat level is not available, logs an error and returns {@link
   * FRIEND_TRUST#NORMAL}. Otherwise, maps {@code HIGH -> LOW}, {@code NORMAL -> NORMAL}, and {@code
   * LOW -> HIGH}.
   *
   * @return the default friend trust to apply
   */
  public FRIEND_TRUST getDefaultFriendTrust() {
    synchronized (this) {
      if (friendsThreatLevel == null) {
        LOG.error("Default friend trust requested but friendsThreatLevel is unset");
        return FRIEND_TRUST.NORMAL;
      }
      if (friendsThreatLevel == FRIENDS_THREAT_LEVEL.HIGH) {
        return FRIEND_TRUST.LOW;
      }
      if (friendsThreatLevel == FRIENDS_THREAT_LEVEL.NORMAL) {
        return FRIEND_TRUST.NORMAL;
      } else // friendsThreatLevel == FRIENDS_THREAT_LEVEL.LOW
      {
        return FRIEND_TRUST.HIGH;
      }
    }
  }
}
