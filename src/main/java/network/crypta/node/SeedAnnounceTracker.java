package network.crypta.node;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Random;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.LRUMap;
import network.crypta.support.io.InetAddressComparator;

import static java.util.concurrent.TimeUnit.HOURS;

/**
 * Tracks announce activity per IP address to identify and de-prioritize peers that repeatedly
 * request seed node references.
 *
 * <p>This tracker maintains lightweight, per-address counters in an {@link LRUMap}. It applies a
 * simple probabilistic gate to throttle excessive announce requests from the same address and
 * periodically resets its state to bound memory and decay history. All mutations are synchronized
 * on the instance to provide thread safety.
 *
 * <p>State is in-memory only and not persisted across process restarts.
 */
public class SeedAnnounceTracker {

  private final LRUMap<InetAddress, TrackerItem> itemsByIP =
      LRUMap.createSafeMap(InetAddressComparator.COMPARATOR);

  // Bound the number of distinct IP entries to cap memory usage.
  private static final int MAX_SIZE = 100 * 1000;
  // Limit the number of rows shown in the stats table.
  private static final int TOP_ITEMS_COUNT = 20;

  /** Per-address counters and last observed version. */
  private static class TrackerItem {

    private TrackerItem(InetAddress addr) {
      this.addr = addr;
    }

    private final InetAddress addr;
    private int totalSeedConnects;
    private int totalAnnounceRequests;
    private int totalAcceptedAnnounceRequests;
    private int totalCompletedAnnounceRequests;
    private int totalSentRefs;
    private int lastVersion;

    public void acceptedAnnounce() {
      totalAnnounceRequests++;
      totalAcceptedAnnounceRequests++;
    }

    public void rejectedAnnounce() {
      totalAnnounceRequests++;
    }

    public void connected() {
      totalSeedConnects++;
    }

    public void setVersion(int ver) {
      if (ver <= 0) return;
      lastVersion = ver;
    }

    public void completed(int forwardedRefs) {
      totalCompletedAnnounceRequests++;
      totalSentRefs += forwardedRefs;
    }
  }

  // Reset counters every 2 hours to decay history and bound memory; no smoothing is applied.
  static final long RESET_TIME = HOURS.toMillis(2);

  private long lastReset = System.currentTimeMillis();

  /**
   * Decides whether to accept an announce from the given seed client and updates per-address
   * counters.
   *
   * <p>Heuristics: if the IP has received more than 5 node references and the peer runs an
   * unrouteable older version, it is rejected with an 80% probability. If the IP has received more
   * than 10 node references (any version), it is rejected with a 75% probability. Otherwise, the
   * announce is accepted. Decisions are randomized using the provided {@link Random}.
   *
   * <p>Thread safety: this method synchronizes on {@code this}. It may clear internal state when
   * the reset interval elapses.
   *
   * @param source the announcing peer (provides IP address and build number); must not be null
   * @param fastRandom a non-cryptographic random source used for probabilistic throttling; must not
   *     be null
   * @return {@code true} if the announce is accepted, {@code false} if it is rejected based on the
   *     current counters and heuristics
   */
  public boolean acceptAnnounce(SeedClientPeerNode source, Random fastRandom) {
    InetAddress addr = source.getPeer().getAddress();
    int ver = source.getBuildNumber();
    boolean badVersion = source.isUnroutableOlderVersion();
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (now - lastReset > RESET_TIME) {
        itemsByIP.clear();
        lastReset = now;
      }
      TrackerItem item = itemsByIP.get(addr);
      if (item == null) {
        item = new TrackerItem(addr);
      } else {
        boolean reject = false;
        if (item.totalSentRefs > 5 && badVersion) {
          reject = fastRandom.nextInt(5) != 0;
        } else if (item.totalSentRefs > 10) {
          reject = fastRandom.nextInt(4) != 0;
        }
        if (reject) return false;
      }
      item.acceptedAnnounce();
      item.setVersion(ver);
      itemsByIP.push(addr, item);
      while (itemsByIP.size() > MAX_SIZE) itemsByIP.popKey();
      return true;
    }
  }

  /**
   * Records a rejected announce for the given peer address and updates the last seen version.
   *
   * <p>Thread safety: synchronizes on {@code this}. The map may evict the least-recently-used entry
   * to maintain {@link #MAX_SIZE}.
   *
   * @param source the announcing peer for which an announce was rejected; must not be null
   */
  public void rejectedAnnounce(SeedClientPeerNode source) {
    InetAddress addr = source.getPeer().getAddress();
    int ver = source.getBuildNumber();
    synchronized (this) {
      TrackerItem item = itemsByIP.get(addr);
      if (item == null) item = new TrackerItem(addr);
      item.rejectedAnnounce();
      item.setVersion(ver);
      itemsByIP.push(addr, item);
      while (itemsByIP.size() > MAX_SIZE) itemsByIP.popKey();
    }
  }

  /**
   * Records a seed connection from the given peer and updates the last seen version.
   *
   * <p>Thread safety: synchronizes on {@code this}. The map may evict the least-recently-used entry
   * to maintain {@link #MAX_SIZE}.
   *
   * @param source the peer that connected to the seed; must not be null
   */
  public void onConnectSeed(SeedClientPeerNode source) {
    InetAddress addr = source.getPeer().getAddress();
    int ver = source.getBuildNumber();
    synchronized (this) {
      TrackerItem item = itemsByIP.get(addr);
      if (item == null) item = new TrackerItem(addr);
      item.connected();
      item.setVersion(ver);
      itemsByIP.push(addr, item);
      while (itemsByIP.size() > MAX_SIZE) itemsByIP.popKey();
    }
  }

  /**
   * Records a completed announce and the number of forwarded node references for the given peer.
   *
   * <p>Thread safety: synchronizes on {@code this}. The map may evict the least-recently-used entry
   * to maintain {@link #MAX_SIZE}.
   *
   * @param source the peer that completed the announce; must not be null
   * @param forwardedRefs number of node references forwarded to the peer; must be non-negative
   */
  public void completedAnnounce(SeedClientPeerNode source, int forwardedRefs) {
    InetAddress addr = source.getPeer().getAddress();
    int ver = source.getBuildNumber();
    synchronized (this) {
      TrackerItem item = itemsByIP.get(addr);
      if (item == null) item = new TrackerItem(addr);
      item.completed(forwardedRefs);
      item.setVersion(ver);
      itemsByIP.push(addr, item);
      while (itemsByIP.size() > MAX_SIZE) itemsByIP.popKey();
    }
  }

  /**
   * Renders a summary table of the most active IP addresses into the provided HTML node.
   *
   * <p>The table includes columns for IP address, connection and announce counts, accept/completion
   * counts, forwarded references, and the last observed build number. Column headers are resolved
   * via {@link NodeL10n} keys.
   *
   * <p>Thread safety: obtains a snapshot via {@link #getTopTrackerItems()} and renders it without
   * holding internal locks.
   *
   * @param content the container node to which the table is appended; must not be null
   */
  public void drawSeedStats(HTMLNode content) {
    TrackerItem[] topItems = getTopTrackerItems();
    if (topItems.length == 0) return;
    HTMLNode table = content.addChild("table", "border", "0");
    HTMLNode row = table.addChild("tr");
    row.addChild("th", l10nStats("seedTableIP"));
    row.addChild("th", l10nStats("seedTableConnections"));
    row.addChild("th", l10nStats("seedTableAnnouncements"));
    row.addChild("th", l10nStats("seedTableAccepted"));
    row.addChild("th", l10nStats("seedTableCompleted"));
    row.addChild("th", l10nStats("seedTableForwarded"));
    row.addChild("th", l10nStats("seedTableVersion"));
    for (TrackerItem item : topItems) {
      row = table.addChild("tr");
      row.addChild("td", item.addr.getHostAddress());
      row.addChild("td", Integer.toString(item.totalSeedConnects));
      row.addChild("td", Integer.toString(item.totalAnnounceRequests));
      row.addChild("td", Integer.toString(item.totalAcceptedAnnounceRequests));
      row.addChild("td", Integer.toString(item.totalCompletedAnnounceRequests));
      row.addChild("td", Integer.toString(item.totalSentRefs));
      row.addChild("td", Integer.toString(item.lastVersion));
    }
  }

  // Returns the most active items sorted by activity; synchronized to snapshot a stable view.
  private synchronized TrackerItem[] getTopTrackerItems() {
    TrackerItem[] items = new TrackerItem[itemsByIP.size()];
    itemsByIP.valuesToArray(items);
    Arrays.sort(
        items,
        (arg0, arg1) -> {
          int a = Math.max(arg0.totalAnnounceRequests, arg0.totalSeedConnects);
          int b = Math.max(arg1.totalAnnounceRequests, arg1.totalSeedConnects);
          if (a > b) {
            return 1;
          }
          if (b > a) {
            return -1;
          }
          if (arg0.totalAcceptedAnnounceRequests > arg1.totalAcceptedAnnounceRequests) {
            return 1;
          } else if (arg0.totalAcceptedAnnounceRequests < arg1.totalAcceptedAnnounceRequests) {
            return -1;
          }
          return 0;
        });
    int topLength = Math.min(TOP_ITEMS_COUNT, items.length);
    return Arrays.copyOfRange(items, items.length - topLength, items.length);
  }

  /** Returns a localized statistics label for the given key. */
  private String l10nStats(String key) {
    return NodeL10n.getBase().getString("StatisticsToadlet." + key);
  }
}
