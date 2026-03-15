package network.crypta.node.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.io.AddressTracker;
import network.crypta.io.AddressTrackerItem;
import network.crypta.io.InetAddressAddressTrackerItem;
import network.crypta.io.PeerAddressTrackerItem;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.runtime.spi.ConnectivityGapSnapshot;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.ConnectivityPortForwardStatus;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficInitiator;
import network.crypta.support.SimpleFieldSet;

/**
 * Adapts the daemon's legacy connectivity state to the runtime SPI's {@link ConnectivityPort}.
 *
 * <p>This bridge keeps knowledge of {@link Node}, {@link UdpSocketHandler}, {@link AddressTracker},
 * and the legacy tracker item types inside the daemon root module while exposing only detached
 * JDK-only snapshots to the HTTP layer. It is intentionally read-only and preserves the current
 * connectivity page semantics without exposing daemon configuration objects to callers.
 *
 * <p>The adapter takes one live pass over the daemon state when {@link #snapshot(boolean)} is
 * called. Summary-only requests avoid the per-entry tracker export work used by the advanced page,
 * which keeps this slice aligned with the current HTTP cost boundary.
 */
final class LegacyConnectivityPort implements ConnectivityPort {
  /** Configuration key used by listener subsets to report whether the listener is enabled. */
  private static final String ENABLED_KEY = "enabled";

  /** Live daemon root used only while building detached snapshots for the SPI layer. */
  private final Node node;

  /**
   * Creates a connectivity adapter backed by the legacy daemon root.
   *
   * @param node live node whose runtime state is exported through detached SPI snapshots
   */
  LegacyConnectivityPort(Node node) {
    this.node = Objects.requireNonNull(node);
  }

  @Override
  public ConnectivitySnapshot snapshot(boolean includeAdvancedDetails) {
    UdpSocketHandler[] handlers = node.network().packetSocketHandlers();
    List<ConnectivitySocketSnapshot> sockets = new ArrayList<>(handlers.length);
    for (UdpSocketHandler handler : handlers) {
      sockets.add(toSocketSnapshot(handler, includeAdvancedDetails));
    }
    return new ConnectivitySnapshot(
        node.network().fnpPort(),
        node.network().opennetFnpPort(),
        listenerPort("fproxy"),
        listenerPort("fcp"),
        listenerPort("console"),
        connectionTypeNotice(),
        List.copyOf(sockets));
  }

  /**
   * Reads one listener subset from the legacy configuration tree.
   *
   * <p>The connectivity page only needs the enabled flag and the configured port. Parse failures
   * are treated as a disabled listener, so the read-only admin view remains resilient to incomplete
   * or transient configuration state.
   *
   * @param subsetName configuration subset name such as {@code fproxy}, {@code fcp}, or {@code
   *     console}
   * @return detached listener snapshot derived from the current node configuration
   */
  private ConnectivityListenerPortSnapshot listenerPort(String subsetName) {
    try {
      SimpleFieldSet config = node.getConfig().get(subsetName).exportFieldSet(true);
      boolean enabled = config.getBoolean(ENABLED_KEY, false);
      int port = enabled ? config.getInt("port") : 0;
      return new ConnectivityListenerPortSnapshot(enabled, port);
    } catch (FSParseException _) {
      return new ConnectivityListenerPortSnapshot(false, 0);
    }
  }

  /**
   * Exports the current connection-type notice when the detector has one available.
   *
   * <p>The returned snapshot is already detached from the daemon alert classes and may include a
   * rendered alert fragment that preserves the old connectivity-page infobox behavior.
   *
   * @return detached connection-type notice, or {@code null} when no notice is active
   */
  private ConnectivityNoticeSnapshot connectionTypeNotice() {
    return node.network().ipDetector().connectionTypeNotice();
  }

  /**
   * Converts one live UDP socket handler into a detached socket snapshot.
   *
   * <p>When advanced details are disabled, the method returns only the summary fields needed by the
   * basic connectivity page. Advanced mode includes the tracker-derived gap and table data.
   *
   * @param handler live UDP socket handler to inspect
   * @param includeAdvancedDetails whether tracker-table details should be exported
   * @return detached socket snapshot for the current handler state
   */
  private ConnectivitySocketSnapshot toSocketSnapshot(
      UdpSocketHandler handler, boolean includeAdvancedDetails) {
    AddressTracker tracker = handler.getAddressTracker();
    if (!includeAdvancedDetails) {
      return new ConnectivitySocketSnapshot(
          handler.getTitle(),
          toPortForwardStatus(tracker.getPortForwardStatus()),
          -1,
          List.of(),
          List.of());
    }

    return new ConnectivitySocketSnapshot(
        handler.getTitle(),
        toPortForwardStatus(tracker.getPortForwardStatus()),
        tracker.getLongestSendReceiveGap(),
        peerEntries(tracker.getPeerAddressTrackerItems()),
        ipEntries(tracker.getInetAddressTrackerItems()));
  }

  /**
   * Converts peer tracker items into detached table rows.
   *
   * @param items live peer tracker items returned by the daemon address tracker
   * @return immutable list of detached peer-entry snapshots in iteration order
   */
  private List<ConnectivityTrafficEntrySnapshot> peerEntries(PeerAddressTrackerItem[] items) {
    List<ConnectivityTrafficEntrySnapshot> entries = new ArrayList<>(items.length);
    for (PeerAddressTrackerItem item : items) {
      entries.add(toTrafficEntry(item.peer.toString(), item));
    }
    return List.copyOf(entries);
  }

  /**
   * Converts IP tracker items into detached table rows.
   *
   * @param items live IP tracker items returned by the daemon address tracker
   * @return immutable list of detached IP-entry snapshots in iteration order
   */
  private List<ConnectivityTrafficEntrySnapshot> ipEntries(InetAddressAddressTrackerItem[] items) {
    List<ConnectivityTrafficEntrySnapshot> entries = new ArrayList<>(items.length);
    for (InetAddressAddressTrackerItem item : items) {
      entries.add(toTrafficEntry(item.addr.toString(), item));
    }
    return List.copyOf(entries);
  }

  /**
   * Converts one tracker item into the detached row model used by the SPI.
   *
   * @param address rendered peer or IP label that should appear in the advanced table
   * @param trackerItem live tracker item supplying counters, timing, and gap history
   * @return detached traffic-entry snapshot with immutable gap history
   */
  private ConnectivityTrafficEntrySnapshot toTrafficEntry(
      String address, AddressTrackerItem trackerItem) {
    return new ConnectivityTrafficEntrySnapshot(
        address,
        trackerItem.packetsSent(),
        trackerItem.packetsReceived(),
        toInitiator(trackerItem),
        trackerItem.timeFromStartupToFirstSentPacket(),
        trackerItem.timeFromStartupToFirstReceivedPacket(),
        gapSnapshots(trackerItem.getGaps()));
  }

  /**
   * Converts the tracker gap array into immutable detached snapshots.
   *
   * @param gaps live tracker gap array in daemon order
   * @return immutable list of detached gap snapshots in the same order
   */
  private List<ConnectivityGapSnapshot> gapSnapshots(AddressTrackerItem.Gap[] gaps) {
    List<ConnectivityGapSnapshot> snapshots = new ArrayList<>(gaps.length);
    for (AddressTrackerItem.Gap gap : gaps) {
      snapshots.add(new ConnectivityGapSnapshot(gap.gapLength(), gap.receivedPacketAt()));
    }
    return List.copyOf(snapshots);
  }

  /**
   * Maps the legacy tracker initiator view to the detached SPI enum.
   *
   * @param trackerItem live tracker item whose counters indicate who sent first
   * @return detached initiator classification for the advanced tracker table
   */
  private ConnectivityTrafficInitiator toInitiator(AddressTrackerItem trackerItem) {
    if (trackerItem.packetsReceived() == 0) {
      return ConnectivityTrafficInitiator.NO_REPLY;
    }
    return trackerItem.weSentFirst()
        ? ConnectivityTrafficInitiator.LOCAL
        : ConnectivityTrafficInitiator.REMOTE;
  }

  /**
   * Maps the daemon's address-tracker status enum to the SPI status enum.
   *
   * @param status legacy address-tracker status for one UDP socket
   * @return detached port-forwarding status used by the HTTP layer
   */
  private ConnectivityPortForwardStatus toPortForwardStatus(AddressTracker.Status status) {
    return switch (status) {
      case DEFINITELY_NATED -> ConnectivityPortForwardStatus.DEFINITELY_NATED;
      case MAYBE_NATED -> ConnectivityPortForwardStatus.MAYBE_NATED;
      case DONT_KNOW -> ConnectivityPortForwardStatus.DONT_KNOW;
      case MAYBE_PORT_FORWARDED -> ConnectivityPortForwardStatus.MAYBE_PORT_FORWARDED;
      case DEFINITELY_PORT_FORWARDED -> ConnectivityPortForwardStatus.DEFINITELY_PORT_FORWARDED;
    };
  }
}
