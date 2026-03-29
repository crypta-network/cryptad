package network.crypta.config;

import java.util.function.LongSupplier;
import network.crypta.support.Fields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared datastore-sizing helper for first-time setup flows.
 *
 * <p>This class owns the config write math historically embedded in the HTTP wizard step, so other
 * daemon-backed adapters can reuse the exact same behavior without depending on the HTTP package.
 * It applies a total datastore selection to the concrete node configuration keys that back the main
 * store, client cache, and slashdot or recent-requests cache. The implementation is intended to be
 * behavior-preserving during module extraction, so it keeps the same split formulas, size caps,
 * logging shape, and exception-handling behavior that the legacy wizard step used.
 *
 * <p>The helper is stateless. Each call parses the requested size, consults a caller-supplied
 * maximum, derives the related cache sizes from current bandwidth and lifetime settings, and writes
 * the resulting values into the supplied {@link Config}. It does not persist the config to disk on
 * its own; callers remain responsible for any later store step in the surrounding workflow.
 */
public final class DatastoreSizingSupport {

  private static final Logger LOG =
      LoggerFactory.getLogger("network.crypta.clients.http.wizardsteps.DatastoreSize");

  private static final long ONE_GIB = 1024L * 1024L * 1024L;

  private DatastoreSizingSupport() {
    throw new AssertionError("No instances");
  }

  /**
   * Applies a datastore size selection using the provided maximum-size supplier.
   *
   * <p>This overload preserves the historical first-run behavior: after applying the size split, it
   * also initializes the related {@code storeType} and {@code clientCacheType} options to their
   * expected first-time defaults. Use it for flows that are creating a fresh configuration rather
   * than editing an existing node in place.
   *
   * @param selectedStoreSize datastore size selection string, typically including a recognized unit
   *     suffix such as {@code GiB}
   * @param config configuration instance updated in-place with the derived store and cache values
   * @param maxDatastoreSizeSupplier supplier for the current maximum allowed datastore size in
   *     bytes, evaluated during the call
   */
  public static void setDatastoreSize(
      String selectedStoreSize, Config config, LongSupplier maxDatastoreSizeSupplier) {
    setDatastoreSize(selectedStoreSize, true, config, maxDatastoreSizeSupplier);
  }

  /**
   * Applies a datastore size selection using the provided first-time flag and max-size supplier.
   *
   * <p>The selected size is parsed once and treated as the total budget for the store plus the two
   * related caches. The helper assigns up to ten percent to the client cache, assigns up to ten
   * percent to the slashdot or recent-requests cache while respecting the existing bandwidth-based
   * cap, and writes the remainder to {@code node.storeSize}. If the requested size exceeds the
   * supplied maximum, the method preserves the legacy behavior by routing the resulting {@link
   * InvalidConfigValueException} through the existing {@link ConfigException} catch block and
   * logging the failure instead of rethrowing it to the caller.
   *
   * @param selectedStoreSize datastore size selection string, typically including a recognized unit
   *     suffix
   * @param firsttime whether the related {@code *Type} options should be initialized to
   *     first-configuration defaults during this call
   * @param config configuration instance updated in-place with the derived store and cache values
   * @param maxDatastoreSizeSupplier supplier for the current maximum allowed datastore size in
   *     bytes, evaluated after parsing the requested size
   */
  public static void setDatastoreSize(
      String selectedStoreSize,
      boolean firsttime,
      Config config,
      LongSupplier maxDatastoreSizeSupplier) {
    try {
      long size = Fields.parseLong(selectedStoreSize);

      long maxDatastoreSize = maxDatastoreSizeSupplier.getAsLong();
      if (size > maxDatastoreSize) {
        throw new InvalidConfigValueException(
            "Attempting to set DatastoreSize ("
                + size
                + ") larger than maxDatastoreSize ("
                + maxDatastoreSize / ONE_GIB
                + " GiB)");
      }

      // client cache: 10% up to 200MB
      long clientCacheSize = Math.min(size / 10, 200L * 1024 * 1024);
      // recent requests cache / slashdot cache / ULPR cache
      int upstreamLimit = config.get("node").getInt("outputBandwidthLimit");
      int downstreamLimit = config.get("node").getInt("inputBandwidthLimit");
      // is used for remote stuff, so go by the minimum of the two
      int limit;
      if (downstreamLimit <= 0) limit = upstreamLimit;
      else limit = Math.min(downstreamLimit, upstreamLimit);
      // A 35 KiB/sec limit has been seen to have 0.5 store writes per second.
      // Reserving enough room to cache everything only doubles that rate.
      // Most traffic is at a low enough HTL to go to the datastore instead.
      // That means this slashdot cache estimate could probably be smaller.
      long lifetime = config.get("node").getLong("slashdotCacheLifetime");
      long maxSlashdotCacheSize = (lifetime / 1000) * limit;
      long slashdotCacheSize = Math.min(size / 10, maxSlashdotCacheSize);

      long storeSize = size - (clientCacheSize + slashdotCacheSize);

      if (LOG.isInfoEnabled()) {
        LOG.info("Setting datastore size to {}", Fields.longToString(storeSize, true));
      }
      config.get("node").set("storeSize", Fields.longToString(storeSize, true));
      if (firsttime) config.get("node").set("storeType", "salt-hash");
      if (LOG.isInfoEnabled()) {
        LOG.info("Setting client cache size to {}", Fields.longToString(clientCacheSize, true));
      }
      config.get("node").set("clientCacheSize", Fields.longToString(clientCacheSize, true));
      if (firsttime) config.get("node").set("clientCacheType", "salt-hash");
      if (LOG.isInfoEnabled()) {
        LOG.info(
            "Setting slashdot/ULPR/recent requests cache size to {}",
            Fields.longToString(slashdotCacheSize, true));
      }
      config.get("node").set("slashdotCacheSize", Fields.longToString(slashdotCacheSize, true));

      LOG.info("The storeSize has been set to {}", selectedStoreSize);
    } catch (ConfigException e) {
      LOG.error("Unexpected configuration error; please report this issue.", e);
    }
  }
}
