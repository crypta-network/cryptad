package network.crypta.node;

import network.crypta.node.stats.StoreLocationStats;
import network.crypta.store.StoreCallback;
import network.crypta.support.math.DecayingKeyspaceAverage;

/**
 * Provides {@link StoreLocationStats} views backed by {@link NodeStats} store metrics.
 *
 * <p>This class is a small adapter that exposes per-store averages and distance summaries as
 * read-only {@link StoreLocationStats} views. Callers typically create one instance from a
 * fully-initialized {@link NodeStats} and then request a view for a specific store or cache type
 * when assembling status tables or UI snapshots. Each method call creates a lightweight view that
 * delegates directly to the underlying averages and store callbacks, so values are live snapshots
 * and may change between invocations as the node runs. The provider itself is immutable and does
 * not cache or normalize values beyond the explicit ratio capping described below.
 *
 * <ul>
 *   <li>Builds per-store views without mutating {@link NodeStats}.
 *   <li>Computes average distances via {@link Location#distance(double, double)} on demand.
 *   <li>Caps distance-stat ratios at {@code 1.0} to avoid over-reporting.
 * </ul>
 *
 * @see NodeStats
 * @see network.crypta.node.subsystem.NodeStorageSubsystem#getDataStoreStats()
 * @see StoreLocationStats
 */
public final class NodeStoreStatsProvider {
  private final NodeStats stats;

  /**
   * Creates a provider that reads store statistics from the supplied {@link NodeStats}.
   *
   * <p>The provider retains a direct reference to the supplied instance and does not perform
   * defensive copies or synchronization. Callers should pass a fully constructed {@link NodeStats}
   * that remains valid for the lifetime of this provider. All views returned by this class will
   * reflect whatever state the {@code NodeStats} exposes at call time, so concurrent updates may be
   * visible between successive calls.
   *
   * @param stats source of store and cache statistics; must be non-null and initialized.
   */
  public NodeStoreStatsProvider(NodeStats stats) {
    this.stats = stats;
  }

  /**
   * Returns a {@link StoreLocationStats} view for the CHK datastore.
   *
   * <p>The returned view exposes averages and distance summaries derived from the decaying CHK
   * datastore metrics in {@link NodeStats}. It is a lightweight adapter created per call and does
   * not cache values; each method delegates directly to the underlying averages, the node location
   * manager, and the datastore callback. The view's {@code avgDist()} is computed using {@link
   * Location#distance(double, double)} and therefore reflects the node's current location at call
   * time. Distance statistics are reported as a ratio of reported samples to datastore key count
   * and are capped at {@code 1.0}.
   *
   * @return a live view of CHK datastore location and success metrics.
   */
  public StoreLocationStats chkStoreStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgStoreCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgStoreCHKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestStoreCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgStoreCHKLocation, stats.node.storage().getChkDatastore());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the CHK cache.
   *
   * <p>The view delegates to {@link NodeStats} for average CHK cache locations and success rates
   * and uses the node's current location to compute {@code avgDist()}. Each call returns a fresh
   * adapter that reflects the latest in-memory values without additional synchronization. The
   * {@code distanceStats()} value is computed from the ratio of report counts to cache key count,
   * then capped at {@code 1.0} to keep the metric within a meaningful range for displays.
   *
   * @return a live view of CHK cache location and success metrics.
   */
  public StoreLocationStats chkCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgCacheCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgCacheCHKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestCacheCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgCacheCHKLocation, stats.node.storage().getChkDatacache());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the CHK slashdot cache.
   *
   * <p>This view reports the decaying average location and success probability for CHK operations
   * attributed to the slashdot cache, plus distance summaries relative to the node's current
   * location. The adapter is constructed on demand and simply reads {@link NodeStats} fields when
   * its methods are invoked; it performs no additional smoothing or caching. The distance-stat
   * ratio is computed from reported samples and the cache key count, then capped at {@code 1.0} to
   * prevent over-reporting.
   *
   * @return a live view of CHK slashdot-cache location and success metrics.
   */
  public StoreLocationStats chkSlashDotCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgSlashdotCacheCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgSlashdotCacheCHKSucess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestSlashdotCacheCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(
            stats.avgSlashdotCacheCHKLocation, stats.node.storage().getChkSlashdotCache());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the CHK client cache.
   *
   * <p>The returned view exposes current averages for client-cache CHK operations from {@link
   * NodeStats} and computes distances using the node's live location. It is a new adapter instance
   * for each call, with all values read directly from {@code NodeStats} and the client cache's
   * {@link StoreCallback}. The distance-stat ratio is the report count divided by key count and is
   * capped at {@code 1.0} so UI consumers receive a bounded percentage-like metric.
   *
   * @return a live view of CHK client-cache location and success metrics.
   */
  public StoreLocationStats chkClientCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgClientCacheCHKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgClientCacheCHKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestClientCacheCHKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(
            stats.avgClientCacheCHKLocation, stats.node.storage().getChkClientCache());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the SSK datastore.
   *
   * <p>This adapter exposes decaying averages for SSK datastore locations and success rates, plus
   * distance summaries computed against the node's current location. The view is created anew for
   * each call and reads the underlying {@link NodeStats} fields on demand, so updates in the
   * running node are visible between invocations. The distance-stat ratio is derived from report
   * counts and the datastore key count and is capped at {@code 1.0} for bounded reporting.
   *
   * @return a live view of SSK datastore location and success metrics.
   */
  public StoreLocationStats sskStoreStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgStoreSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgStoreSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestStoreSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgStoreSSKLocation, stats.node.storage().getSskDatastore());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the SSK cache.
   *
   * <p>The returned view reports the current decaying averages for SSK cache location and success,
   * along with distance summaries relative to the node's live location. It is a lightweight adapter
   * with no internal state beyond the captured {@link NodeStats} reference. The distance statistic
   * is the ratio of report count to cache key count, capped at {@code 1.0} to keep the metric
   * within a display-friendly range.
   *
   * @return a live view of SSK cache location and success metrics.
   */
  public StoreLocationStats sskCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgCacheSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgCacheSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestCacheSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgCacheSSKLocation, stats.node.storage().getSskDatacache());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the SSK slashdot cache.
   *
   * <p>This view exposes decaying averages for SSK slashdot-cache locations and success rates and
   * computes distance summaries from the node's current location. Each invocation constructs a
   * fresh adapter that delegates directly to {@link NodeStats} and the slashdot cache's {@link
   * StoreCallback}. The distance-stat ratio uses report count and key count and is capped at {@code
   * 1.0} for consistency with other store views.
   *
   * @return a live view of SSK slashdot-cache location and success metrics.
   */
  public StoreLocationStats sskSlashDotCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgSlashdotCacheSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgSlashdotCacheSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestSlashdotCacheSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(
            stats.avgSlashdotCacheSSKLocation, stats.node.storage().getSskSlashdotCache());
      }
    };
  }

  /**
   * Returns a {@link StoreLocationStats} view for the SSK client cache.
   *
   * <p>The view is created on demand and surfaces the latest decaying averages for client-cache SSK
   * operations, along with distance summaries computed against the node's current location. It does
   * not cache values or synchronize access; each method reads from {@link NodeStats} and the client
   * cache's {@link StoreCallback} when invoked. The distance-stat ratio is bounded at {@code 1.0}
   * to provide a stable, percentage-like indicator.
   *
   * @return a live view of SSK client-cache location and success metrics.
   */
  public StoreLocationStats sskClientCacheStats() {
    return new StoreLocationStats() {
      @Override
      public double avgLocation() {
        return stats.avgClientCacheSSKLocation.currentValue();
      }

      @Override
      public double avgSuccess() {
        return stats.avgClientCacheSSKSuccess.currentValue();
      }

      @Override
      public double furthestSuccess() {
        return stats.furthestClientCacheSSKSuccess;
      }

      @Override
      public double avgDist() {
        return Location.distance(
            stats.node.network().locationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(
            stats.avgClientCacheSSKLocation, stats.node.storage().getSskClientCache());
      }
    };
  }

  private double cappedDistance(DecayingKeyspaceAverage avgLocation, StoreCallback<?> store) {
    double cachePercent = 1.0 * avgLocation.countReports() / store.keyCount();
    // Cap the reported value at 100%, as the decaying average does not account beyond that anyway.
    if (cachePercent > 1.0) {
      cachePercent = 1.0;
    }
    return cachePercent;
  }
}
