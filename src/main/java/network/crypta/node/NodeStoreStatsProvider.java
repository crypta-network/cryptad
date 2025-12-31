package network.crypta.node;

import network.crypta.node.stats.StoreLocationStats;
import network.crypta.store.StoreCallback;
import network.crypta.support.math.DecayingKeyspaceAverage;

/**
 * Builds store-location views for reporting cache/store hit locations and success rates.
 *
 * <p>Extracted from {@link NodeStats} to keep store-related reporting separate from core load
 * admission logic.
 */
public final class NodeStoreStatsProvider {
  private final NodeStats stats;

  public NodeStoreStatsProvider(NodeStats stats) {
    this.stats = stats;
  }

  /**
   * View of stats for CHK Store
   *
   * @return stats for CHK Store
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgStoreCHKLocation, stats.node.getChkDatastore());
      }
    };
  }

  /**
   * View of stats for CHK Cache
   *
   * @return CHK cache stats
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgCacheCHKLocation, stats.node.getChkDatacache());
      }
    };
  }

  /**
   * View of stats for CHK SlashdotCache
   *
   * @return CHK Slashdotcache stats
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgSlashdotCacheCHKLocation, stats.node.getChkSlashdotCache());
      }
    };
  }

  /**
   * View of stats for CHK ClientCache
   *
   * @return CHK ClientCache stats
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgClientCacheCHKLocation, stats.node.getChkClientCache());
      }
    };
  }

  /**
   * View of stats for SSK Store
   *
   * @return stats for SSK Store
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgStoreSSKLocation, stats.node.getSskDatastore());
      }
    };
  }

  /**
   * View of stats for SSK Cache
   *
   * @return SSK cache stats
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgCacheSSKLocation, stats.node.getSskDatacache());
      }
    };
  }

  /**
   * View of stats for SSK SlashdotCache
   *
   * @return SSK Slashdotcache stats
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgSlashdotCacheSSKLocation, stats.node.getSskSlashdotCache());
      }
    };
  }

  /**
   * View of stats for SSK ClientCache
   *
   * @return SSK ClientCache stats
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
        return Location.distance(stats.node.getLocationManager().getLocation(), avgLocation());
      }

      @Override
      public double distanceStats() {
        return cappedDistance(stats.avgClientCacheSSKLocation, stats.node.getSskClientCache());
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
