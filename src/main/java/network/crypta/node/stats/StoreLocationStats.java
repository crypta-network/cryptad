package network.crypta.node.stats;

/**
 * This interface represents aggregated stats for data store
 *
 * @author nikotyan
 */
public interface StoreLocationStats {

  double avgLocation() throws StatsNotAvailableException;

  double avgSuccess() throws StatsNotAvailableException;

  double furthestSuccess() throws StatsNotAvailableException;

  double avgDist() throws StatsNotAvailableException;

  double distanceStats() throws StatsNotAvailableException;
}
