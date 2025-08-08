package network.crypta.node.stats;

/**
 * This interface represents the data we can publish on our stats page for a given instance of a data store.
 *
 * @author nikotyan
 */
public interface DataStoreStats {
	long keys();

	long capacity();

	long dataSize();

	double utilization();

	double avgLocation() throws StatsNotAvailableException;

	double avgSuccess() throws StatsNotAvailableException;

	double furthestSuccess() throws StatsNotAvailableException;

	double avgDist() throws StatsNotAvailableException;

	double distanceStats() throws StatsNotAvailableException;
	
	StoreAccessStats getSessionAccessStats();
	
	StoreAccessStats getTotalAccessStats() throws StatsNotAvailableException;

}
