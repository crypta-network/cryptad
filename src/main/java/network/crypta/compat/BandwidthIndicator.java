package network.crypta.compat;

/** Supplies upstream/downstream bit-rate estimates for setup heuristics. */
public interface BandwidthIndicator {
  int getDownstreamMaxBitRate();

  int getUpstreamMaxBitRate();
}
