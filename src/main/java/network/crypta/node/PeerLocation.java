package network.crypta.node;

import java.util.Arrays;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds a peer's ring location and sampled locations of its neighbors (FOAF).
 *
 * <p>The ring location is a double in {@code [0.0, 1.0)}; an invalid or unknown location is
 * represented by {@link Location#LOCATION_INVALID} ({@code -1.0}). FOAF locations are stored as a
 * sorted array of doubles. When FOAF data has not yet been received, methods that expose FOAF
 * locations return {@code null} to distinguish "unknown" from a known-empty list.
 *
 * <p>Thread-safety: methods that access internal state are synchronized where needed. Callers do
 * not need external synchronization.
 */
public class PeerLocation {
  private static final Logger LOG = LoggerFactory.getLogger(PeerLocation.class);

  /** Current location on the routing ring; {@code -1.0} indicates unknown. */
  private double currentLocation;

  /**
   * Sorted locations of our peer's neighbors (FOAF).
   *
   * <p>Invariant: never mutate in place; only replace with a new, sorted array.
   */
  private double[] currentPeersLocation;

  /** Timestamp (ms since epoch) when {@link #currentLocation} was last set. */
  private long locSetTime;

  /**
   * Create a {@code PeerLocation} from a string representation.
   *
   * <p>Parses the string via {@link Location#getLocation(String)}; invalid input yields {@code
   * -1.0}. The location set time is initialized to {@link System#currentTimeMillis()}.
   *
   * @param locationString textual form of the ring location
   */
  PeerLocation(String locationString) {
    currentLocation = Location.getLocation(locationString);
    locSetTime = System.currentTimeMillis();
  }

  /**
   * Returns the string form of the current ring location.
   *
   * @return decimal string of the current location; {@code "-1.0"} when unknown
   */
  public synchronized String toString() {
    return Double.toString(currentLocation);
  }

  /**
   * Parse and set FOAF locations from string values.
   *
   * <p>When {@code peerLocationsString} is {@code null}, this method performs no action. Otherwise,
   * it parses values with {@link Location#getLocation(String)}, sorts them, and updates the stored
   * FOAF locations via {@link #updateLocation(double, double[])} while preserving the current
   * {@link #getLocation()} value.
   *
   * @param peerLocationsString array of textual FOAF locations; may be {@code null}
   */
  public void setPeerLocations(String[] peerLocationsString) {
    if (peerLocationsString != null) {
      double[] peerLocations = new double[peerLocationsString.length];
      for (int i = 0; i < peerLocationsString.length; i++)
        peerLocations[i] = Location.getLocation(peerLocationsString[i]);
      updateLocation(currentLocation, peerLocations);
    }
  }

  /**
   * Returns the peer's ring location.
   *
   * @return a double in {@code [0.0, 1.0)} or {@code -1.0} when unknown
   */
  public synchronized double getLocation() {
    return currentLocation;
  }

  /**
   * Returns a defensive copy of FOAF locations.
   *
   * <p>When no peer locations are available yet (unknown), returns {@code null} to allow callers to
   * distinguish between "unknown" and a known-empty list.
   *
   * <p>Thread-safety: synchronized. Complexity is O(n) for the copy.
   *
   * @return sorted array copy of FOAF locations, an empty array when known-empty, or {@code null}
   *     when unknown
   */
  @SuppressWarnings("java:S1168")
  public synchronized double[] getPeersLocationArray() {
    if (currentPeersLocation == null) return null;
    return Arrays.copyOf(currentPeersLocation, currentPeersLocation.length);
  }

  /**
   * Returns the time when the ring location was last set.
   *
   * @return timestamp in milliseconds since the epoch
   */
  public synchronized long getLocationSetTime() {
    return locSetTime;
  }

  /**
   * Indicates whether the current ring location is valid.
   *
   * @return {@code true} when in {@code [0.0, 1.0)}, otherwise {@code false}
   */
  public synchronized boolean isValidLocation() {
    return Location.isValid(currentLocation);
  }

  /**
   * Returns the number of known FOAF locations.
   *
   * @return non‑negative count; {@code 0} when FOAF is unknown or empty
   */
  public synchronized int getDegree() {
    if (currentPeersLocation == null) return 0;
    return currentPeersLocation.length;
  }

  boolean updateLocation(double newLoc, double[] newLocs) {
    if (!Location.isValid(newLoc)) {
      LOG.error("Reject location update for {} (value={})", this, newLoc);
      // Ignore invalid ring location values
      return false;
    }

    final double[] newPeersLocation = new double[newLocs.length];
    for (int i = 0; i < newLocs.length; i++) {
      final double loc = newLocs[i];
      if (!Location.isValid(loc)) {
        LOG.error("Reject location update for {} (value={})", this, loc);
        // Ignore invalid FOAF location values
        return false;
      }
      newPeersLocation[i] = loc;
    }

    Arrays.sort(newPeersLocation);
    boolean anythingChanged = false;

    synchronized (this) {
      if (!Location.equals(currentLocation, newLoc) || currentPeersLocation == null) {
        anythingChanged = true;
      }
      if (!anythingChanged) {
        anythingChanged = currentPeersLocation.length != newPeersLocation.length;
      }
      if (!anythingChanged) {
        for (int i = 0; i < currentPeersLocation.length; i++) {
          if (!Location.equals(currentPeersLocation[i], newPeersLocation[i])) {
            anythingChanged = true;
            break;
          }
        }
      }
      currentLocation = newLoc;
      currentPeersLocation = newPeersLocation;
      locSetTime = System.currentTimeMillis();
    }
    return anythingChanged;
  }

  synchronized double setLocation(double newLoc) {
    double oldLoc = currentLocation;
    if (!Location.equals(newLoc, currentLocation)) {
      currentLocation = newLoc;
      locSetTime = System.currentTimeMillis();
    }
    return oldLoc;
  }

  /**
   * Returns the index of the first element in {@code elems} greater than {@code x}, or {@code -1}
   * when no such element exists.
   *
   * <p>Assumes {@code elems} is sorted ascending. Complexity is O(log n).
   */
  private static int findFirstGreater(final double[] elems, final double x) {
    int low = 0;
    int high = elems.length;
    int mid;
    if (elems[high - 1] <= x) {
      return -1;
    }
    while (low != high) {
      mid = low + (high - low) / 2;
      if (elems[mid] > x) {
        high = mid;
      } else {
        low = mid + 1;
      }
    }
    return low;
  }

  /**
   * Finds the index of the closest location to {@code l} in a sorted list.
   *
   * <p>Assumes {@code locs} is sorted ascending and non‑empty. Breaks ties by selecting the left
   * neighbor. Complexity is O(log n).
   */
  static int findClosestLocation(final double[] locs, final double l) {
    assert (locs.length > 0);
    if (locs.length == 1) {
      return 0;
    }
    final int firstGreater = findFirstGreater(locs, l);
    final int left;
    final int right;
    if (firstGreater == -1 || firstGreater == 0) {
      // Either all locations are greater than l, or all are smaller.
      // The closest must be at one of the ring boundaries.
      left = locs.length - 1;
      right = 0;
    } else {
      left = firstGreater - 1;
      right = firstGreater;
    }
    if (Location.distance(l, locs[left]) <= Location.distance(l, locs[right])) {
      return left;
    }
    return right;
  }

  /**
   * Returns the closest non‑excluded FOAF location to {@code l}.
   *
   * <p>Complexity is O(log n + m), where {@code n} is the number of FOAF locations and {@code m}
   * the number of exclusions.
   *
   * @param l target ring location
   * @param exclude set of FOAF locations to exclude; may be {@code null}
   * @return closest non‑excluded FOAF location, or {@link Double#NaN} when none exists
   */
  public double getClosestPeerLocation(final double l, Set<Double> exclude) {
    final double[] locs;
    synchronized (this) {
      locs = currentPeersLocation;
    }
    if (locs == null || locs.length == 0) {
      return Double.NaN;
    }
    final int closest = findClosestLocation(locs, l);
    if (exclude == null) {
      return locs[closest];
    }
    if (!exclude.contains(locs[closest])) {
      return locs[closest];
    }
    return findClosestNonExcluded(locs, l, exclude, closest);
  }

  /**
   * Scans outward from the closest element to find the nearest non‑excluded location.
   *
   * <p>Preserves tie‑breaking by preferring the left neighbor on equal distances.
   */
  private static double findClosestNonExcluded(
      final double[] locs, final double l, final Set<Double> exclude, final int closest) {
    int left = prevIndex(closest, locs.length);
    int right = nextIndex(closest, locs.length);
    double leftDist = Location.distance(l, locs[left]);
    double rightDist = Location.distance(l, locs[right]);
    while (left != right) {
      if (leftDist <= rightDist) {
        final double loc = locs[left];
        if (!exclude.contains(loc)) {
          return loc;
        }
        left = prevIndex(left, locs.length);
        leftDist = Location.distance(l, locs[left]);
      } else {
        final double loc = locs[right];
        if (!exclude.contains(loc)) {
          return loc;
        }
        right = nextIndex(right, locs.length);
        rightDist = Location.distance(l, locs[right]);
      }
    }
    final double loc = locs[left];
    if (!exclude.contains(loc)) {
      return loc;
    }
    return Double.NaN;
  }

  // Circular predecessor index on a ring of length {@code length}.
  private static int prevIndex(int index, int length) {
    return (index == 0) ? (length - 1) : (index - 1);
  }

  // Circular successor index on a ring of length {@code length}.
  private static int nextIndex(int index, int length) {
    return (index == length - 1) ? 0 : (index + 1);
  }
}
