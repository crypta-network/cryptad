package network.crypta.node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Allow underscore test names per project rules
class PeerLocationTest {
  private static final double EPSILON = 1e-15;

  private static final double[][] PEER_LOCATIONS =
      new double[][] {
        // Must be sorted!
        {0.1},
        {0.0},
        {0.9},
        {0.1, 0.3},
        {0.1, 0.3, 0.4},
        {0.0, 0.1, 0.2, 0.3, 0.3, 0.35, 0.5, 0.5, 0.99},
        {0.1, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.20, 0.21, 0.22, 0.23, 0.24},
        {0.0000001, 0.0000003, 0.0001, 0.0002, 0.4, 0.5, 0.999, 0.999999, 0.9999995},
        {0, 0.1, 0.11, 0.9, 0.99, 1}
      };

  private static final double[] TARGET_LOCATIONS =
      new double[] {
        0.0, 1e-12, 0.01, 0.05, 0.09, 0.1, 0.11, 0.29, 0.3, 0.31, 0.35, 0.4, 0.45, 0.5, 0.51, 0.9,
        0.91, 0.9999, 1 - 1e-12
      };

  @Test
  void findClosestLocation_variousInputs_matchesReference() {
    for (double[] peers : PEER_LOCATIONS) {
      for (double target : TARGET_LOCATIONS) {
        int closest = PeerLocation.findClosestLocation(peers, target);
        double ref = trivialFindClosestDistance(peers, target);
        assertEquals(ref, Location.distance(peers[closest], target), EPSILON);
      }
    }
  }

  @Test
  void getClosestPeerLocation_withExclusions_matchesReference() {
    for (double[] peers : PEER_LOCATIONS) {
      PeerLocation pl = new PeerLocation("0.0");
      assertTrue(pl.updateLocation(0.0, peers));
      for (double target : TARGET_LOCATIONS) {
        for (Set<Double> exclude : omit(peers)) {
          double closest = pl.getClosestPeerLocation(target, exclude);
          assertFalse(exclude.contains(closest));
          double ref = trivialFindClosestDistance(peers, target, exclude);
          if (!Double.isInfinite(ref)) {
            assertFalse(Double.isNaN(closest));
            boolean isPeer = false;
            for (double peer : peers) {
              if (closest == peer) {
                isPeer = true;
                break;
              }
            }
            assertTrue(isPeer);
            assertEquals(ref, Location.distance(closest, target), EPSILON);
          } else {
            assertTrue(Double.isNaN(closest));
          }
        }
      }
    }
  }

  @Test
  void constructor_andAccessors_whenValid_expectInitialized() {
    long before = System.currentTimeMillis();
    PeerLocation pl = new PeerLocation("0.3");
    long after = System.currentTimeMillis();

    assertEquals(0.3, pl.getLocation(), EPSILON);
    assertTrue(pl.isValidLocation());
    assertEquals("0.3", pl.toString());
    assertTrue(pl.getLocationSetTime() >= before && pl.getLocationSetTime() <= after);
    assertEquals(0, pl.getDegree());
    assertNull(pl.getPeersLocationArray());
  }

  @Test
  void constructor_whenInvalidLocationString_expectInvalidLocation() {
    PeerLocation pl = new PeerLocation("not-a-number");
    assertFalse(pl.isValidLocation());
    assertEquals(Location.LOCATION_INVALID, pl.getLocation());
    assertEquals("-1.0", pl.toString());
  }

  @Test
  void setPeerLocations_whenNull_noChange() {
    PeerLocation pl = new PeerLocation("0.2");
    long t0 = pl.getLocationSetTime();

    pl.setPeerLocations(null);

    assertEquals(0.2, pl.getLocation(), EPSILON);
    assertEquals(0, pl.getDegree());
    assertNull(pl.getPeersLocationArray());
    assertEquals(t0, pl.getLocationSetTime());
  }

  @Test
  void setPeerLocations_parsesSorts_andReturnsDefensiveCopy() {
    PeerLocation pl = new PeerLocation("0.2");
    long t0 = pl.getLocationSetTime();
    String[] peers = new String[] {"0.9", "0.1", "0.5"};

    pl.setPeerLocations(peers);

    double[] got1 = pl.getPeersLocationArray();
    assertArrayEquals(new double[] {0.1, 0.5, 0.9}, got1, EPSILON);
    assertEquals(3, pl.getDegree());
    assertEquals(0.2, pl.getLocation(), EPSILON);
    assertTrue(pl.getLocationSetTime() >= t0);

    // Defensive copy: modifying the returned array must not affect internal state
    double[] snapshot = pl.getPeersLocationArray();
    double first = snapshot[0];
    snapshot[0] = first + 0.123;
    double[] snapshot2 = pl.getPeersLocationArray();
    assertEquals(first, snapshot2[0], EPSILON);
  }

  @Test
  void updateLocation_whenInvalidNewLoc_returnsFalse_andNoChange() {
    PeerLocation pl = new PeerLocation("0.2");
    pl.setPeerLocations(new String[] {"0.3", "0.7"});
    double[] beforePeers = pl.getPeersLocationArray();
    long t0 = pl.getLocationSetTime();

    boolean changed = pl.updateLocation(-0.5, new double[] {0.1});

    assertFalse(changed);
    assertEquals(0.2, pl.getLocation(), EPSILON);
    assertArrayEquals(beforePeers, pl.getPeersLocationArray(), EPSILON);
    assertEquals(t0, pl.getLocationSetTime());
  }

  @Test
  void updateLocation_whenInvalidPeerValue_returnsFalse_andNoChange() {
    PeerLocation pl = new PeerLocation("0.2");
    pl.setPeerLocations(new String[] {"0.3", "0.7"});
    double[] beforePeers = pl.getPeersLocationArray();
    long t0 = pl.getLocationSetTime();

    boolean changed = pl.updateLocation(0.2, new double[] {0.1, -0.1});

    assertFalse(changed);
    assertEquals(0.2, pl.getLocation(), EPSILON);
    assertArrayEquals(beforePeers, pl.getPeersLocationArray(), EPSILON);
    assertEquals(t0, pl.getLocationSetTime());
  }

  @Test
  void updateLocation_whenSameData_returnsFalse_butUpdatesTime() {
    PeerLocation pl = new PeerLocation("0.2");
    boolean first = pl.updateLocation(0.2, new double[] {0.5, 0.1, 0.9});
    assertTrue(first); // initial peers were null
    long t1 = pl.getLocationSetTime();

    boolean second = pl.updateLocation(0.2, new double[] {0.1, 0.5, 0.9});
    assertFalse(second);
    assertTrue(pl.getLocationSetTime() >= t1);
    assertArrayEquals(new double[] {0.1, 0.5, 0.9}, pl.getPeersLocationArray(), EPSILON);
  }

  @Test
  void setLocation_whenDifferent_updatesAndReturnsOld_andUpdatesTime() {
    PeerLocation pl = new PeerLocation("0.2");
    pl.setPeerLocations(new String[] {"0.3"});
    long t0 = pl.getLocationSetTime();

    double old = pl.setLocation(0.4);

    assertEquals(0.2, old, EPSILON);
    assertEquals(0.4, pl.getLocation(), EPSILON);
    assertTrue(pl.getLocationSetTime() >= t0);
  }

  @Test
  void setLocation_whenSame_returnsOld_andDoesNotUpdateTime() {
    PeerLocation pl = new PeerLocation("0.2");
    long t0 = pl.getLocationSetTime();

    double old = pl.setLocation(0.2);

    assertEquals(0.2, old, EPSILON);
    assertEquals(0.2, pl.getLocation(), EPSILON);
    assertEquals(t0, pl.getLocationSetTime());
  }

  @Test
  void getClosestPeerLocation_whenNoPeers_returnsNaN() {
    PeerLocation pl = new PeerLocation("0.0");
    double res = pl.getClosestPeerLocation(0.5, new HashSet<>());
    assertTrue(Double.isNaN(res));
  }

  @Test
  void getClosestPeerLocation_whenAllExcluded_returnsNaN() {
    PeerLocation pl = new PeerLocation("0.0");
    double[] peers = {0.1, 0.4, 0.6};
    assertTrue(pl.updateLocation(0.0, peers));
    Set<Double> exclude = new HashSet<>(Arrays.asList(0.1, 0.4, 0.6));
    double res = pl.getClosestPeerLocation(0.5, exclude);
    assertTrue(Double.isNaN(res));
  }

  @Test
  void findClosestLocation_whenTie_prefersLeftNeighbor() {
    double[] peers = {0.25, 0.75};

    int atZero = PeerLocation.findClosestLocation(peers, 0.0);
    assertEquals(1, atZero); // left of 0.0 is 0.75 on the ring

    int atHalf = PeerLocation.findClosestLocation(peers, 0.5);
    assertEquals(0, atHalf); // left neighbor when equidistant
  }

  // Generate sets of sequential omitted values of half the length, plus the empty set
  private java.util.List<Set<Double>> omit(double[] locs) {
    java.util.List<Set<Double>> result = new java.util.ArrayList<>(locs.length + 1);
    int n = locs.length / 2 + 1;
    for (int i = 0; i < locs.length; i++) {
      Set<Double> s = new HashSet<>();
      for (int j = 0; j < n; j++) {
        s.add(locs[(i + j) % locs.length]);
      }
      result.add(s);
      assertFalse(s.isEmpty());
    }
    result.add(new HashSet<>()); // Include the empty set
    return result;
  }

  // Trivial reference implementation that finds the distance to the closest location
  private double trivialFindClosestDistance(double[] locs, double l) {
    double minDist = Double.POSITIVE_INFINITY;
    for (double loc : locs) {
      final double d = Location.distance(loc, l);
      if (d < minDist) {
        minDist = d;
      }
    }
    return minDist;
  }

  // Trivial reference implementation that finds the distance to the closest location, with some
  // locations excluded from consideration
  private double trivialFindClosestDistance(double[] locs, double l, Set<Double> exclude) {
    double minDist = Double.POSITIVE_INFINITY;
    for (double loc : locs) {
      if (exclude.contains(loc)) {
        continue;
      }
      final double d = Location.distance(loc, l);
      if (d < minDist) {
        minDist = d;
      }
    }
    return minDist;
  }
}
