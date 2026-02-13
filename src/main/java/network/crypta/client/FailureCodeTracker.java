package network.crypta.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks failure codes and their occurrence counts for client insert or fetch operations.
 *
 * <p>This utility aggregates integer error codes and supports two mutually exclusive modes:
 * <em>insert</em> and <em>fetch</em>. In insert mode it expects codes from {@link
 * InsertException.InsertExceptionMode}; in fetch mode it expects codes from {@link
 * FetchException.FetchExceptionMode}. Callers increment counts as failures occur, merge trackers
 * produced by sub-operations, and render the result either as a compact {@link #toString()} or a
 * line-oriented verbose report via {@link #toVerboseString()}.
 *
 * <p>Lifecycle and invariants:
 *
 * <ul>
 *   <li>The mode is fixed at construction time and never changes.
 *   <li>Counts are non-negative and increase monotonically through calls to the various {@code
 *       inc(...)} methods or {@link #merge(FailureCodeTracker)}.
 *   <li>Most mutating operations are synchronized to keep internal tallies consistent.
 * </ul>
 *
 * <p>Thread-safety: methods that mutate internal state are synchronized; read methods that depend
 * on a stable snapshot are also synchronized. The tracker is therefore safe for concurrent access
 * from multiple threads provided callers avoid holding locks while performing expensive I/O in
 * callbacks that may re-enter these APIs.
 *
 * <p>Typical usage is to create a tracker per higher-level request, increment codes as failures are
 * observed, and persist or serialize the snapshot (for example, into a {@link
 * network.crypta.support.SimpleFieldSet}) so that progress and diagnostics survive restarts.
 *
 * <p>WARNING: Changing non-transient members on classes that are {@link Serializable} can result in
 * restarting downloads or losing uploads when persisted state is loaded by older/newer versions.
 *
 * @see FetchException
 * @see InsertException
 */
public final class FailureCodeTracker implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(FailureCodeTracker.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Whether this tracker records insert failures instead of fetch failures.
   *
   * <p>When {@code true}, public APIs that accept a failure mode expect values from {@link
   * InsertException.InsertExceptionMode}. When {@code false}, they expect values from {@link
   * FetchException.FetchExceptionMode}. The value is final and defines the tracker’s identity.
   */
  public final boolean insert;

  /** Running total of all recorded failures across every code. */
  private int total;

  /**
   * Create a new empty tracker in the requested mode.
   *
   * <p>The created instance contains no codes and a total count of zero. The mode cannot be changed
   * later; prefer creating distinct instances per operation rather than reusing one with cleared
   * state.
   *
   * @param insert {@code true} to track {@linkplain InsertException.InsertExceptionMode insert}
   *     failures; {@code false} to track {@linkplain FetchException.FetchExceptionMode fetch}
   *     failures
   */
  public FailureCodeTracker(boolean insert) {
    this.insert = insert;
  }

  /**
   * Create a tracker from a {@link SimpleFieldSet} snapshot.
   *
   * <p>Only the numeric counts are read; any accompanying textual descriptions inside the field set
   * are ignored. Negative counts are rejected.
   *
   * @param isInsert whether this tracker operates in insert mode; governs interpretation of codes
   * @param fs the non-verbose field-set representation previously produced by {@link
   *     #toFieldSet(boolean)}; must contain {@code *.Count} entries with non-negative integers
   */
  public FailureCodeTracker(boolean isInsert, SimpleFieldSet fs) {
    this.insert = isInsert;
    map = new HashMap<>();
    Iterator<String> i = fs.directSubsetNameIterator();
    while (i.hasNext()) {
      String name = i.next();
      SimpleFieldSet f = fs.subset(name);
      // We ignore the Description if there is one; we just want the count
      int num = Integer.parseInt(name);
      int count = Integer.parseInt(f.get("Count"));
      if (count < 0) throw new IllegalArgumentException("Count < 0");
      map.put(num, count);
      total += count;
    }
  }

  /**
   * Framework/serialization constructor.
   *
   * <p>Exists solely for deserialization frameworks that require a no‑arg constructor. The tracker
   * is created in fetch mode by default; real instances should be created via the public
   * constructors that explicitly specify the mode.
   */
  protected FailureCodeTracker() {
    // For serialization.
    this.insert = false;
  }

  /** Map of failure code to the number of times that code has been observed. */
  private HashMap<Integer, Integer> map;

  /**
   * Increment the count for a fetch failure mode by one.
   *
   * <p>Valid only when this tracker is in fetch mode. Passing a zero-valued code logs a warning and
   * still updates the internal map entry for {@code 0} if present.
   *
   * @param k the {@link FetchExceptionMode} whose {@link FetchExceptionMode#code} value is counted;
   *     must not be {@code null}
   * @throws IllegalStateException if this tracker is configured for insert mode
   */
  public void inc(FetchExceptionMode k) {
    if (insert) throw new IllegalStateException();
    inc(k.code);
  }

  /**
   * Increment the count for an insert failure mode by one.
   *
   * <p>Valid only when this tracker is in insert mode. Passing a zero-valued code logs a warning
   * and still updates the internal map entry for {@code 0} if present.
   *
   * @param k the {@link InsertExceptionMode} whose {@link InsertExceptionMode#code} value is
   *     counted; must not be {@code null}
   * @throws IllegalStateException if this tracker is configured for fetch mode
   */
  public void inc(InsertExceptionMode k) {
    if (!insert) throw new IllegalStateException();
    inc(k.code);
  }

  /**
   * Increment the count for an arbitrary numeric failure code by one.
   *
   * <p>This method is synchronized to ensure that {@link #total} and the per-code counter are
   * updated atomically. The map is created lazily on the first increment.
   *
   * @param k the integer failure code to increment; a value of {@code 0} is accepted but unusual
   */
  public synchronized void inc(int k) {
    if (k == 0) {
      LOG.warn("FailureCodeTracker.inc(int): zero failure code increment requested");
    }
    if (map == null) map = new HashMap<>();
    Integer key = k;
    map.merge(key, 1, Integer::sum);
    total++;
  }

  /**
   * Increment the count for a fetch failure mode by a specified value.
   *
   * <p>Valid only when this tracker is in fetch mode.
   *
   * @param k the {@link FetchExceptionMode} whose {@link FetchExceptionMode#code} value is counted
   * @param val the amount to add to the existing counter; negative values decrease the counter
   * @throws IllegalStateException if this tracker is configured for insert mode
   */
  public void inc(FetchExceptionMode k, int val) {
    if (insert) throw new IllegalStateException();
    inc(k.code, val);
  }

  /**
   * Increment the count for an insert failure mode by a specified value.
   *
   * <p>Valid only when this tracker is in insert mode.
   *
   * @param k the {@link InsertExceptionMode} whose {@link InsertExceptionMode#code} value is
   *     counted
   * @param val the amount to add to the existing counter; negative values decrease the counter
   * @throws IllegalStateException if this tracker is configured for fetch mode
   */
  public void inc(InsertExceptionMode k, int val) {
    if (!insert) throw new IllegalStateException();
    inc(k.code, val);
  }

  /**
   * Increment the count for an arbitrary numeric failure code by a specified value.
   *
   * <p>This method is synchronized and lazily initializes the backing map. If the code is not yet
   * present, the counter is created; otherwise it is increased by {@code val}.
   *
   * @param k the failure code key; may be any integer (including {@code 0})
   * @param val the delta to apply to the counter for {@code k}; negative values decrease the count
   */
  public synchronized void inc(Integer k, int val) {
    if (k == 0) {
      LOG.warn("FailureCodeTracker.inc(Integer,int): zero failure code delta requested");
    }
    if (map == null) map = new HashMap<>();
    Integer i = map.get(k);
    if (i == null) map.put(k, 1);
    else map.put(k, i + val);
    total += val;
  }

  /**
   * Produce a multi-line, human-friendly dump of the collected codes.
   *
   * <p>Each line contains {@code <count> <TAB> <description>}. Descriptions are derived from the
   * corresponding exception mode table for the current tracker mode.
   *
   * @return a readable report suitable for logs and diagnostics; never {@code null}
   */
  public synchronized String toVerboseString() {
    if (map == null) return super.toString() + ":empty";
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<Integer, Integer> e : map.entrySet()) {
      Integer x = e.getKey();
      Integer val = e.getValue();
      String s = getMessage(x);
      sb.append(val);
      sb.append('\t');
      sb.append(s);
      sb.append('\n');
    }
    return sb.toString();
  }

  /**
   * Resolve a human-readable description for a failure code.
   *
   * @param x the code to resolve; must correspond to a known mode for the current tracker type
   * @return a non-null description string as provided by the respective exception class
   */
  public String getMessage(Integer x) {
    return insert
        ? InsertException.getMessage(InsertExceptionMode.getByCode(x))
        : FetchException.getMessage(FetchExceptionMode.getByCode(x));
  }

  @Override
  public synchronized String toString() {
    if (map == null) return super.toString() + ":empty";
    StringBuilder sb = new StringBuilder(super.toString());
    sb.append(':');
    if (map.isEmpty()) sb.append("empty");
    else if (map.size() == 1) {
      sb.append("one:");
      Integer code = (Integer) map.keySet().toArray()[0];
      sb.append(code);
      sb.append('=');
      sb.append(map.get(code));
    } else if (map.size() < 10) {
      boolean needComma = false;
      for (Map.Entry<Integer, Integer> entry : map.entrySet()) {
        if (needComma) sb.append(',');
        sb.append(entry.getKey()); // code
        sb.append('=');
        sb.append(entry.getValue());
        needComma = true;
      }
    } else {
      sb.append(map.size());
    }
    return sb.toString();
  }

  /**
   * Merge codes from another tracker into this one.
   *
   * <p>Counters for matching codes are added. The {@linkplain #insert mode} of this tracker is not
   * changed. A {@code null} or empty source has no effect.
   *
   * @param source the tracker whose per‑code counters should be added to this tracker; may be
   *     {@code null}
   * @return this tracker for call chaining
   */
  public FailureCodeTracker merge(FailureCodeTracker source) {
    if (source == null) return this;
    Map<Integer, Integer> sourceMapSnapshot = source.snapshotMap();
    if (sourceMapSnapshot.isEmpty()) return this;
    synchronized (this) {
      for (Map.Entry<Integer, Integer> e : sourceMapSnapshot.entrySet()) {
        Integer k = e.getKey();
        Integer item = e.getValue();
        inc(k, item);
      }
      return this;
    }
  }

  private synchronized Map<Integer, Integer> snapshotMap() {
    if (map == null) return Map.of();
    return new HashMap<>(map);
  }

  /**
   * Merge codes from a {@link FetchException} instance.
   *
   * <p>When present, the exception’s embedded tracker is merged first so that all detailed counts
   * are retained. Regardless, the top-level mode code is also incremented to ensure higher-level
   * classification remains visible in the aggregate.
   *
   * @param e the fetch exception to fold into this tracker; must not be {@code null}
   * @throws IllegalStateException if this tracker is configured for insert mode
   */
  public void merge(FetchException e) {
    if (insert) throw new IllegalStateException("Merging a FetchException in an insert!");
    if (e.errorCodes != null) {
      merge(e.errorCodes);
    }
    // Increment mode anyway, so we get the splitfile error as well.
    inc(e.mode.code);
  }

  /**
   * Return the total number of failures recorded across all codes.
   *
   * @return the sum of counts for all keys; zero when the tracker is empty
   */
  public synchronized int totalCount() {
    return total;
  }

  /**
   * Create a {@link SimpleFieldSet} representation of this tracker.
   *
   * <p>When {@code verbose} is {@code true}, the field set includes per-code descriptions under
   * {@code <code>.Description}. Counts are always included under {@code <code>.Count}. Keys are the
   * raw integer codes from the current mode.
   *
   * @param verbose whether to include human-readable descriptions alongside counts
   * @return a non-{@code null} field set suitable for storage or transport
   */
  public synchronized SimpleFieldSet toFieldSet(boolean verbose) {
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    if (map != null) {
      for (Map.Entry<Integer, Integer> e : map.entrySet()) {
        Integer k = e.getKey();
        Integer item = e.getValue();
        int code = k;
        // prefix.num.Description=<code description>
        // prefix.num.Count=<count>
        if (verbose) sfs.putSingle(code + ".Description", getMessage(code));
        sfs.put(code + ".Count", item);
      }
    }
    return sfs;
  }

  /**
   * Determine whether exactly one distinct failure code has been recorded.
   *
   * @return {@code true} when the tracker is empty or contains a single key; otherwise {@code
   *     false}
   */
  public synchronized boolean isOneCodeOnly() {
    if (map == null) return true;
    return map.size() == 1;
  }

  /**
   * Get the first recorded code interpreted as a {@link FetchExceptionMode}.
   *
   * <p>Intended for callers that only need a representative failure when a single code is present.
   *
   * @return the first code as a fetch mode value
   * @throws IllegalStateException if this tracker is configured for insert mode
   */
  public FetchExceptionMode getFirstCodeFetch() {
    if (insert) throw new IllegalStateException();
    return FetchExceptionMode.getByCode(getFirstCode());
  }

  /**
   * Get the first recorded code interpreted as an {@link InsertExceptionMode}.
   *
   * @return the first code as an insert mode value
   * @throws IllegalStateException if this tracker is configured for fetch mode
   */
  public InsertExceptionMode getFirstCodeInsert() {
    if (!insert) throw new IllegalStateException();
    return InsertExceptionMode.getByCode(getFirstCode());
  }

  /**
   * Return an arbitrary recorded failure code.
   *
   * <p>When multiple codes are present, the choice is unspecified and should be treated only as a
   * representative sample. Callers that rely on the presence of a single code should validate that
   * condition first via {@link #isOneCodeOnly()}.
   *
   * @return one of the keys contained in the internal map
   * @throws ArrayIndexOutOfBoundsException if the tracker is empty
   */
  public synchronized int getFirstCode() {
    return (Integer) map.keySet().toArray()[0];
  }

  /**
   * Determine whether the collected codes contain any fatal error.
   *
   * <p>Fatality is delegated to {@link InsertException#isFatal(InsertExceptionMode)} or {@link
   * FetchException#isFatal(FetchExceptionMode)} based on the supplied flag; only codes with a
   * strictly positive count are considered.
   *
   * @param isInsert {@code true} to evaluate codes as insert modes; {@code false} to evaluate as
   *     fetch modes
   * @return {@code true} when any fatal code with count &gt; 0 is present; otherwise {@code false}
   */
  public synchronized boolean isFatal(boolean isInsert) {
    if (map == null) return false;
    for (Map.Entry<Integer, Integer> e : map.entrySet()) {
      Integer code = e.getKey();
      if (e.getValue() == 0) continue;
      if (isInsert) {
        if (InsertException.isFatal(InsertExceptionMode.getByCode(code))) return true;
      } else {
        if (FetchException.isFatal(FetchExceptionMode.getByCode(code))) return true;
      }
    }
    return false;
  }

  /**
   * Merge codes from an {@link InsertException} instance.
   *
   * <p>When present, the exception’s embedded tracker is merged first so that all detailed counts
   * are retained; the top-level mode is then incremented.
   *
   * @param e the insert exception to fold into this tracker; must not be {@code null}
   * @throws IllegalArgumentException if this tracker is configured for fetch mode
   */
  public void merge(InsertException e) {
    if (!insert)
      throw new IllegalArgumentException("This is not an insert yet merge(" + e + ") called!");
    if (e.getErrorCodes() != null) merge(e.getErrorCodes());
    inc(e.getMode());
  }

  /**
   * Whether the tracker currently contains no recorded codes or all counts are zero.
   *
   * @return {@code true} when the internal map is {@code null} or empty; otherwise {@code false}
   */
  public synchronized boolean isEmpty() {
    return map == null || map.isEmpty();
  }

  /**
   * Create a defensive copy of the supplied tracker.
   *
   * <p>The returned instance preserves the {@code insert} mode and all accumulated counts at the
   * time of copying. Passing {@code null} returns {@code null} to ease optional flows.
   *
   * @param source the tracker to copy; may be {@code null}
   * @return a new tracker with equivalent state, or {@code null} when {@code source} is {@code
   *     null}
   */
  public static FailureCodeTracker copyOf(FailureCodeTracker source) {
    if (source == null) return null;
    FailureCodeTracker tracker = new FailureCodeTracker(source.insert);
    tracker.merge(source);
    return tracker;
  }

  /**
   * Check whether any recorded code corresponds to the "data found" condition for a fetch.
   *
   * <p>Valid only in insert mode; consults {@link
   * FetchException#isDataFound(FetchException.FetchExceptionMode, FailureCodeTracker)} for each
   * positive‑count code and returns as soon as a matching mode is encountered.
   *
   * @return {@code true} if any positive-count code maps to "data found"; otherwise {@code false}
   * @throws IllegalStateException if this tracker is configured for fetch mode
   */
  public synchronized boolean isDataFound() {
    if (!insert) throw new IllegalStateException();
    for (Map.Entry<Integer, Integer> entry : map.entrySet()) {
      if (entry.getValue() <= 0) continue;
      if (FetchException.isDataFound(FetchExceptionMode.getByCode(entry.getKey()), null))
        return true;
    }
    return false;
  }

  private static final int MAGIC = 0xb605aa08;
  private static final int VERSION = 1;

  private static int upperLimitErrorCode(boolean insert) {
    return insert ? insertUpperLimitErrorCode() : fetchUpperLimitErrorCode();
  }

  private static int insertUpperLimitErrorCode() {
    return InsertException.UPPER_LIMIT_ERROR_CODE;
  }

  private static int fetchUpperLimitErrorCode() {
    return FetchException.UPPER_LIMIT_ERROR_CODE;
  }

  /**
   * Compute the byte length of the fixed-size representation produced by {@link
   * #writeFixedLengthTo(DataOutputStream)}.
   *
   * <p>The size depends on the mode, as the upper bound for error codes differs between insert and
   * fetch. The returned value includes the header and all counters up to the mode-specific upper
   * limit.
   *
   * @param insert {@code true} for insert mode sizing; {@code false} for fetch mode
   * @return the number of bytes required to serialize a tracker at that mode’s upper limit
   */
  public static int getFixedLength(boolean insert) {
    int upperLimit = upperLimitErrorCode(insert);
    return 4 + 4 + 4 + 4 * upperLimit;
  }

  /**
   * Write a fixed-size representation to a {@link DataOutputStream}.
   *
   * <p>The binary format starts with a magic value and version, followed by the mode’s upper limit
   * and then a dense array of four-byte counters from {@code 0} to {@code upperLimit-1}. This form
   * is designed for layouts that must reserve a fixed region on the disk such as splitfiles.
   *
   * @param dos the destination stream; the method writes exactly {@link #getFixedLength(boolean)}
   *     bytes for the current mode
   * @throws IOException if writing to {@code dos} fails
   */
  public synchronized void writeFixedLengthTo(DataOutputStream dos) throws IOException {
    int upperLimit = upperLimitErrorCode(insert);
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeInt(upperLimit);
    for (int i = 0; i < upperLimit; i++) dos.writeInt(getErrorCount(i));
  }

  /**
   * Get the number of errors recorded for a specific numeric mode.
   *
   * @param mode the raw integer failure code
   * @return the current count for {@code mode}, or {@code 0} when absent
   */
  public synchronized int getErrorCount(int mode) {
    if (map == null) return 0;
    Integer item = map.get(mode);
    return item == null ? 0 : item;
  }

  /**
   * Get the number of errors recorded for a specific insert failure mode.
   *
   * @param mode the insert mode to query
   * @return the current count for {@code mode}, or {@code 0} when absent
   * @throws IllegalStateException if this tracker is configured for fetch mode
   */
  public synchronized int getErrorCount(InsertExceptionMode mode) {
    if (!insert) throw new IllegalStateException();
    return getErrorCount(mode.code);
  }

  /**
   * Get the number of errors recorded for a specific fetch failure mode.
   *
   * @param mode the fetch mode to query
   * @return the current count for {@code mode}, or {@code 0} when absent
   * @throws IllegalStateException if this tracker is configured for insert mode
   */
  public synchronized int getErrorCount(FetchExceptionMode mode) {
    if (insert) throw new IllegalStateException();
    return getErrorCount(mode.code);
  }

  /**
   * Reconstruct a tracker from its {@linkplain #writeFixedLengthTo(DataOutputStream) fixed-length}
   * binary representation.
   *
   * <p>The method validates the header (magic, version, and mode-specific upper limit) and then
   * reads all counters. Negative values are rejected as a format error.
   *
   * @param insert {@code true} when deserializing an insert-mode tracker; {@code false} for fetch
   * @param dis the input stream positioned at the start of a serialized tracker
   * @throws IOException if the input stream cannot be read
   * @throws StorageFormatException if the header does not match the expected format or counters are
   *     invalid
   */
  public FailureCodeTracker(boolean insert, DataInputStream dis)
      throws IOException, StorageFormatException {
    this.insert = insert;
    if (dis.readInt() != MAGIC)
      throw new StorageFormatException("Bad magic for FailureCodeTracker");
    if (dis.readInt() != VERSION)
      throw new StorageFormatException("Bad version for FailureCodeTracker");
    int upperLimit = upperLimitErrorCode(insert);
    if (dis.readInt() != upperLimit)
      throw new StorageFormatException("Bad upper limit for FailureCodeTracker");
    for (int i = 0; i < upperLimit; i++) {
      int x = dis.readInt();
      if (x < 0) throw new StorageFormatException("Negative error counts");
      if (x == 0) continue;
      if (map == null) map = new HashMap<>();
      total += x;
      map.put(i, x);
    }
  }
}
