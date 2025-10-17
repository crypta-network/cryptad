package network.crypta.support;

import java.util.Arrays;
import java.util.HashMap;

/**
 * Mutable multiset (bag) of strings with per-string occurrence counts.
 *
 * <p>This utility associates a non-negative counter with each distinct string key. Keys are
 * compared using {@link String#equals(Object)} and may be {@code null} (treated as a distinct key).
 * Typical usage is to call {@link #inc(String)} for each observation and inspect totals via {@link
 * #get(String)} or present a summary via {@link #toLongString()} or {@link #toTableRows(HTMLNode)}.
 *
 * <p>Thread-safety: Mutating and snapshotting operations are synchronized on the instance; simple
 * reads via {@link #get(String)} are not synchronized. If multiple threads access the same instance
 * concurrently, external synchronization is required for safe publication of updates to readers.
 *
 * <p>Complexity: {@code inc()} and {@code get()} are amortized O(1). Rendering methods sort the
 * distinct keys and are O(n log n) in the number of keys.
 *
 * <p>Nullability and sorting: When producing sorted output, ties on the counter are broken by a
 * reverse-lexicographic comparison of the string keys. If any of the tied keys are {@code null}, a
 * {@link NullPointerException} will be thrown by the tie-break comparison. A lone {@code null} key
 * whose count is unique does not trigger an exception.
 *
 * @author toad
 */
public class StringCounter {

  private final HashMap<String, Item> map;

  private static class Item {
    public Item(String string2) {
      this.string = string2;
    }

    final String string;
    int counter;
  }

  /** Creates an empty counter with no keys. */
  public StringCounter() {
    map = new HashMap<>();
  }

  /**
   * Increments the counter associated with {@code string} by one.
   *
   * <p>If the key is observed for the first time it is inserted with an initial count of 1.
   *
   * <p>Thread-safety: This method synchronizes on the instance.
   *
   * @param string Key to increment; may be {@code null} to count nulls separately
   */
  public synchronized void inc(String string) {
    Item item = map.get(string);
    if (item == null) {
      item = new Item(string);
      item.counter = 1;
      map.put(string, item);
    } else item.counter++;
  }

  /**
   * Returns the current count for {@code string}.
   *
   * <p>If the key has not been observed, {@code 0} is returned. The method does not allocate and
   * does not modify internal state.
   *
   * <p>Thread-safety: This method is not synchronized; concurrent updates from other threads may
   * not be visible without external synchronization.
   *
   * @param string Key to query; may be {@code null}
   * @return Non-negative count, or {@code 0} if absent
   */
  public int get(String string) {
    Item item = map.get(string);
    if (item == null) return 0;
    return item.counter;
  }

  // Produces a snapshot array of current items for sorting/rendering. Synchronized to avoid
  // concurrent modification while iterating over the backing map.
  private synchronized Item[] items() {
    return map.values().toArray(new Item[0]);
  }

  /**
   * Returns the current items sorted by descending counter; ties are broken by a
   * reverse-lexicographic comparison of the string keys.
   *
   * <p>Note: This preserves historical semantics where ties on {@code counter} are broken by the
   * reverse ordering of string comparison. This will throw a {@link NullPointerException} when any
   * tied key is {@code null}.
   */
  private synchronized Item[] sortedItemsDesc() {
    Item[] items = items();
    Arrays.sort(
        items,
        (it0, it1) -> {
          if (it0.counter > it1.counter) {
            return -1; // higher count first
          } else if (it0.counter < it1.counter) {
            return 1; // lower count later
          } else {
            // Reverse alphabetical order on ties (may throw NPE if any string is null).
            // Use argument swapping instead of negating compareTo() to avoid MIN_VALUE overflow.
            return it1.string.compareTo(it0.string);
          }
        });
    return items;
  }

  /**
   * Renders a descending frequency table as a single string.
   *
   * <p>The format is one line per key, each line containing the key, a tab, and the count (e.g.,
   * {@code "key\t3"}). Lines are separated by {@code '\n'}. When there are no entries, the empty
   * string is returned.
   *
   * <p>Sorting semantics and null-handling follow {@link #sortedItemsDesc()}.
   *
   * @return A formatted table string, possibly empty
   * @throws NullPointerException if tied keys include {@code null}
   */
  public String toLongString() {
    Item[] items = sortedItemsDesc();
    if (items.length == 0) return "";
    StringBuilder sb = new StringBuilder();
    for (Item it : items) {
      sb.append(it.string);
      sb.append('\t');
      sb.append(it.counter);
      sb.append('\n');
    }
    // At least one line was appended; drop the final trailing newline.
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  /**
   * Appends table rows representing the counts to the given {@link HTMLNode} table.
   *
   * <p>For each key, a new {@code <tr>} is added with two {@code <td>} cells: the first contains
   * the count followed by a non-breaking space (NBSP) to keep the count visually separated, and the
   * second contains the key. Rows are added in descending count order with reverse-lexicographic
   * tie-breaks.
   *
   * @param table Destination table node; must be a mutable {@code <table>} element
   * @return Number of rows appended
   * @throws NullPointerException if tied keys include {@code null}
   */
  public int toTableRows(HTMLNode table) {
    Item[] items = sortedItemsDesc();
    for (Item it : items) {
      HTMLNode row = table.addChild("tr");
      // NBSP appended to keep count adjacent in some renderers.
      row.addChild("td", it.counter + "\u00a0");
      row.addChild("td", it.string);
    }
    return items.length;
  }
}
