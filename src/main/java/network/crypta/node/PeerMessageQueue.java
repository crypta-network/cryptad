package network.crypta.node;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Map;
import java.util.Random;
import network.crypta.io.comm.DMT;
import network.crypta.support.DoublyLinkedList;
import network.crypta.support.DoublyLinkedListImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Queue of outbound messages for a single peer.
 *
 * <p>Messages are organized by transport priority (see {@link network.crypta.io.comm.DMT}) and,
 * within each priority, by urgency and submission time. Some priorities (realtime and bulk) use a
 * round‑robin policy keyed by a per-transfer UID to maintain fairness across transfers. Other
 * priorities are FIFO by submission time until they become urgent.
 *
 * <p>Threading: Public methods are synchronized on the instance. Internal structures are mutated
 * only while holding that lock. Time values are in milliseconds since the epoch unless otherwise
 * stated. Deadlines represent the latest time a message should be sent to avoid being considered
 * overdue.
 *
 * <p>Side effects: Selecting a message for send may update round‑robin trackers and deadlines to
 * preserve fairness. Removing a specific message via {@link #removeMessage(MessageItem)} invokes
 * {@link MessageItem#onFailed()} after successful removal.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class PeerMessageQueue {
  private static final Logger LOG = LoggerFactory.getLogger(PeerMessageQueue.class);

  private final PrioQueue[] queuesByPriority;

  private static class PrioQueue {

    // Note: this could be split into PrioQueue and RoundRobinByUIDPrioQueue later if required.
    PrioQueue(long timeout, boolean timeoutSinceLastSend) {
      this.timeout = timeout;
      this.roundRobinBetweenUIDs = timeoutSinceLastSend;
    }

    /** The timeout in milliseconds after which messages become urgent. */
    final long timeout;

    /**
     * If true, do round-robin between UID's, and count the timeout relative to the last send. Block
     * transfers need this - both realtime and bulk.
     */
    final boolean roundRobinBetweenUIDs;

    private static class Items extends DoublyLinkedListImpl.Item<Items> {
      /** Messages to send for a single UID. Earlier elements are sent first within the UID. */
      final LinkedList<MessageItem> messages;

      final long id;
      long timeLastSent;

      Items(long id, long initialTimeLastSent) {
        messages = new LinkedList<>();
        this.id = id;
        timeLastSent = initialTimeLastSent;
      }

      public void addLast(MessageItem item) {
        messages.addLast(item);
      }

      public void addFirst(MessageItem item) {
        messages.addFirst(item);
      }

      public boolean remove(MessageItem item) {
        return messages.remove(item);
      }

      @Override
      public String toString() {
        return super.toString() + ":" + id + ":" + messages.size() + ":" + timeLastSent;
      }
    }

    /**
     * Forget round‑robin state after 3 minutes. This bounds tracker memory for inactive UIDs and is
     * higher than the per-packet coalescing delays used by realtime/bulk transfers.
     */
    static final long FORGET_AFTER = 3L * 60 * 1000;

    /**
     * Ordered by {@code timeLastSent}, not by timeout. Elements not yet sent appear first with
     * {@code timeLastSent = -1}. A doubly-linked list allows stable reordering and O(1) removal.
     */
    DoublyLinkedListImpl<Items> nonEmptyItemsWithID;

    /**
     * UID trackers that were sent recently but currently have no queued messages. Tracked to
     * preserve fair round‑robin when new messages arrive for the same UID.
     */
    DoublyLinkedListImpl<Items> emptyItemsWithID;

    Map<Long, Items> itemsByID;

    /** Non‑urgent messages. Earlier elements are sent first when they become eligible. */
    LinkedList<MessageItem> itemsNonUrgent;

    // Structures are constructed lazily while callers hold PeerMessageQueue's monitor.

    /**
     * Add a new message. For non-round‑robin priorities, append by submission time and compute the
     * initial deadline as {@code submitted + timeout}. For round‑robin priorities, do the same
     * unless a message with the same UID was sent recently, in which case the deadline is relative
     * to {@code lastSend + timeout}.
     */
    public void addLast(MessageItem item) {
      // Clear the deadline for the item.
      item.clearDeadline();
      if (LOG.isDebugEnabled()) checkOrder();
      if (!roundRobinBetweenUIDs) {
        addToNonUrgent(item);
        return;
      }
      long id = item.getID();
      if (itemsByID != null) {
        Items it = itemsByID.get(id);
        if (it != null
            && it.timeLastSent > 0
            && it.timeLastSent + timeout <= System.currentTimeMillis()) {
          it.addLast(item);
          if (it.getParent() == emptyItemsWithID) moveFromEmptyToNonEmptyBackward(it);
          else assert (it.getParent() == nonEmptyItemsWithID);
          if (LOG.isDebugEnabled()) checkOrder();
          return;
        }
      }
      addToNonUrgent(item);
    }

    private void addToNonUrgent(MessageItem item) {
      if (itemsNonUrgent == null) itemsNonUrgent = new LinkedList<>();
      ListIterator<MessageItem> it = itemsNonUrgent.listIterator(itemsNonUrgent.size());
      // MessageItems can be created out of order; submitted timestamps may not be monotonic.
      // This insertion runs under the PeerMessageQueue lock, so ordering remains consistent.
      while (true) {
        if (!it.hasPrevious()) {
          it.add(item);
          if (LOG.isDebugEnabled()) checkOrder();
          return;
        }
        MessageItem prev = it.previous();
        if (item.submitted >= prev.submitted) {
          it.next();
          it.add(item);
          if (LOG.isDebugEnabled()) checkOrder();
          return;
        }
      }
    }

    private void moveToUrgent(long now) {
      if (LOG.isDebugEnabled()) checkOrder();
      if (itemsNonUrgent == null) return;
      ListIterator<MessageItem> it = itemsNonUrgent.listIterator();
      int moved = 0;
      while (it.hasNext()) {
        MessageItem item = it.next();
        Items list = (itemsByID == null) ? null : itemsByID.get(item.getID());
        if (shouldMoveToUrgent(list, item, now)) {
          moveItemToUrgent(it, list, item);
          moved++;
        } else if (!roundRobinBetweenUIDs) {
          break;
        }
      }
      if (LOG.isTraceEnabled() && moved > 0)
        LOG.trace("Move {} messages to urgent round-robin", moved);
      if (LOG.isDebugEnabled()) checkOrder();
    }

    private boolean shouldMoveToUrgent(Items list, MessageItem item, long now) {
      return (item.submitted + timeout <= now)
          || (list != null && roundRobinBetweenUIDs && (list.timeLastSent + timeout <= now));
    }

    private void moveItemToUrgent(ListIterator<MessageItem> it, Items list, MessageItem item) {
      if (LOG.isTraceEnabled()) LOG.trace("Move message to urgent list: {}", item);
      if (LOG.isDebugEnabled()) checkOrder();
      Items ensured = ensureTrackerForUrgent(list, item.getID(), item.submitted);
      ensured.addLast(item);
      it.remove();
      if (LOG.isDebugEnabled()) checkOrder();
    }

    private Items ensureTrackerForUrgent(Items list, long id, long initialTimeLastSent) {
      ensureMapsInitialized();
      if (list == null) {
        Items created = new Items(id, initialTimeLastSent);
        addToNonEmptyForward(created);
        itemsByID.put(id, created);
        if (LOG.isDebugEnabled()) checkOrder();
        return created;
      }
      if (list.messages.isEmpty()) {
        if (list.getParent() == nonEmptyItemsWithID) {
          LOG.error("List is empty but in nonEmptyItemsWithID: {}", list);
        } else {
          assert (list.getParent() == emptyItemsWithID);
          // It already exists, so it has a valid time.
          // Which is probably in the past, so use Forward.
          // Must add it to the list before moving to non-empty because of assertion.
          moveFromEmptyToNonEmptyForward(list);
        }
      } else {
        assert (list.getParent() == nonEmptyItemsWithID);
      }
      if (LOG.isDebugEnabled()) checkOrder();
      return list;
    }

    private void ensureMapsInitialized() {
      if (itemsByID == null) itemsByID = new HashMap<>();
      if (nonEmptyItemsWithID == null) nonEmptyItemsWithID = new DoublyLinkedListImpl<>();
    }

    private void moveFromEmptyToNonEmptyForward(Items list) {
      // Assumed to be in emptyItemsWithID
      assert (list.messages.isEmpty());
      if (LOG.isDebugEnabled() && list.getParent() == nonEmptyItemsWithID) {
        LOG.error("Item is marked non-empty but contains no messages");
        return;
      }
      if (emptyItemsWithID != null) emptyItemsWithID.remove(list);
      addToNonEmptyForward(list);
    }

    private void addToNonEmptyForward(Items list) {
      if (nonEmptyItemsWithID == null) nonEmptyItemsWithID = new DoublyLinkedListImpl<>();
      Enumeration<Items> it = nonEmptyItemsWithID.elements();
      while (it.hasMoreElements()) {
        Items compare = it.nextElement();
        if (compare.timeLastSent >= list.timeLastSent) {
          nonEmptyItemsWithID.insertPrev(compare, list);
          return;
        }
      }
      nonEmptyItemsWithID.push(list);
    }

    private void moveFromEmptyToNonEmptyBackward(Items list) {
      // Assumed to be in emptyItemsWithID
      emptyItemsWithID.remove(list);
      addToNonEmptyBackward(list);
    }

    private void addToNonEmptyBackward(Items list) {
      if (nonEmptyItemsWithID == null) nonEmptyItemsWithID = new DoublyLinkedListImpl<>();
      Enumeration<Items> it = nonEmptyItemsWithID.reverseElements();
      while (it.hasMoreElements()) {
        Items compare = it.nextElement();
        if (compare.timeLastSent <= list.timeLastSent) {
          nonEmptyItemsWithID.insertNext(compare, list);
          return;
        }
      }
      nonEmptyItemsWithID.unshift(list);
    }

    private void addToEmptyBackward(Items list) {
      if (emptyItemsWithID == null) emptyItemsWithID = new DoublyLinkedListImpl<>();
      Enumeration<Items> it = emptyItemsWithID.reverseElements();
      while (it.hasMoreElements()) {
        Items compare = it.nextElement();
        if (compare.timeLastSent <= list.timeLastSent) {
          emptyItemsWithID.insertNext(compare, list);
          return;
        }
      }
      emptyItemsWithID.unshift(list);
    }

    /**
     * Add a new message at the front so it is sent as soon as possible (e.g., after a failed send).
     * The item is assumed to be urgent already.
     */
    public void addFirst(MessageItem item) {
      // Keep the old deadline for the item.
      if (!roundRobinBetweenUIDs) {
        addToNonUrgent(item);
        return;
      }
      if (LOG.isDebugEnabled()) checkOrder();
      long id = item.getID();
      Items list = getOrCreateListForAddFirst(id);
      list.addFirst(item);
      if (LOG.isDebugEnabled()) checkOrder();
    }

    private Items getOrCreateListForAddFirst(long id) {
      if (itemsByID == null) {
        itemsByID = new HashMap<>();
        if (nonEmptyItemsWithID == null) nonEmptyItemsWithID = new DoublyLinkedListImpl<>();
        Items list = new Items(id, -1);
        addToNonEmptyForward(list);
        itemsByID.put(id, list);
        return list;
      }
      Items list = itemsByID.get(id);
      if (list == null) {
        list = new Items(id, -1);
        if (nonEmptyItemsWithID == null) nonEmptyItemsWithID = new DoublyLinkedListImpl<>();
        nonEmptyItemsWithID.unshift(list);
        itemsByID.put(id, list);
        return list;
      }
      if (list.messages.isEmpty()) {
        assert (list.getParent() == emptyItemsWithID);
        // It already exists, so it has a valid time.
        // Likely in the past; insert using forward ordering.
        moveFromEmptyToNonEmptyForward(list);
      } else {
        assert (list.getParent() == nonEmptyItemsWithID);
      }
      return list;
    }

    public int size() {
      int size = 0;
      if (nonEmptyItemsWithID != null)
        for (Items items : nonEmptyItemsWithID) size += items.messages.size();
      if (itemsNonUrgent != null) size += itemsNonUrgent.size();
      return size;
    }

    public int addTo(MessageItem[] output, int ptr) {
      if (nonEmptyItemsWithID != null)
        for (Items list : nonEmptyItemsWithID)
          for (MessageItem item : list.messages) output[ptr++] = item;
      if (itemsNonUrgent != null) for (MessageItem item : itemsNonUrgent) output[ptr++] = item;
      return ptr;
    }

    /**
     * Verify that {@code nonEmptyItemsWithID} is ordered by {@code timeLastSent}.
     *
     * <p>Locking: callers must synchronize on {@code PeerMessageQueue.this}.
     */
    private void checkOrder() {
      if (nonEmptyItemsWithID != null) {
        long prev = -1;
        Items prevItems = null;
        for (Items items : nonEmptyItemsWithID) {
          long thisTime = items.timeLastSent;
          if (thisTime < prev)
            LOG.error(
                "Inconsistent order in non-empty itemsByID: prevTimeout={} prev={} timeout={}"
                    + " curr={}",
                prev,
                prevItems,
                thisTime,
                items,
                new Exception("error"));
          prev = thisTime;
          prevItems = items;
        }
      }
      if (itemsNonUrgent != null) {
        long prev = -1;
        MessageItem prevItem = null;
        for (MessageItem item : itemsNonUrgent) {
          if (item.submitted < prev)
            LOG.error(
                "Inconsistent order in itemsNonUrgent: prevSubmitted={} currSubmitted={} prev={}"
                    + " curr={}",
                prev,
                item.submitted,
                prevItem,
                item);
          prev = item.submitted;
          prevItem = item;
        }
      }
    }

    /**
     * Note that this does NOT consider the length of the queue, which can trigger a send. This is
     * intentional, and is relied upon by the bulk-or-realtime logic in addMessages().
     *
     * @param t The initial urgent time. What we return must be less than or equal to this.
     *     Convenient for chaining.
     * @param stopIfBeforeTime If the next urgent time is <= to this time, return immediately.
     */
    public long getNextUrgentTime(long t, long stopIfBeforeTime) {
      return roundRobinBetweenUIDs
          ? getNextUrgentTimeRoundRobin(t, stopIfBeforeTime)
          : getNextUrgentTimeNonRoundRobin(t, stopIfBeforeTime);
    }

    private long getNextUrgentTimeNonRoundRobin(long t, long stopIfBeforeTime) {
      if (itemsNonUrgent != null && !itemsNonUrgent.isEmpty()) {
        t = Math.min(t, itemsNonUrgent.getFirst().submitted + timeout);
        if (t <= stopIfBeforeTime) return t;
      }
      assert (nonEmptyItemsWithID == null);
      assert (itemsByID == null);
      return t;
    }

    private long getNextUrgentTimeRoundRobin(long t, long stopIfBeforeTime) {
      t = updateFromNonEmptyRoundRobin(t, stopIfBeforeTime);
      if (t <= stopIfBeforeTime) return t;
      t = updateFromNonUrgentRoundRobin(t, stopIfBeforeTime);
      return t;
    }

    private long updateFromNonEmptyRoundRobin(long t, long stopIfBeforeTime) {
      if (nonEmptyItemsWithID == null) return t;
      for (Items items : nonEmptyItemsWithID) {
        if (items.messages.isEmpty()) continue;
        if (items.timeLastSent > 0) {
          t = Math.min(t, items.timeLastSent + timeout);
        } else {
          t = Math.min(t, items.messages.getFirst().submitted + timeout);
        }
        if (t <= stopIfBeforeTime) return t;
      }
      return t;
    }

    private long updateFromNonUrgentRoundRobin(long t, long stopIfBeforeTime) {
      if (itemsNonUrgent == null || itemsNonUrgent.isEmpty()) return t;
      for (MessageItem item : itemsNonUrgent) {
        long candidate = candidateTimeForNonUrgent(item);
        t = Math.min(t, candidate);
        if (t <= stopIfBeforeTime) return t;
        if (itemsByID == null) break; // Only the first one matters, since none have been sent.
      }
      return t;
    }

    private long candidateTimeForNonUrgent(MessageItem item) {
      if (itemsByID != null) {
        Items tracked = itemsByID.get(item.getID());
        if (tracked != null && tracked.timeLastSent > 0) {
          return tracked.timeLastSent + timeout;
        }
      }
      return item.submitted + timeout;
    }

    /**
     * Add the size of messages in this queue to <code>length</code> until length is larger than
     * <code>maxSize</code>, or all messages have been added.
     *
     * @param length the starting length
     * @param maxSize the size at which to stop
     * @return the resulting length after adding messages
     */
    public int addSize(int length, int maxSize) {
      length = addNonUrgentSizes(length, maxSize);
      length = addUrgentSizes(length, maxSize);
      return length;
    }

    private int addNonUrgentSizes(int length, int maxSize) {
      if (itemsNonUrgent == null) return length;
      for (MessageItem item : itemsNonUrgent) {
        length += item.getLength();
        if (length > maxSize) return length;
      }
      return length;
    }

    private int addUrgentSizes(int length, int maxSize) {
      if (nonEmptyItemsWithID == null) return length;
      for (Items list : nonEmptyItemsWithID) {
        for (MessageItem item : list.messages) {
          length += item.getLength();
          if (length > maxSize) return length;
        }
      }
      return length;
    }

    private MessageItem addNonUrgentMessages(long now) {
      if (LOG.isDebugEnabled()) checkOrder();
      if (itemsNonUrgent == null || itemsNonUrgent.isEmpty()) return null;
      MessageItem item = itemsNonUrgent.removeFirst();
      item.setDeadline(item.submitted + timeout);
      if (itemsByID != null) demoteTrackerAfterNonUrgentSend(now, item);
      if (LOG.isDebugEnabled()) checkOrder();
      return item;
    }

    private void demoteTrackerAfterNonUrgentSend(long now, MessageItem item) {
      Items tracker = itemsByID.get(item.getID());
      if (tracker == null) return;
      tracker.timeLastSent = now;
      DoublyLinkedList<? super Items> parent = tracker.getParent();
      if (tracker.messages.isEmpty()) {
        demoteEmptyTracker(tracker, parent);
      } else {
        demoteNonEmptyTracker(tracker, parent);
      }
    }

    private void demoteEmptyTracker(Items tracker, DoublyLinkedList<? super Items> parent) {
      if (LOG.isTraceEnabled())
        LOG.trace("Moving {} to end of empty list in addNonUrgentMessages", tracker);
      if (emptyItemsWithID == null) emptyItemsWithID = new DoublyLinkedListImpl<>();
      if (parent == null) {
        LOG.error("Tracker is in itemsByID but not in either list! (empty)");
      } else if (parent == emptyItemsWithID) {
        emptyItemsWithID.remove(tracker);
      } else if (parent == nonEmptyItemsWithID) {
        LOG.error("Tracker is in non empty items list when is empty");
        nonEmptyItemsWithID.remove(tracker);
      } else assert (false);
      addToEmptyBackward(tracker);
    }

    private void demoteNonEmptyTracker(Items tracker, DoublyLinkedList<? super Items> parent) {
      if (LOG.isDebugEnabled())
        LOG.debug("Moving {} to end of non-empty list in addNonUrgentMessages", tracker);
      if (nonEmptyItemsWithID == null) nonEmptyItemsWithID = new DoublyLinkedListImpl<>();
      if (parent == null) {
        LOG.error("Tracker is in itemsByID but not in either list! (non-empty)");
      } else if (parent == nonEmptyItemsWithID) {
        nonEmptyItemsWithID.remove(tracker);
      } else if (parent == emptyItemsWithID) {
        LOG.error("Tracker is in empty items list when is non-empty");
        emptyItemsWithID.remove(tracker);
      } else assert (false);
      addToNonEmptyBackward(tracker);
    }

    /**
     * Select one urgent message using round-robin state.
     *
     * <p>Examines the head of {@code nonEmptyItemsWithID}, extracts the next message for that UID,
     * and requeues the UID to the appropriate list tail based on whether it remains non-empty.
     *
     * @param now current time in milliseconds since epoch
     * @return the selected urgent message, or {@code null} if none are available
     */
    private MessageItem addUrgentMessages(long now) {
      if (LOG.isDebugEnabled()) checkOrder();
      if (nonEmptyItemsWithID == null) {
        if (LOG.isDebugEnabled()) LOG.debug("No non-empty items; no urgent messages to send");
        return null;
      }
      if (!normalizeHeadNonEmpty()) return null;
      Items list = nonEmptyItemsWithID.head();
      assert list != null;
      MessageItem item = extractFromListAndRequeue(list, now);
      if (LOG.isTraceEnabled()) checkOrder();
      return item;
    }

    private boolean normalizeHeadNonEmpty() {
      Items list = nonEmptyItemsWithID.head();
      while (list != null && list.messages.isEmpty()) {
        if (!handleEmptyListInUrgent(list)) return false;
        list = nonEmptyItemsWithID.head();
      }
      return list != null;
    }

    private boolean handleEmptyListInUrgent(Items list) {
      // Should not happen; guard to preserve internal invariants.
      LOG.error("List appears in nonEmptyItemsWithID but contains no messages: {}", list);
      nonEmptyItemsWithID.remove(list);
      addToEmptyBackward(list);
      if (nonEmptyItemsWithID.isEmpty()) {
        if (LOG.isDebugEnabled()) LOG.debug("No non-empty items to send");
        return false;
      }
      return true;
    }

    private MessageItem extractFromListAndRequeue(Items list, long now) {
      MessageItem item = list.messages.getFirst();
      list.messages.removeFirst();
      nonEmptyItemsWithID.remove(list);
      item.setDeadline(list.timeLastSent + timeout);
      list.timeLastSent = now;
      if (!list.messages.isEmpty()) {
        if (LOG.isTraceEnabled())
          LOG.trace("Move {} to tail of non-empty list in addUrgentMessages", list);
        addToNonEmptyBackward(list);
      } else {
        if (LOG.isTraceEnabled())
          LOG.trace("Move {} to tail of empty list in addUrgentMessages", list);
        addToEmptyBackward(list);
      }
      return item;
    }

    /**
     * Select one eligible message for this priority.
     *
     * <p>When round‑robin is enabled, first promotes items that reached their timeout threshold
     * (urgent), then selects from urgent; if none are urgent, selects from non‑urgent in submission
     * order. When round‑robin is disabled, only non‑urgent order applies.
     *
     * @param now current time in milliseconds since epoch
     * @return the selected message, or {@code null} if none are eligible
     */
    MessageItem addPriorityMessages(long now) {
      // Prefer urgent messages; fall back to non-urgent when none are eligible.
      if (LOG.isDebugEnabled()) {
        int nonEmpty = nonEmptyItemsWithID == null ? 0 : nonEmptyItemsWithID.size();
        int empty = emptyItemsWithID == null ? 0 : emptyItemsWithID.size();
        int byID = itemsByID == null ? 0 : itemsByID.size();
        if (nonEmpty + empty < byID) {
          LOG.error(
              "itemsByID count exceeds tracked lists: non-empty={} empty={} byID={} on {}",
              nonEmpty,
              empty,
              byID,
              this);
        } else if (LOG.isDebugEnabled())
          LOG.debug(
              "Queue state: non-empty={} empty={} byID={} on {}", nonEmpty, empty, byID, this);
      }
      if (roundRobinBetweenUIDs) moveToUrgent(now);
      clearOldNonUrgent(now);
      if (roundRobinBetweenUIDs) {
        MessageItem item = addUrgentMessages(now);
        if (item != null) return item;
      } else {
        assert (itemsByID == null);
      }
      // 	If no more urgent messages, try to add some non-urgent messages too.
      return addNonUrgentMessages(now);
    }

    private void clearOldNonUrgent(long now) {
      if (LOG.isDebugEnabled()) checkOrder();
      int removed = 0;
      if (emptyItemsWithID == null) return;
      while (!emptyItemsWithID.isEmpty()) {
        if (LOG.isDebugEnabled()) checkOrder();
        boolean removedOne = processEmptyHead(now);
        if (!removedOne) break;
        removed++;
      }
      if (LOG.isTraceEnabled() && removed > 0)
        LOG.trace("Remove {} stale empty UID trackers", removed);
    }

    private boolean shouldForget(Items list, long now) {
      return list.timeLastSent == -1 || now - list.timeLastSent > FORGET_AFTER;
    }

    private void forgetTrackerList(Items list) {
      // Map.remove(Object) returns the removed value; verify correctness.
      Items old = itemsByID.remove(list.id);
      if (old == null) LOG.error("ID {} not found in itemsByID tracker", list.id);
      else if (old != list)
        LOG.error(
            "Mismatched list in itemsByID tracker: stored={} current={} id={}", old, list, list.id);
      emptyItemsWithID.remove(list);
    }

    private boolean processEmptyHead(long now) {
      Items list = emptyItemsWithID.head();
      if (list == null) {
        LOG.error("emptyItemsWithID is not empty but head() returns null");
        return false;
      }
      if (!list.messages.isEmpty()) {
        LOG.error("List in emptyItemsWithID contains messages");
        emptyItemsWithID.remove(list);
        addToNonEmptyBackward(list);
        return false;
      }
      if (shouldForget(list, now)) {
        forgetTrackerList(list);
        return true;
      }
      return false;
    }

    public void clear() {
      emptyItemsWithID = null;
      nonEmptyItemsWithID = null;
      itemsByID = null;
      itemsNonUrgent = null;
      if (LOG.isDebugEnabled()) checkOrder();
    }

    public boolean removeMessage(MessageItem item) {
      if (LOG.isDebugEnabled()) checkOrder();
      long id = item.getID();
      if (itemsByID != null) {
        Items list = itemsByID.get(id);
        if (list != null && list.remove(item)) {
          if (list.messages.isEmpty()) {
            nonEmptyItemsWithID.remove(list);
            addToEmptyBackward(list);
          }
          if (LOG.isDebugEnabled()) checkOrder();
          return true;
        }
      }
      if (LOG.isDebugEnabled()) checkOrder();
      if (itemsNonUrgent != null) return itemsNonUrgent.remove(item);
      else return false;
    }

    public void removeUIDs(Long[] list) {
      if (LOG.isDebugEnabled()) checkOrder();
      if (itemsByID == null) return;
      for (Long l : list) {
        Items items = itemsByID.get(l);
        if (items == null) continue;
        if (items.messages.isEmpty()) {
          itemsByID.remove(l);
          assert (emptyItemsWithID != null);
          assert (items.getParent() == emptyItemsWithID);
          emptyItemsWithID.remove(items);
        }
      }
      if (LOG.isDebugEnabled()) checkOrder();
    }

    public boolean isEmpty() {
      if (itemsNonUrgent != null && !itemsNonUrgent.isEmpty()) {
        return false;
      }
      if (nonEmptyItemsWithID != null) {
        for (Items items : nonEmptyItemsWithID) {
          if (items.messages.isEmpty()) continue;
          return false;
        }
      }
      return true;
    }
  }

  private final Random fastWeakRandom;

  PeerMessageQueue(Random fastWeakRandom) {
    this.fastWeakRandom = fastWeakRandom;
    queuesByPriority = new PrioQueue[DMT.NUM_PRIORITIES];
    for (int i = 0; i < queuesByPriority.length; i++) {
      switch (i) {
        case DMT.PRIORITY_BULK_DATA ->
            queuesByPriority[i] = new PrioQueue(PacketSender.MAX_COALESCING_DELAY_BULK, true);
        case DMT.PRIORITY_REALTIME_DATA ->
            queuesByPriority[i] = new PrioQueue(PacketSender.MAX_COALESCING_DELAY, true);
        default -> queuesByPriority[i] = new PrioQueue(PacketSender.MAX_COALESCING_DELAY, false);
      }
    }
  }

  /**
   * Enqueue a message and estimate the total queued size.
   *
   * <p>The estimate sums {@link MessageItem#getLength()} for all queued messages across priorities
   * plus a small per-message overhead, stopping once it exceeds {@code maxSize}. The new item is
   * inserted according to its priority and scheduling rules.
   *
   * @param item the message to enqueue
   * @param maxSize the upper bound for the estimate in bytes; accumulation stops once exceeded
   * @return the estimated total size in bytes (may exceed {@code maxSize} and then be incomplete)
   */
  public synchronized int queueAndEstimateSize(MessageItem item, int maxSize) {
    enqueuePrioritizedMessageItem(item);
    int x = 0;
    for (PrioQueue pq : queuesByPriority) {
      x = accumulateEstimateFor(pq, x, maxSize);
      if (x > maxSize) break;
    }
    return x;
  }

  private int accumulateEstimateFor(PrioQueue pq, int current, int maxSize) {
    int x = accumulateFromNonUrgent(pq, current, maxSize);
    if (x > maxSize) return x;
    return accumulateFromNonEmpty(pq, x, maxSize);
  }

  private int accumulateFromNonUrgent(PrioQueue pq, int current, int maxSize) {
    int x = current;
    if (pq.itemsNonUrgent == null) return x;
    for (MessageItem it : pq.itemsNonUrgent) {
      x += it.getLength() + 2;
      if (x > maxSize) return x;
    }
    return x;
  }

  private int accumulateFromNonEmpty(PrioQueue pq, int current, int maxSize) {
    int x = current;
    if (pq.nonEmptyItemsWithID == null) return x;
    for (PrioQueue.Items q : pq.nonEmptyItemsWithID) {
      for (MessageItem it : q.messages) {
        x += it.getLength() + 2;
        if (x > maxSize) return x;
      }
    }
    return x;
  }

  /**
   * Estimate the total size of all queued messages in bytes.
   *
   * <p>The estimate includes a small per-message overhead and sums all priorities. It does not
   * allocate or modify queue state.
   *
   * @return the approximate total queued size in bytes
   */
  public synchronized long getMessageQueueLengthBytes() {
    long x = 0;
    for (PrioQueue pq : queuesByPriority) {
      if (pq.nonEmptyItemsWithID != null)
        for (PrioQueue.Items q : pq.nonEmptyItemsWithID)
          for (MessageItem it : q.messages) x += it.getLength() + 2;
    }
    return x;
  }

  private synchronized void enqueuePrioritizedMessageItem(MessageItem addMe) {
    // Assume it goes on the end, both the common case
    short prio = addMe.getPriority();
    queuesByPriority[prio].addLast(addMe);
  }

  /**
   * Like {@code enqueuePrioritizedMessageItem} but adds at the front within the same priority.
   *
   * <p>Warning: Pulling a message and then pushing it back disturbs UID round‑robin fairness.
   * Prefer avoiding this unless necessary for correctness.
   */
  synchronized void pushfrontPrioritizedMessageItem(MessageItem addMe) {
    // Assume it goes on the front
    short prio = addMe.getPriority();
    queuesByPriority[prio].addFirst(addMe);
  }

  /**
   * Drain the queue into a newly allocated array.
   *
   * <p>Returns all queued items in their current order and clears internal structures. Intended for
   * batch send paths.
   *
   * @return an array containing the queued messages; empty if none
   */
  public synchronized MessageItem[] grabQueuedMessageItems() {
    int size = 0;
    for (PrioQueue queue : queuesByPriority) size += queue.size();
    MessageItem[] output = new MessageItem[size];
    int ptr = 0;
    for (PrioQueue queue : queuesByPriority) {
      ptr = queue.addTo(output, ptr);
      queue.clear();
    }
    return output;
  }

  /**
   * Compute the next time a message must be sent.
   *
   * <p>If any message is already overdue, the returned value is less than or equal to {@code now}
   * (as provided via {@code returnIfBefore}).
   *
   * @param t the current best known next-urgent time in milliseconds; the result is no greater
   * @param returnIfBefore the current time in milliseconds; return early if the next urgent time is
   *     less than or equal to this value
   * @return the next urgent time in milliseconds (may be in the past)
   */
  public synchronized long getNextUrgentTime(long t, long returnIfBefore) {
    for (PrioQueue queue : queuesByPriority) {
      t = Math.min(t, queue.getNextUrgentTime(t, returnIfBefore));
      if (t <= returnIfBefore)
        return t; // How much in the past doesn't matter, as long as it's in the past.
    }
    return t;
  }

  /**
   * Return whether any message times out by {@code now}.
   *
   * @param now the cutoff time in milliseconds since epoch
   * @return {@code true} if any message must be sent by {@code now}
   */
  public boolean mustSendNow(long now) {
    return getNextUrgentTime(Long.MAX_VALUE, now) <= now;
  }

  /**
   * Return whether the queue size plus a baseline exceeds {@code maxSize}.
   *
   * @param minSize the starting size in bytes to add to the estimate
   * @param maxSize the maximum packet size in bytes
   * @return {@code true} if estimated size exceeds {@code maxSize}
   */
  public synchronized boolean mustSendSize(int minSize, int maxSize) {
    int length = minSize;
    for (PrioQueue items : queuesByPriority) {
      length = items.addSize(length, maxSize);
      if (length > maxSize) return true;
    }
    return false;
  }

  /**
   * Select the next message to send, honoring priority and fairness.
   *
   * <p>Removes and returns a single message. For round‑robin priorities, selection updates the
   * per‑UID tracker as if the message were sent to preserve fairness. Callers should avoid invoking
   * this when the message cannot be sent.
   *
   * @param minPriority the lowest priority index to consider (see {@link DMT})
   * @return the selected message, or {@code null} if none is eligible
   */
  public synchronized MessageItem grabQueuedMessageItem(int minPriority) {
    long now = System.currentTimeMillis();

    // Scan priorities before realtime
    MessageItem early = tryPrioritiesRange(0, DMT.PRIORITY_REALTIME_DATA, minPriority, now);
    if (early != null) return early;

    // Include bulk or realtime, whichever is more urgent.
    if (shouldTryRealtimeFirst()) {
      MessageItem rtThenBulk = tryRealtimeThenBulk(now);
      if (rtThenBulk != null) return rtThenBulk;
    } else {
      MessageItem bulkThenRt = tryBulkThenRealtime(now);
      if (bulkThenRt != null) return bulkThenRt;
    }

    // Remaining priorities after bulk
    return tryPrioritiesRange(DMT.PRIORITY_BULK_DATA + 1, DMT.NUM_PRIORITIES, minPriority, now);
  }

  private MessageItem tryPrioritiesRange(int start, int end, int minPriority, long now) {
    for (int i = start; i < end; i++) {
      if (i < minPriority) continue;
      if (LOG.isDebugEnabled()) LOG.debug("Scan priority {}", i);
      MessageItem ret = queuesByPriority[i].addPriorityMessages(now);
      if (ret != null) return ret;
    }
    return null;
  }

  private boolean shouldTryRealtimeFirst() {
    if (queuesByPriority[DMT.PRIORITY_REALTIME_DATA].isEmpty()) return false;
    if (queuesByPriority[DMT.PRIORITY_BULK_DATA].isEmpty()) return true;
    if (queuesByPriority[DMT.PRIORITY_BULK_DATA].getNextUrgentTime(Long.MAX_VALUE, 0)
        >= queuesByPriority[DMT.PRIORITY_REALTIME_DATA].getNextUrgentTime(Long.MAX_VALUE, 0)) {
      return true;
    }
    // 2% chance to use bulk in case of a draw to avoid starving the bulk queue.
    return this.fastWeakRandom.nextInt(50) > 0;
  }

  private MessageItem tryRealtimeThenBulk(long now) {
    if (LOG.isDebugEnabled()) LOG.debug("Try realtime first");
    MessageItem ret = queuesByPriority[DMT.PRIORITY_REALTIME_DATA].addPriorityMessages(now);
    if (ret != null) return ret;
    if (LOG.isDebugEnabled()) LOG.debug("Try bulk");
    return queuesByPriority[DMT.PRIORITY_BULK_DATA].addPriorityMessages(now);
  }

  private MessageItem tryBulkThenRealtime(long now) {
    if (LOG.isDebugEnabled()) LOG.debug("Try bulk first");
    MessageItem ret = queuesByPriority[DMT.PRIORITY_BULK_DATA].addPriorityMessages(now);
    if (ret != null) return ret;
    if (LOG.isDebugEnabled()) LOG.debug("Try realtime");
    return queuesByPriority[DMT.PRIORITY_REALTIME_DATA].addPriorityMessages(now);
  }

  /**
   * Remove a specific message from the queue.
   *
   * <p>On successful removal, calls {@link MessageItem#onFailed()} outside the synchronized block
   * to notify the producer that the message will not be sent.
   *
   * @param message the message to remove
   * @return {@code true} if the message was found and removed; {@code false} otherwise
   */
  public boolean removeMessage(MessageItem message) {
    synchronized (this) {
      short prio = message.getPriority();
      if (!queuesByPriority[prio].removeMessage(message)) return false;
    }
    message.onFailed();
    return true;
  }

  /**
   * Remove empty UID trackers for the given IDs.
   *
   * <p>Deletes round‑robin tracking entries for UIDs that currently have no queued messages.
   * Enqueued messages are not removed by this method.
   *
   * @param list array of UID values whose empty trackers should be cleared
   */
  public synchronized void removeUIDsFromMessageQueues(Long[] list) {
    for (PrioQueue queue : queuesByPriority) {
      queue.removeUIDs(list);
    }
  }
}
