package network.crypta.node;

/**
 * Callbacks for the local node-announcement procedure.
 *
 * <p>Implementations receive progress and outcome notifications while attempting to announce a node
 * reference ("noderef") to peers. Callbacks may be invoked multiple times during a single run
 * depending on how many peers are contacted and how they respond. Avoid heavy or blocking work
 * inside callbacks to keep the announcement pipeline responsive.
 */
public interface AnnouncementCallback {

  /**
   * Signals that the announcement attempt has finished. No further callbacks are expected for the
   * current run.
   */
  void completed();

  /**
   * Reports that a node reference was deemed invalid and rejected.
   *
   * @param reason diagnostic description of why the noderef was considered bogus
   */
  void bogusNoderef(String reason);

  /**
   * Reports a failure while interacting with a specific peer during announcement.
   *
   * @param pn the peer involved in the failure
   * @param reason diagnostic description of the failure
   */
  void nodeFailed(PeerNode pn, String reason);

  /** Indicates there are no additional peers to consider for this announcement run. */
  void noMoreNodes();

  /**
   * Reports that a peer has been added as a result of the announcement.
   *
   * @param pn the peer that was added
   */
  void addedNode(PeerNode pn);

  /** Indicates that the noderef was declined by policy or otherwise not desired. */
  void nodeNotWanted();

  /** Node reference was valid but not added locally (for example, because it already exists). */
  void nodeNotAdded();

  /** Indicates that the announcement was accepted by at least one peer. */
  void acceptedSomewhere();

  /**
   * Reports that a valid noderef was relayed to the downstream node that initiated the announcement
   * process.
   */
  void relayedNoderef();
}
