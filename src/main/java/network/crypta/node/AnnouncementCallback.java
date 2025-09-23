package network.crypta.node;

/** Callback for a local announcement. */
public interface AnnouncementCallback {

  void completed();

  void bogusNoderef(String reason);

  void nodeFailed(PeerNode pn, String reason);

  /* RNF */
  void noMoreNodes();

  void addedNode(PeerNode pn);

  void nodeNotWanted();

  /** Node valid but locally not added e.g. because we already have it */
  void nodeNotAdded();

  void acceptedSomewhere();

  /** Relayed a valid noderef to the (downstream) node which started the announcement */
  void relayedNoderef();
}
