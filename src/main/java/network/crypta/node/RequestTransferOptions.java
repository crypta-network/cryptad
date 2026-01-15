package network.crypta.node;

/**
 * Options that influence transfer estimates while counting requests.
 *
 * @param transfersPerInsert average outgoing transfers assumed per insert
 * @param ignoreLocalVsRemote whether to treat local requests as remote for estimation
 */
public record RequestTransferOptions(int transfersPerInsert, boolean ignoreLocalVsRemote) {}
