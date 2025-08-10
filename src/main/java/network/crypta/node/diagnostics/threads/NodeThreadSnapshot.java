package network.crypta.node.diagnostics.threads;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper class to contain a list of NodeThreadInfos.
 */
public class NodeThreadSnapshot {
    private final List<NodeThreadInfo> threads;
    private final int interval;

    /**
     * @param threads List of threads for this snapshot.
     */
    public NodeThreadSnapshot(List<NodeThreadInfo> threads, int interval) {
        this.threads = new ArrayList<>(threads);
        this.interval = interval;
    }

    /**
     * @return The snapshot's thread list.
     */
    public List<NodeThreadInfo> getThreads() {
        return new ArrayList<>(threads);
    }

    /**
     * @return Snapshot interval.
     */
    public int getInterval() {
        return interval;
    }
}
