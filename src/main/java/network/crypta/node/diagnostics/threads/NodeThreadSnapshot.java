package network.crypta.node.diagnostics.threads;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper class to contain a list of NodeThreadInfos.
 */
public record NodeThreadSnapshot(List<NodeThreadInfo> threads, int interval) {
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
    @Override
    public List<NodeThreadInfo> threads() {
        return new ArrayList<>(threads);
    }

    /**
     * @return Snapshot interval.
     */
    @Override
    public int interval() {
        return interval;
    }
}
