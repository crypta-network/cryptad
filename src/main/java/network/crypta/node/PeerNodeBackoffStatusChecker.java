package network.crypta.node;

import java.lang.ref.WeakReference;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

record PeerNodeBackoffStatusChecker(WeakReference<PeerNode> ref) implements Runnable {
    private static volatile boolean logMINOR;

    static {
        Logger.registerLogThresholdCallback(
                new LogThresholdCallback() {
                    @Override
                    public void shouldUpdate() {
                        logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
                    }
                });
    }

    @Override
    public void run() {
        PeerNode pn = ref.get();
        if (pn == null) return;
        if (pn.cachedRemoved()) {
            if (logMINOR && pn.node.getPeers().havePeer(pn)) {
                Logger.error(this, "Removed flag is set yet is in peers table?!: " + pn);
            } else {
                return;
            }
        }
        if (!pn.node.getPeers().havePeer(pn)) {
            if (!pn.cachedRemoved())
                Logger.error(this, "Not in peers table but not flagged as removed: " + pn);
            return;
        }
        pn.setPeerNodeStatus(System.currentTimeMillis(), true);
    }
}
