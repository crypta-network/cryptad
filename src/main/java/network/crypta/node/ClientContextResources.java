package network.crypta.node;

import network.crypta.client.ArchiveManager;
import network.crypta.client.async.HealingQueue;

/** Bundles resources required to initialize a {@link network.crypta.client.async.ClientContext}. */
public final class ClientContextResources {
  private final ArchiveManager archiveManager;
  private final HealingQueue healingQueue;

  public ClientContextResources(ArchiveManager archiveManager, HealingQueue healingQueue) {
    this.archiveManager = archiveManager;
    this.healingQueue = healingQueue;
  }

  public ArchiveManager getArchiveManager() {
    return archiveManager;
  }

  public HealingQueue getHealingQueue() {
    return healingQueue;
  }
}
