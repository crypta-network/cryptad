package network.crypta.node.runtime;

import java.io.File;
import java.util.Random;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;

/** Bridges the current node/core implementation into the JDK-only runtime SPI. */
public final class LegacyRuntimePorts implements RuntimePorts {
  private final Node node;
  private final NodeClientCore core;
  private final ExecutionPort executionPort;
  private final RandomnessPort randomnessPort;
  private final TransferAccessPort transferAccessPort;
  private final LifecyclePort lifecyclePort;

  public LegacyRuntimePorts(Node node, NodeClientCore core) {
    this.node = node;
    this.core = core;
    this.executionPort =
        (task, name) -> LegacyRuntimePorts.this.node.network().executor().execute(task, name);
    this.randomnessPort =
        new RandomnessPort() {
          @Override
          public void fillSecureRandom(byte[] target) {
            LegacyRuntimePorts.this.node.bootstrap().random().nextBytes(target);
          }

          @Override
          public Random fastWeakRandom() {
            return LegacyRuntimePorts.this.node.bootstrap().fastWeakRandom();
          }
        };
    this.transferAccessPort =
        new TransferAccessPort() {
          @Override
          public boolean allowUploadFrom(File file) {
            return LegacyRuntimePorts.this.core.allowUploadFrom(file);
          }

          @Override
          public boolean allowDownloadTo(File file) {
            return LegacyRuntimePorts.this.core.allowDownloadTo(file);
          }

          @Override
          public File downloadsDir() {
            return LegacyRuntimePorts.this.core.getDownloadsDir();
          }

          @Override
          public File persistentTempDir() {
            return LegacyRuntimePorts.this.core.getPersistentTempDir();
          }

          @Override
          public File[] allowedUploadDirs() {
            return LegacyRuntimePorts.this.core.getAllowedUploadDirs();
          }

          @Override
          public File[] allowedDownloadDirs() {
            return LegacyRuntimePorts.this.core.getAllowedDownloadDirs();
          }
        };
    this.lifecyclePort =
        new LifecyclePort() {
          @Override
          public boolean hasStarted() {
            return LegacyRuntimePorts.this.node.isHasStarted();
          }

          @Override
          public boolean isStopping() {
            return LegacyRuntimePorts.this.node.isStopping();
          }

          @Override
          public long startupTimeMillis() {
            return LegacyRuntimePorts.this.node.getStartupTime();
          }
        };
  }

  @Override
  public ExecutionPort execution() {
    return executionPort;
  }

  @Override
  public RandomnessPort randomness() {
    return randomnessPort;
  }

  @Override
  public TransferAccessPort transferAccess() {
    return transferAccessPort;
  }

  @Override
  public LifecyclePort lifecycle() {
    return lifecyclePort;
  }
}
