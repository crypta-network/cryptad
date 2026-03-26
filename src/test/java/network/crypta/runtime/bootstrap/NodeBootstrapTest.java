package network.crypta.runtime.bootstrap;

import java.util.Random;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.StartupToadlet;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.fs.AppDirs;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeBootstrapTest {
  private static final String SERVICE_MODE_PROPERTY = "cryptad.service.mode";

  @Test
  void logStartupInfo_whenCalled_expectNoException() {
    NodeBootstrap bootstrap = new NodeBootstrap(mock(Node.class));

    assertDoesNotThrow(bootstrap::logStartupInfo);
  }

  @Test
  void setupProgramDirectories_whenUserMode_expectAppDefaults() throws NodeInitException {
    String previousMode = System.getProperty(SERVICE_MODE_PROPERTY);
    System.setProperty(SERVICE_MODE_PROPERTY, "user");
    try {
      Node node = mock(Node.class);
      SubConfig installConfig = mock(SubConfig.class);
      ProgramDirectory userDir = mock(ProgramDirectory.class);
      ProgramDirectory cfgDir = mock(ProgramDirectory.class);
      ProgramDirectory nodeDir = mock(ProgramDirectory.class);
      ProgramDirectory runDir = mock(ProgramDirectory.class);
      Resolved resolved = new AppDirs().resolve();

      when(node.setupProgramDir(
              installConfig,
              "userDir",
              resolved.configDir().toString(),
              "Node.userDir",
              "Node.userDirLong"))
          .thenReturn(userDir);
      when(node.setupProgramDir(
              installConfig,
              "cfgDir",
              resolved.configDir().toString(),
              "Node.cfgDir",
              "Node.cfgDirLong"))
          .thenReturn(cfgDir);
      when(node.setupProgramDir(
              installConfig,
              "nodeDir",
              resolved.dataDir().resolve("node").toString(),
              "Node.nodeDir",
              "Node.nodeDirLong"))
          .thenReturn(nodeDir);
      when(node.setupProgramDir(
              installConfig,
              "runDir",
              resolved.runDir().toString(),
              "Node.runDir",
              "Node.runDirLong"))
          .thenReturn(runDir);
      NodeBootstrap bootstrap = new NodeBootstrap(node);
      NodeBootstrap.NodeProgramDirs dirs = bootstrap.setupProgramDirectories(installConfig);

      assertSame(userDir, dirs.userDir());
      assertSame(cfgDir, dirs.cfgDir());
      assertSame(nodeDir, dirs.nodeDir());
      assertSame(runDir, dirs.runDir());

      InOrder order = inOrder(node);
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "userDir",
              resolved.configDir().toString(),
              "Node.userDir",
              "Node.userDirLong");
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "cfgDir",
              resolved.configDir().toString(),
              "Node.cfgDir",
              "Node.cfgDirLong");
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "nodeDir",
              resolved.dataDir().resolve("node").toString(),
              "Node.nodeDir",
              "Node.nodeDirLong");
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "runDir",
              resolved.runDir().toString(),
              "Node.runDir",
              "Node.runDirLong");
      verifyNoMoreInteractions(node);
    } finally {
      resetServiceMode(previousMode);
    }
  }

  @Test
  void setupProgramDirectories_whenServiceMode_expectServiceDefaults() throws NodeInitException {
    String previousMode = System.getProperty(SERVICE_MODE_PROPERTY);
    System.setProperty(SERVICE_MODE_PROPERTY, "service");
    try {
      Node node = mock(Node.class);
      SubConfig installConfig = mock(SubConfig.class);
      ProgramDirectory userDir = mock(ProgramDirectory.class);
      ProgramDirectory cfgDir = mock(ProgramDirectory.class);
      ProgramDirectory nodeDir = mock(ProgramDirectory.class);
      ProgramDirectory runDir = mock(ProgramDirectory.class);
      Resolved resolved = new ServiceDirs().resolve();

      when(node.setupProgramDir(
              installConfig,
              "userDir",
              resolved.configDir().toString(),
              "Node.userDir",
              "Node.userDirLong"))
          .thenReturn(userDir);
      when(node.setupProgramDir(
              installConfig,
              "cfgDir",
              resolved.configDir().toString(),
              "Node.cfgDir",
              "Node.cfgDirLong"))
          .thenReturn(cfgDir);
      when(node.setupProgramDir(
              installConfig,
              "nodeDir",
              resolved.dataDir().resolve("node").toString(),
              "Node.nodeDir",
              "Node.nodeDirLong"))
          .thenReturn(nodeDir);
      when(node.setupProgramDir(
              installConfig,
              "runDir",
              resolved.runDir().toString(),
              "Node.runDir",
              "Node.runDirLong"))
          .thenReturn(runDir);
      NodeBootstrap bootstrap = new NodeBootstrap(node);
      NodeBootstrap.NodeProgramDirs dirs = bootstrap.setupProgramDirectories(installConfig);

      assertSame(userDir, dirs.userDir());
      assertSame(cfgDir, dirs.cfgDir());
      assertSame(nodeDir, dirs.nodeDir());
      assertSame(runDir, dirs.runDir());

      InOrder order = inOrder(node);
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "userDir",
              resolved.configDir().toString(),
              "Node.userDir",
              "Node.userDirLong");
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "cfgDir",
              resolved.configDir().toString(),
              "Node.cfgDir",
              "Node.cfgDirLong");
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "nodeDir",
              resolved.dataDir().resolve("node").toString(),
              "Node.nodeDir",
              "Node.nodeDirLong");
      order
          .verify(node)
          .setupProgramDir(
              installConfig,
              "runDir",
              resolved.runDir().toString(),
              "Node.runDir",
              "Node.runDirLong");
      verifyNoMoreInteractions(node);
    } finally {
      resetServiceMode(previousMode);
    }
  }

  @Test
  void createEntropyGatheringThread_whenCalled_expectNamedThread() {
    NodeBootstrap bootstrap = new NodeBootstrap(mock(Node.class));

    NativeThread thread = bootstrap.createEntropyGatheringThread();

    assertNotNull(thread);
    assertSame(NativeThread.class, thread.getClass());
    assertEquals("Entropy Gathering Thread", thread.getName());
  }

  @Test
  void setupRandomSources_whenProvidedRandoms_expectFieldsAndStartupNotified() {
    NodeBootstrap bootstrap = new NodeBootstrap(mock(Node.class));
    RandomSource randomSource = mock(RandomSource.class);
    RandomSource weakRandom = mock(RandomSource.class);
    SimpleToadletServer toadletServer = mock(SimpleToadletServer.class);
    StartupToadlet startupToadlet = mock(StartupToadlet.class);
    NativeThread entropyThread = mock(NativeThread.class);
    ProgramDirectory userDir = mock(ProgramDirectory.class);

    when(toadletServer.getStartupToadlet()).thenReturn(startupToadlet);

    bootstrap.setupRandomSources(randomSource, weakRandom, toadletServer, entropyThread, userDir);

    assertSame(randomSource, bootstrap.random());
    assertSame(NodeStarter.getGlobalSecureRandom(), bootstrap.secureRandom());
    assertSame(weakRandom, bootstrap.fastWeakRandom());
    assertTrue(bootstrap.isPrngReady());
    verify(startupToadlet).setIsPRNGReady();
    verify(entropyThread, never()).start();
  }

  @Test
  void setupRandomSources_whenWeakRandomNull_expectCreateRandomUsed() {
    NodeBootstrap bootstrap = new NodeBootstrap(mock(Node.class));
    NodeBootstrap spyBootstrap = org.mockito.Mockito.spy(bootstrap);
    RandomSource randomSource = mock(RandomSource.class);
    Random fallbackRandom = new Random(7);
    SimpleToadletServer toadletServer = mock(SimpleToadletServer.class);
    StartupToadlet startupToadlet = mock(StartupToadlet.class);
    NativeThread entropyThread = mock(NativeThread.class);
    ProgramDirectory userDir = mock(ProgramDirectory.class);

    when(toadletServer.getStartupToadlet()).thenReturn(startupToadlet);
    doReturn(fallbackRandom).when(spyBootstrap).createRandom();

    spyBootstrap.setupRandomSources(randomSource, null, toadletServer, entropyThread, userDir);

    verify(spyBootstrap).createRandom();
    assertSame(fallbackRandom, spyBootstrap.fastWeakRandom());
    verify(startupToadlet).setIsPRNGReady();
    verify(entropyThread, never()).start();
  }

  @Test
  void createRandom_whenCalled_expectNewRandomInstance() {
    NodeBootstrap bootstrap = new NodeBootstrap(mock(Node.class));

    Random first = bootstrap.createRandom();
    Random second = bootstrap.createRandom();

    assertNotNull(first);
    assertNotNull(second);
    assertNotSame(first, second);
  }

  @Test
  void markPrngReady_whenCalled_expectFlagTrue() {
    NodeBootstrap bootstrap = new NodeBootstrap(mock(Node.class));

    assertFalse(bootstrap.isPrngReady());

    bootstrap.markPrngReady();

    assertTrue(bootstrap.isPrngReady());
  }

  private static void resetServiceMode(String previousMode) {
    if (previousMode == null) {
      System.clearProperty(SERVICE_MODE_PROPERTY);
    } else {
      System.setProperty(SERVICE_MODE_PROPERTY, previousMode);
    }
  }
}
