package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ServerSideFCPMessageHandler;
import network.crypta.support.JarClassLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PluginInfoWrapperTest {

  @TempDir Path tempDir;

  private static final String SHUTDOWN_JAR = "Shutdown.jar";

  @Test
  void constructor_whenNonConfigurablePlugin_expectNullConfigToadletAndFlagsFalse()
      throws Exception {
    // Arrange
    FredPlugin plugin = new BasicPlugin();
    Node node = mockNode(false);

    // Act
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "ExamplePlugin.jar", false);

    // Assert
    assertFalse(wrapper.isConfigurablePlugin());
    assertNull(wrapper.getConfig());
    assertNull(wrapper.getSubConfig());
    assertNull(wrapper.getConfigToadlet());
    assertFalse(wrapper.isOfficialPlugin());
    assertEquals("ExamplePlugin.jar", wrapper.getFilename());
    assertEquals(BasicPlugin.class.getName(), wrapper.getPluginClassName());
  }

  @Test
  void constructor_whenConfigurablePlugin_expectConfigAndToadletCreated() throws Exception {
    // Arrange
    Node node = mockNode(true);
    FredPlugin plugin = new NoOpConfigurablePlugin();

    // Act
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "Configurable.jar", false);

    // Assert
    assertTrue(wrapper.isConfigurablePlugin());
    assertNotNull(wrapper.getConfig(), "Config should be constructed for configurable plugins");
    assertNotNull(
        wrapper.getSubConfig(), "SubConfig should be constructed for configurable plugins");
    assertNotNull(
        wrapper.getConfigToadlet(), "ConfigToadlet should be constructed for configurable plugins");
    assertTrue(wrapper.isL10nPlugin(), "Configurable plugins are also l10n plugins");
  }

  @Test
  void getPluginVersion_whenVersionedPlugin_expectReportedVersion() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin =
        mock(
            FredPlugin.class,
            org.mockito.Mockito.withSettings().extraInterfaces(FredPluginVersioned.class));
    when(((FredPluginVersioned) plugin).getVersion()).thenReturn("1.2.3");
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "Versioned.jar", false);

    // Act
    String version = wrapper.getPluginVersion();

    // Assert
    assertEquals("1.2.3", version);
  }

  @Test
  void getPluginVersion_whenNotVersionedPlugin_expectLocalizedNoVersionString() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin = new BasicPlugin();
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "NotVersioned.jar", false);
    String expected = NodeL10n.getBase().getString("PproxyToadlet.noVersion");

    // Act
    String version = wrapper.getPluginVersion();

    // Assert
    assertEquals(expected, version);
  }

  @Test
  void getPluginLongVersion_whenRealVersionedPlugin_expectReportedLongVersion() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin =
        mock(
            FredPlugin.class,
            org.mockito.Mockito.withSettings().extraInterfaces(FredPluginRealVersioned.class));
    when(((FredPluginRealVersioned) plugin).getRealVersion()).thenReturn(42L);
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "RealVersioned.jar", false);

    // Act
    long version = wrapper.getPluginLongVersion();

    // Assert
    assertEquals(42L, version);
  }

  @Test
  void getPluginLongVersion_whenNotRealVersionedPlugin_expectMinusOne() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin = new BasicPlugin();
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "NotRealVersioned.jar", false);

    // Act
    long version = wrapper.getPluginLongVersion();

    // Assert
    assertEquals(-1L, version);
  }

  @Test
  void constructor_whenPluginImplementsCapabilities_expectFlagsTrue() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin =
        mock(
            FredPlugin.class,
            org.mockito.Mockito.withSettings()
                .extraInterfaces(
                    FredPluginBandwidthIndicator.class,
                    FredPluginHTTP.class,
                    FredPluginThreadless.class,
                    FredPluginIPDetector.class,
                    FredPluginPortForward.class,
                    FredPluginMultiple.class,
                    ServerSideFCPMessageHandler.class,
                    FredPluginThemed.class,
                    FredPluginL10n.class,
                    FredPluginBaseL10n.class));

    // Act
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "Capabilities.jar", false);

    // Assert
    assertTrue(wrapper.isBandwidthIndicator());
    assertTrue(wrapper.isPproxyPlugin());
    assertTrue(wrapper.isThreadlessPlugin());
    assertTrue(wrapper.isIPDetectorPlugin());
    assertTrue(wrapper.isPortForwardPlugin());
    assertTrue(wrapper.isMultiplePlugin());
    assertTrue(wrapper.isFCPServerPlugin());
    assertTrue(wrapper.isThemedPlugin());
    assertTrue(wrapper.isL10nPlugin());
    assertTrue(wrapper.isBaseL10nPlugin());
    assertFalse(wrapper.isConfigurablePlugin());
  }

  @Test
  void getFCPServerPlugin_whenFcpServerPlugin_expectSameInstanceReturned() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin =
        mock(
            FredPlugin.class,
            org.mockito.Mockito.withSettings().extraInterfaces(ServerSideFCPMessageHandler.class));
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "FcpServer.jar", false);

    // Act
    ServerSideFCPMessageHandler handler = wrapper.getFCPServerPlugin();

    // Assert
    assertTrue(wrapper.isFCPServerPlugin());
    assertEquals(plugin, handler);
  }

  @Test
  void getFCPServerPlugin_whenNotFcpServerPlugin_expectClassCastException() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin = new BasicPlugin();
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "NotFcpServer.jar", false);

    // Act + Assert
    assertThrows(ClassCastException.class, wrapper::getFCPServerPlugin);
  }

  @Test
  void setThread_whenCalled_expectThreadRenamedToWrapperThreadName() throws Exception {
    // Arrange
    Node node = mockNode(false);
    PluginInfoWrapper wrapper =
        new PluginInfoWrapper(node, new BasicPlugin(), "Threaded.jar", false);
    Thread pluginThread = new Thread(() -> {});

    // Act
    wrapper.setThread(pluginThread);

    // Assert
    assertEquals(wrapper.getThreadName(), pluginThread.getName());
  }

  @Test
  void setThread_whenCalledTwice_expectIllegalStateException() throws Exception {
    // Arrange
    Node node = mockNode(false);
    PluginInfoWrapper wrapper =
        new PluginInfoWrapper(node, new BasicPlugin(), "Threaded.jar", false);
    wrapper.setThread(new Thread(() -> {}));
    Thread secondThread = new Thread(() -> {});

    // Act + Assert
    assertThrows(IllegalStateException.class, () -> wrapper.setThread(secondThread));
  }

  @Test
  void getPluginToadletSymlinks_whenAddingAndRemoving_expectSetSemantics() throws Exception {
    // Arrange
    Node node = mockNode(false);
    PluginInfoWrapper wrapper =
        new PluginInfoWrapper(node, new BasicPlugin(), "Symlinks.jar", false);

    // Act + Assert
    assertTrue(wrapper.addPluginToadletSymlink("/a"));
    assertFalse(wrapper.addPluginToadletSymlink("/a"), "Duplicate symlink should not be added");
    assertTrue(wrapper.addPluginToadletSymlink("/b"));

    String[] links = wrapper.getPluginToadletSymlinks();
    Arrays.sort(links);
    assertArrayEquals(new String[] {"/a", "/b"}, links);

    assertTrue(wrapper.removePluginToadletSymlink("/a"));
    assertFalse(
        wrapper.removePluginToadletSymlink("/a"), "Removing absent symlink should be false");

    String[] remaining = wrapper.getPluginToadletSymlinks();
    Arrays.sort(remaining);
    assertArrayEquals(new String[] {"/b"}, remaining);
  }

  @Test
  void removePluginToadletSymlink_whenEmpty_expectFalse() throws Exception {
    // Arrange
    Node node = mockNode(false);
    PluginInfoWrapper wrapper =
        new PluginInfoWrapper(node, new BasicPlugin(), "Symlinks.jar", false);

    // Act
    boolean removed = wrapper.removePluginToadletSymlink("/missing");

    // Assert
    assertFalse(removed);
  }

  @Test
  void startShutdownPlugin_whenTerminateThrows_expectDoesNotPropagateAndRestoresContextClassLoader()
      throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin = mock(FredPlugin.class);
    PluginManager manager = mock(PluginManager.class);
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "ThrowsOnTerminate.jar", false);

    ClassLoader previousContextClassLoader = Thread.currentThread().getContextClassLoader();
    ClassLoader originalContextClassLoader = new ClassLoader(null) {};
    Thread.currentThread().setContextClassLoader(originalContextClassLoader);
    org.mockito.Mockito.doThrow(new RuntimeException("boom")).when(plugin).terminate();

    // Act
    try {
      wrapper.startShutdownPlugin(manager, false);

      // Assert
      verify(manager).unregisterPlugin(wrapper, plugin, false);
      verify(plugin).terminate();
      assertTrue(wrapper.isStopping());
      assertEquals(originalContextClassLoader, Thread.currentThread().getContextClassLoader());
    } finally {
      Thread.currentThread().setContextClassLoader(previousContextClassLoader);
    }
  }

  @Test
  void startShutdownPlugin_whenCalledTwice_expectUnregisterOnlyOnce() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin = mock(FredPlugin.class);
    PluginManager manager = mock(PluginManager.class);
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, SHUTDOWN_JAR, false);

    // Act
    wrapper.startShutdownPlugin(manager, false);
    wrapper.startShutdownPlugin(manager, false);

    // Assert
    verify(manager).unregisterPlugin(wrapper, plugin, false);
    verify(plugin, atLeastOnce()).terminate();
    assertTrue(wrapper.isStopping());
  }

  @Test
  void finishShutdownPlugin_whenThreadIgnoresInterruptAndTimesOut_expectFalse() throws Exception {
    // Arrange
    Node node = mockNode(false);
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, new BasicPlugin(), SHUTDOWN_JAR, false);
    AtomicBoolean running = new AtomicBoolean(true);
    Thread pluginThread =
        Thread.ofVirtual()
            .unstarted(
                () -> {
                  while (running.get()) {
                    // Intentionally ignore interrupts to simulate a misbehaving plugin thread.
                    boolean ignoredInterrupt = Thread.interrupted();
                    if (ignoredInterrupt) {
                      // Intentionally ignored: clear the interrupt status so the loop keeps
                      // running.
                      LockSupport.parkNanos(0L);
                    }
                    LockSupport.parkNanos(1_000_000_000L);
                  }
                });
    pluginThread.start();
    wrapper.setThread(pluginThread);

    // Act
    boolean success = wrapper.finishShutdownPlugin(mock(PluginManager.class), 1L, false);

    // Assert
    assertFalse(success);

    // Cleanup: stop the background thread deterministically.
    running.set(false);
    LockSupport.unpark(pluginThread);
    pluginThread.interrupt();
    pluginThread.join(5_000L);
  }

  @Test
  void finishShutdownPlugin_whenNoWaitRequested_expectTrueEvenIfThreadStillAlive()
      throws Exception {
    // Arrange
    Node node = mockNode(false);
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, new BasicPlugin(), SHUTDOWN_JAR, false);
    AtomicBoolean running = new AtomicBoolean(true);
    Thread pluginThread =
        Thread.ofVirtual()
            .unstarted(
                () -> {
                  while (running.get()) {
                    boolean ignoredInterrupt = Thread.interrupted();
                    if (ignoredInterrupt) {
                      // Intentionally ignored: clear the interrupt status so the loop keeps
                      // running.
                      LockSupport.parkNanos(0L);
                    }
                    LockSupport.parkNanos(1_000_000_000L);
                  }
                });
    pluginThread.start();
    wrapper.setThread(pluginThread);

    // Act
    boolean success = wrapper.finishShutdownPlugin(mock(PluginManager.class), -1L, false);

    // Assert
    assertTrue(success);

    // Cleanup
    running.set(false);
    LockSupport.unpark(pluginThread);
    pluginThread.interrupt();
    pluginThread.join(5_000L);
  }

  @Test
  void stopPlugin_whenCalled_expectAlwaysRemovesPlugin() throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin plugin = mock(FredPlugin.class);
    PluginManager manager = mock(PluginManager.class);
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "Stop.jar", false);

    // Act
    wrapper.stopPlugin(manager, -1L, false);

    // Assert
    verify(manager).unregisterPlugin(wrapper, plugin, false);
    verify(plugin).terminate();
    verify(manager).removePlugin(wrapper);
    assertTrue(wrapper.isStopping());
  }

  @Test
  void finishShutdownPlugin_whenPluginClassLoaderIsJarClassLoader_expectLoaderClosed()
      throws Exception {
    // Arrange
    Node node = mockNode(false);
    RecordingJarClassLoader loader =
        new RecordingJarClassLoader(createEmptyJar(tempDir.resolve("plugin.jar")).toFile());
    FredPlugin plugin =
        (FredPlugin)
            Proxy.newProxyInstance(
                loader,
                new Class<?>[] {FredPlugin.class},
                (_, method, _) -> {
                  if (method.getName().equals("terminate")) {
                    return null;
                  }
                  if (method.getName().equals("runPlugin")) {
                    return null;
                  }
                  throw new UnsupportedOperationException(method.getName());
                });

    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, plugin, "JarLoaded.jar", false);

    // Act
    boolean success = wrapper.finishShutdownPlugin(mock(PluginManager.class), -1L, false);

    // Assert
    assertTrue(success);
    assertTrue(loader.isClosed());
  }

  @Test
  void compareTo_whenDifferentPluginClassNames_expectSameOrderingAsClassToString()
      throws Exception {
    // Arrange
    Node node = mockNode(false);
    FredPlugin a = new BasicPlugin();
    FredPlugin b = new OtherBasicPlugin();
    PluginInfoWrapper wa = new PluginInfoWrapper(node, a, "A.jar", false);
    PluginInfoWrapper wb = new PluginInfoWrapper(node, b, "B.jar", false);
    int expected = a.getClass().toString().compareTo(b.getClass().toString());

    // Act
    int actual = wa.compareTo(wb);

    // Assert
    assertEquals(Integer.signum(expected), Integer.signum(actual));
  }

  @Test
  void getLocalisedPluginName_whenOfficial_expectDelegatesToPluginManager() throws Exception {
    // Arrange
    Node node = mockNode(false);
    String filename = "SomeOfficialPlugin";
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, new BasicPlugin(), filename, true);

    // Act
    String localised = wrapper.getLocalisedPluginName();

    // Assert
    assertEquals(PluginManager.getOfficialPluginLocalisedName(filename), localised);
  }

  @Test
  void getLocalisedPluginName_whenNotOfficial_expectReturnsFilename() throws Exception {
    // Arrange
    Node node = mockNode(false);
    String filename = "SomeThirdPartyPlugin";
    PluginInfoWrapper wrapper = new PluginInfoWrapper(node, new BasicPlugin(), filename, false);

    // Act
    String localised = wrapper.getLocalisedPluginName();

    // Assert
    assertEquals(filename, localised);
  }

  private Node mockNode(boolean needsCfgDir) {
    Node node = mock(Node.class);
    NodeClientCore core = mock(NodeClientCore.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);

    if (needsCfgDir) {
      when(node.getCfgDir()).thenReturn(tempDir.toFile());
    }
    when(node.getClientCore()).thenReturn(core);
    when(core.makeClient(anyShort(), anyBoolean(), anyBoolean())).thenReturn(client);
    when(core.getPluginStores()).thenReturn(mock(PluginStores.class));
    return node;
  }

  private static Path createEmptyJar(Path jarPath) throws IOException {
    Manifest manifest = new Manifest();
    try (OutputStream out = Files.newOutputStream(jarPath);
        JarOutputStream ignored = new JarOutputStream(out, manifest)) {
      // Intentionally empty: proxy classes are defined into the class loader directly.
      ignored.flush();
    }
    return jarPath;
  }

  private static final class BasicPlugin implements FredPlugin {
    @Override
    public void terminate() {
      // Intentionally empty: test stub plugin has no background work to shut down.
    }

    @Override
    public void runPlugin(PluginRespirator pr) {
      // Intentionally empty: test stub plugin does not start threads or register callbacks.
    }
  }

  private static final class OtherBasicPlugin implements FredPlugin {
    @Override
    public void terminate() {
      // Intentionally empty: test stub plugin has no background work to shut down.
    }

    @Override
    public void runPlugin(PluginRespirator pr) {
      // Intentionally empty: test stub plugin does not start threads or register callbacks.
    }
  }

  private static final class NoOpConfigurablePlugin implements FredPlugin, FredPluginConfigurable {
    @Override
    public void setupConfig(network.crypta.config.SubConfig subconfig) {
      // no-op: registration not required for PluginInfoWrapper constructor to complete.
    }

    @Override
    public String getString(String key) {
      return key;
    }

    @Override
    public void setLanguage(network.crypta.l10n.BaseL10n.LANGUAGE newLanguage) {
      // no-op
    }

    @Override
    public void terminate() {
      // Intentionally empty: test stub plugin has no background work to shut down.
    }

    @Override
    public void runPlugin(PluginRespirator pr) {
      // Intentionally empty: test stub plugin does not start threads or register callbacks.
    }
  }

  private static final class RecordingJarClassLoader extends JarClassLoader {
    private volatile boolean closed = false;

    private RecordingJarClassLoader(java.io.File jar) throws IOException {
      super(jar);
    }

    @Override
    public void close() throws IOException {
      closed = true;
      super.close();
    }

    private boolean isClosed() {
      return closed;
    }
  }
}
