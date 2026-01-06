package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.StringCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // JUnit-style names: method_whenCondition_expectOutcome
class PluginManagerTest {

  @TempDir Path tempDir;

  private static final String PLUGINS_TEMP_DIR = "plugins";
  private static final String OFFICIAL_PLUGIN_HELLO_WORLD = "HelloWorld";
  private static final String FPROXY_SUBCONFIG = "fproxy";
  private static final String FPROXY_CSS_OPTION = "css";
  private static final String THEME_CRYPTAFORGE = "cryptaforge";
  private static final String FPROXY_CSS_SHORT_DESC = "fproxy.css";
  private static final String FPROXY_CSS_LONG_DESC = "fproxy.cssLong";

  @Test
  void isOfficialPlugin_whenNullOrBlank_expectNull() {
    PluginManager pluginManager = newPluginManagerWithRealConfig();

    assertNull(pluginManager.isOfficialPlugin(null));
    assertNull(pluginManager.isOfficialPlugin(""));
    assertNull(pluginManager.isOfficialPlugin("   "));
  }

  @Test
  void isOfficialPlugin_whenKnownPlugin_expectDescription() {
    PluginManager pluginManager = newPluginManagerWithRealConfig();

    OfficialPluginDescription desc = pluginManager.isOfficialPlugin(OFFICIAL_PLUGIN_HELLO_WORLD);

    assertNotNull(desc);
    assertEquals(OFFICIAL_PLUGIN_HELLO_WORLD, desc.name);
  }

  @Test
  void findAvailablePlugins_whenCalled_expectContainsKnownPlugin() {
    PluginManager pluginManager = newPluginManagerWithRealConfig();

    List<OfficialPluginDescription> plugins = pluginManager.findAvailablePlugins();

    Optional<OfficialPluginDescription> helloWorld =
        plugins.stream().filter(p -> OFFICIAL_PLUGIN_HELLO_WORLD.equals(p.name)).findFirst();
    assertTrue(helloWorld.isPresent());
  }

  @Test
  void getPluginFilename_whenPluginDirIsFile_expectNull() throws IOException {
    Path pluginDirFile = Files.createFile(tempDir.resolve("not-a-dir"));
    PluginManager pluginManager = newPluginManagerWithRealConfig(pluginDirFile.toFile());

    assertNull(pluginManager.getPluginFilename("Example"));
  }

  @Test
  void getPluginFilename_whenPluginDirMissing_expectCreatesDirAndReturnsJarPath() {
    File pluginDir = tempDir.resolve("plugins-missing").toFile();
    PluginManager pluginManager = newPluginManagerWithRealConfig(pluginDir);

    File jarPath = pluginManager.getPluginFilename("Example");

    assertNotNull(jarPath);
    assertTrue(pluginDir.isDirectory());
    assertEquals(new File(pluginDir, "Example.jar"), jarPath);
  }

  @Test
  void removeCachedCopy_whenNull_expectNoThrowAndNoDeletion() throws IOException {
    File pluginDir = tempDir.resolve(PLUGINS_TEMP_DIR).toFile();
    assertTrue(pluginDir.mkdirs());
    Path keepFile = Files.createFile(pluginDir.toPath().resolve("KeepMe.jar"));
    PluginManager pluginManager = newPluginManagerWithRealConfig();

    assertDoesNotThrow(() -> pluginManager.removeCachedCopy(null));
    assertTrue(Files.exists(keepFile));
  }

  @Test
  void removeCachedCopy_whenNameWithoutExtension_expectDeletesMatchingCachedFiles()
      throws IOException {
    File pluginDir = tempDir.resolve(PLUGINS_TEMP_DIR).toFile();
    assertTrue(pluginDir.mkdirs());
    Path base = Files.createFile(pluginDir.toPath().resolve("MyPlugin.jar"));
    Path v1 = Files.createFile(pluginDir.toPath().resolve("MyPlugin.jar-1"));
    Path v2 = Files.createFile(pluginDir.toPath().resolve("MyPlugin.jar-2"));
    Path other = Files.createFile(pluginDir.toPath().resolve("MyPlugin-Other.jar"));
    PluginManager pluginManager = newPluginManagerWithRealConfig(pluginDir);

    pluginManager.removeCachedCopy("MyPlugin");

    assertTrue(Files.notExists(base));
    assertTrue(Files.notExists(v1));
    assertTrue(Files.notExists(v2));
    assertTrue(Files.exists(other));
  }

  @Test
  void removeCachedCopy_whenSpecificationContainsUnixPath_expectDeletesBasedOnBasename()
      throws IOException {
    File pluginDir = tempDir.resolve(PLUGINS_TEMP_DIR).toFile();
    assertTrue(pluginDir.mkdirs());
    Path base = Files.createFile(pluginDir.toPath().resolve("PathPlugin.jar"));
    Path v1 = Files.createFile(pluginDir.toPath().resolve("PathPlugin.jar-99"));
    PluginManager pluginManager = newPluginManagerWithRealConfig(pluginDir);

    pluginManager.removeCachedCopy("/some/path/PathPlugin.jar");

    assertTrue(Files.notExists(base));
    assertTrue(Files.notExists(v1));
  }

  @Test
  void removeCachedCopy_whenSpecificationContainsWindowsPath_expectDeletesBasedOnBasename()
      throws IOException {
    File pluginDir = tempDir.resolve(PLUGINS_TEMP_DIR).toFile();
    assertTrue(pluginDir.mkdirs());
    Path base = Files.createFile(pluginDir.toPath().resolve("WinPlugin.jar"));
    Path v1 = Files.createFile(pluginDir.toPath().resolve("WinPlugin.jar-123"));
    PluginManager pluginManager = newPluginManagerWithRealConfig(pluginDir);

    pluginManager.removeCachedCopy("C:\\\\plugins\\\\WinPlugin.jar");

    assertTrue(Files.notExists(base));
    assertTrue(Files.notExists(v1));
  }

  @Test
  void startPluginAuto_whenOfficialPluginName_expectRoutesToOfficial() {
    TestablePluginManager pluginManager = newTestablePluginManagerWithRealConfig();

    pluginManager.startPluginAuto(OFFICIAL_PLUGIN_HELLO_WORLD, false);

    assertEquals(TestablePluginManager.Call.OFFICIAL, pluginManager.lastCall);
    assertEquals(OFFICIAL_PLUGIN_HELLO_WORLD, pluginManager.lastName);
    assertFalse(pluginManager.lastStore);
  }

  @Test
  void startPluginAuto_whenFreenetUri_expectRoutesToFreenet() {
    TestablePluginManager pluginManager = newTestablePluginManagerWithRealConfig();

    String chk =
        "CHK@r3SXUzFR-CjBjck0ZxoZ9mIUzGhSMq6Ap471njwvhAU,"
            + "V0cQ6eJcCf-~XTwLvtgC2klbUx8CWFZoELM2RmEjSJo,"
            + "AAMC--8/plugin-HelloWorld.jar";
    pluginManager.startPluginAuto(chk, true);

    assertEquals(TestablePluginManager.Call.FREENET, pluginManager.lastCall);
    assertEquals(chk, pluginManager.lastName);
    assertTrue(pluginManager.lastStore);
  }

  @Test
  void startPluginAuto_whenExistingAbsoluteFilePath_expectRoutesToFile() throws IOException {
    Path pluginJar = Files.createFile(tempDir.resolve("LocalPlugin.jar"));
    TestablePluginManager pluginManager = newTestablePluginManagerWithRealConfig();

    pluginManager.startPluginAuto(pluginJar.toAbsolutePath().toString(), false);

    assertEquals(TestablePluginManager.Call.FILE, pluginManager.lastCall);
    assertEquals(pluginJar.toAbsolutePath().toString(), pluginManager.lastName);
  }

  @Test
  void startPluginAuto_whenNotOfficialNotFreenetNotFile_expectRoutesToUrl() {
    TestablePluginManager pluginManager = newTestablePluginManagerWithRealConfig();

    pluginManager.startPluginAuto("https://example.invalid/plugin.jar", true);

    assertEquals(TestablePluginManager.Call.URL, pluginManager.lastCall);
    assertEquals("https://example.invalid/plugin.jar", pluginManager.lastName);
    assertTrue(pluginManager.lastStore);
  }

  @Test
  void startPluginUrl_whenPluginsDisabled_expectIllegalStateException() {
    PluginManager pluginManager = newPluginManagerWithDisabledPluginsConfig();

    IllegalStateException exception =
        assertThrows(
            IllegalStateException.class,
            () -> pluginManager.startPluginURL("https://example.invalid/p.jar", false));
    assertEquals("Plugins disabled", exception.getMessage());
  }

  @Test
  void loadPluginFromJarFile_whenPluginLoads_expectClassLoaderRemainsUsable() throws Exception {
    PluginManager pluginManager = newPluginManagerWithRealConfig();
    Path pluginJar = buildTestPluginJar(tempDir.resolve("test-plugin.jar"));

    var method =
        PluginManager.class.getDeclaredMethod(
            "loadPluginFromJarFile", String.class, File.class, String.class, boolean.class);
    method.setAccessible(true);

    FredPlugin plugin =
        (FredPlugin)
            method.invoke(
                pluginManager, "TestPlugin", pluginJar.toFile(), "testplugin.Main", false);

    ClassLoader pluginLoader = plugin.getClass().getClassLoader();

    assertDoesNotThrow(
        () -> {
          try {
            pluginLoader.loadClass("testplugin.Helper");
          } catch (ClassNotFoundException e) {
            throw new AssertionError(e);
          }
        });
    assertNotNull(pluginLoader.getResource("testplugin/resource.txt"));
  }

  private static Path buildTestPluginJar(Path jarPath) throws IOException {
    Path workDir = jarPath.getParent().resolve("test-plugin-work");
    Path srcDir = workDir.resolve("src");
    Path classesDir = workDir.resolve("classes");
    Files.createDirectories(srcDir);
    Files.createDirectories(classesDir);

    Path mainJava = srcDir.resolve("Main.java");
    Path helperJava = srcDir.resolve("Helper.java");

    Files.writeString(
        mainJava,
        """
        package testplugin;

        import network.crypta.pluginmanager.FredPlugin;
        import network.crypta.pluginmanager.PluginRespirator;

        public final class Main implements FredPlugin {
          @Override
          public void terminate() {}

          @Override
          public void runPlugin(PluginRespirator pr) {
            // Intentionally empty; this plugin is used only for loader lifetime tests.
          }
        }
        """);
    Files.writeString(
        helperJava,
        """
        package testplugin;

        public final class Helper {
          public static String hi() {
            return "hi";
          }
        }
        """);

    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler, "JDK compiler not available (are tests running on a JRE?)");

    List<String> options = new ArrayList<>();
    options.add("--release");
    options.add("21");
    options.add("-classpath");
    options.add(System.getProperty("java.class.path"));
    options.add("-d");
    options.add(classesDir.toString());

    try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
      Iterable<? extends JavaFileObject> sources =
          fileManager.getJavaFileObjectsFromFiles(List.of(mainJava.toFile(), helperJava.toFile()));
      boolean ok =
          Boolean.TRUE.equals(
              compiler.getTask(null, fileManager, null, options, null, sources).call());
      assertTrue(ok, "Failed to compile test plugin sources");
    }

    Files.createDirectories(jarPath.getParent());

    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Plugin-Main-Class", "testplugin.Main");

    try (JarOutputStream jarOut = new JarOutputStream(Files.newOutputStream(jarPath), manifest)) {
      try (var paths = Files.walk(classesDir)) {
        paths
            .filter(
                path ->
                    Files.isRegularFile(path) && path.getFileName().toString().endsWith(".class"))
            .forEach(
                path -> {
                  String entryName =
                      classesDir.relativize(path).toString().replace(File.separatorChar, '/');
                  try {
                    jarOut.putNextEntry(new JarEntry(entryName));
                    jarOut.write(Files.readAllBytes(path));
                    jarOut.closeEntry();
                  } catch (IOException e) {
                    throw new UncheckedIOException(e);
                  }
                });
      }

      jarOut.putNextEntry(new JarEntry("testplugin/resource.txt"));
      jarOut.write("ok\n".getBytes());
      jarOut.closeEntry();
    } catch (UncheckedIOException e) {
      throw e.getCause();
    }

    return jarPath;
  }

  private PluginManager newPluginManagerWithRealConfig() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    PersistentConfig config = new PersistentConfig(null);
    SubConfig fproxy = config.createSubConfig(FPROXY_SUBCONFIG);
    fproxy.register(
        FPROXY_CSS_OPTION,
        THEME_CRYPTAFORGE,
        0,
        true,
        true,
        FPROXY_CSS_SHORT_DESC,
        FPROXY_CSS_LONG_DESC,
        (StringCallback) null);
    fproxy.finishedInitialization();
    when(node.getConfig()).thenReturn(config);

    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.makeClient(PluginManager.PRIO, true, false))
        .thenReturn(mock(HighLevelSimpleClient.class));

    when(node.getExecutor()).thenReturn(new InlinePriorityAwareExecutor());

    return new PluginManager(node, /* lastVersion= */ Integer.MAX_VALUE);
  }

  private PluginManager newPluginManagerWithRealConfig(File pluginDir) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.getPluginDir()).thenReturn(pluginDir);

    PersistentConfig config = new PersistentConfig(null);
    SubConfig fproxy = config.createSubConfig(FPROXY_SUBCONFIG);
    fproxy.register(
        FPROXY_CSS_OPTION,
        THEME_CRYPTAFORGE,
        0,
        true,
        true,
        FPROXY_CSS_SHORT_DESC,
        FPROXY_CSS_LONG_DESC,
        (StringCallback) null);
    fproxy.finishedInitialization();
    when(node.getConfig()).thenReturn(config);

    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.makeClient(PluginManager.PRIO, true, false))
        .thenReturn(mock(HighLevelSimpleClient.class));

    when(node.getExecutor()).thenReturn(new InlinePriorityAwareExecutor());

    return new PluginManager(node, /* lastVersion= */ Integer.MAX_VALUE);
  }

  private TestablePluginManager newTestablePluginManagerWithRealConfig() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    PersistentConfig config = new PersistentConfig(null);
    SubConfig fproxy = config.createSubConfig(FPROXY_SUBCONFIG);
    fproxy.register(
        FPROXY_CSS_OPTION,
        THEME_CRYPTAFORGE,
        0,
        true,
        true,
        FPROXY_CSS_SHORT_DESC,
        FPROXY_CSS_LONG_DESC,
        (StringCallback) null);
    fproxy.finishedInitialization();
    when(node.getConfig()).thenReturn(config);

    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.makeClient(PluginManager.PRIO, true, false))
        .thenReturn(mock(HighLevelSimpleClient.class));

    when(node.getExecutor()).thenReturn(new InlinePriorityAwareExecutor());

    return new TestablePluginManager(node);
  }

  private PluginManager newPluginManagerWithDisabledPluginsConfig() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    SubConfig pluginManagerConfig = mock(SubConfig.class);
    when(pluginManagerConfig.getBoolean("enabled")).thenReturn(false);
    when(pluginManagerConfig.getStringArr("loadplugin")).thenReturn(new String[0]);

    SubConfig fproxy = mock(SubConfig.class);
    when(fproxy.getString(FPROXY_CSS_OPTION)).thenReturn(THEME_CRYPTAFORGE);

    PersistentConfig config = mock(PersistentConfig.class);
    when(config.createSubConfig("pluginmanager")).thenReturn(pluginManagerConfig);
    when(config.get(FPROXY_SUBCONFIG)).thenReturn(fproxy);
    when(node.getConfig()).thenReturn(config);

    NodeClientCore core = mock(NodeClientCore.class);
    when(node.services().clientCore()).thenReturn(core);
    when(core.makeClient(PluginManager.PRIO, true, false))
        .thenReturn(mock(HighLevelSimpleClient.class));

    when(node.getExecutor()).thenReturn(new InlinePriorityAwareExecutor());

    return new PluginManager(node, /* lastVersion= */ Integer.MAX_VALUE);
  }

  private static final class InlinePriorityAwareExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      job.run();
    }

    @Override
    public int[] waitingThreads() {
      return new int[0];
    }

    @Override
    public int[] runningThreads() {
      return new int[0];
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  private static final class TestablePluginManager extends PluginManager {
    enum Call {
      OFFICIAL,
      FREENET,
      FILE,
      URL
    }

    Call lastCall;
    String lastName;
    boolean lastStore;

    TestablePluginManager(Node node) {
      super(node, Integer.MAX_VALUE);
    }

    @Override
    public PluginInfoWrapper startPluginOfficial(
        String pluginname, boolean store, OfficialPluginDescription desc) {
      lastCall = Call.OFFICIAL;
      lastName = pluginname;
      lastStore = store;
      return mock(PluginInfoWrapper.class);
    }

    @Override
    public PluginInfoWrapper startPluginFreenet(String filename, boolean store) {
      lastCall = Call.FREENET;
      lastName = filename;
      lastStore = store;
      return mock(PluginInfoWrapper.class);
    }

    @Override
    public PluginInfoWrapper startPluginFile(String filename, boolean store) {
      lastCall = Call.FILE;
      lastName = filename;
      lastStore = store;
      return mock(PluginInfoWrapper.class);
    }

    @Override
    public PluginInfoWrapper startPluginURL(String filename, boolean store) {
      lastCall = Call.URL;
      lastName = filename;
      lastStore = store;
      return mock(PluginInfoWrapper.class);
    }
  }
}
