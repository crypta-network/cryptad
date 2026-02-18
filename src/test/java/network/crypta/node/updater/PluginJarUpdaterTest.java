package network.crypta.node.updater;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.Version;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PluginJarUpdaterTest {

  @Mock private NodeUpdateManager manager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private UserAlertManager alerts;
  @Mock private PluginManager pluginManager;

  private static final String REQUIRED_NODE_VERSION_KEY = "Required-Node-Version";

  private static byte[] makeJarWithManifest(String value) throws IOException {
    Manifest mf = new Manifest();
    Attributes attrs = mf.getMainAttributes();
    attrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");
    attrs.putValue(REQUIRED_NODE_VERSION_KEY, value);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (JarOutputStream jos = new JarOutputStream(baos, mf)) {
      // Finalize the JAR stream so the manifest is written and resource is used.
      jos.flush();
      jos.finish();
    }
    return baos.toByteArray();
  }

  private static FetchResult fetchResultFromBytes(byte[] jarBytes) {
    ArrayBucket bucket = new ArrayBucket(jarBytes);
    return FetchResult.create(new ClientMetadata("application/java-archive"), bucket);
  }

  private static FreenetURI dummyUSK() {
    // Construct a valid USK URI using component constructor to avoid base64 parsing
    byte[] rk = new byte[32];
    byte[] ck = new byte[32];
    return new FreenetURI("USK", "jar", null, rk, ck, null);
  }

  private PluginJarUpdater newUpdater(String pluginName, Path persistentTempDir) {
    when(manager.getNode()).thenReturn(node);
    when(manager.isEnabled()).thenReturn(true);
    when(manager.isBlown()).thenReturn(false);

    when(node.services().clientCore()).thenReturn(core);
    when(node.services().pluginManager()).thenReturn(pluginManager);

    when(core.getPersistentTempDir()).thenReturn(persistentTempDir.toFile());
    when(core.getAlerts()).thenReturn(alerts);
    when(core.getFormPassword()).thenReturn("pw");

    // Minimal fetch context wiring used by NodeUpdater's constructor
    HighLevelSimpleClient hlsc = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    when(core.makeClient(
            org.mockito.Mockito.anyShort(),
            org.mockito.Mockito.anyBoolean(),
            org.mockito.Mockito.anyBoolean()))
        .thenReturn(hlsc);
    when(hlsc.getFetchContext()).thenReturn(makeFetchContext());
    ClientContext clientContext = org.mockito.Mockito.mock(ClientContext.class);
    when(core.getClientContext()).thenReturn(clientContext);

    // Keep alert manager methods no-op but capturable
    doNothing().when(alerts).register(any(UserAlert.class));
    doNothing().when(alerts).unregister(any(UserAlert.class));

    NodeUpdaterParams params =
        new NodeUpdaterParams(
            manager,
            dummyUSK(),
            /* current= */ 1,
            /* min= */ 1,
            /* max= */ 999999,
            /* blobFilenamePrefix= */ "plugin-");
    return new PluginJarUpdater(
        params, pluginName, pluginManager, /* autoDeployOnRestart= */ false);
  }

  private static FetchContext makeFetchContext() {
    SimpleEventProducer ep = new SimpleEventProducer();
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(1, 1, 1, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 1, 1)
            .behavior(true, false, false)
            .clientOptions(ep, false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  @Test
  void processSuccess_whenRequiredNodeVersionTooHigh_blocksAndDoesNotArm(@TempDir Path tmp)
      throws Exception {
    String pluginName = "TestPlugin";
    PluginJarUpdater updater = newUpdater(pluginName, tmp);

    int tooHigh = Version.currentBuildNumber() + 100;
    byte[] jar = makeJarWithManifest(Integer.toString(tooHigh));
    FetchResult result = fetchResultFromBytes(jar);

    // Simulate the temp file created by fetcher
    File temp = Files.createTempFile(tmp, "plugin-", ".fblob.tmp").toFile();
    Files.write(temp.toPath(), new byte[] {1, 2, 3});
    // Match NodeUpdater's protected field for the delete path in PluginJarUpdater
    updater.tempBlobFile = temp;

    // Use a fetchedVersion newer than current so onSuccess proceeds
    updater.onSuccess(result, temp, /* fetchedVersion= */ Version.currentBuildNumber() + 1);

    // Not ready to deploy as the requirement is too high
    boolean shouldRestart = updater.onNoRevocation();
    assertFalse(shouldRestart, "Should not request restart when not ready");

    // No alert registered and no plugin manager interactions
    verify(alerts, never()).register(any(UserAlert.class));
    verify(pluginManager, never())
        .killPluginByFilename(any(), any(Integer.class), any(Boolean.class));
    verify(pluginManager, never()).startPluginAuto(any(), any(Boolean.class));
  }

  @Test
  void onNoRevocation_deploysWhenArmedAndLoaded_writesJarAndRestartsPlugin(@TempDir Path tmp)
      throws Exception {
    String pluginName = "MyPlugin";
    PluginJarUpdater updater = newUpdater(pluginName, tmp);

    int requiredOk = Version.currentBuildNumber();
    byte[] jar = makeJarWithManifest(Integer.toString(requiredOk));
    FetchResult result = fetchResultFromBytes(jar);

    // Simulate the temp file created by fetcher
    File temp = Files.createTempFile(tmp, "plugin-", ".fblob.tmp").toFile();
    Files.write(temp.toPath(), new byte[] {9});
    updater.tempBlobFile = temp;

    // Loaded plugin with an older version present
    PluginInfoWrapper loaded = org.mockito.Mockito.mock(PluginInfoWrapper.class);
    when(loaded.getPluginLongVersion()).thenReturn(1L);
    when(pluginManager.findPluginByIdentifier(pluginName)).thenReturn(loaded);
    when(pluginManager.isPluginLoaded(pluginName)).thenReturn(true);

    // Destination JAR path for deployment
    File dest = tmp.resolve(pluginName + ".jar").toFile();
    when(pluginManager.getPluginFilename(pluginName)).thenReturn(dest);

    // Run a success path
    int fetched = Version.currentBuildNumber() + 1;
    updater.onSuccess(result, temp, fetched);

    // Alert registered after successful fetch
    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);
    verify(alerts, times(1)).register(alertCaptor.capture());
    UserAlert createdAlert = alertCaptor.getValue();

    // Arm for immediate deployment and trigger
    updater.arm(false);
    boolean restartNeeded = updater.onNoRevocation();
    assertFalse(restartNeeded, "Deployment happens now; no restart of checker requested");

    // JAR written to plugin filename
    byte[] written = Files.readAllBytes(dest.toPath());
    assertArrayEquals(jar, written, "Deployed jar contents must match fetched bytes");

    verify(pluginManager, times(1)).killPluginByFilename(pluginName, Integer.MAX_VALUE, true);
    verify(pluginManager, times(1)).startPluginAuto(pluginName, true);

    // Alert unregistered after deployment
    verify(alerts, times(1)).unregister(createdAlert);
  }

  @Test
  void onNoRevocation_deploysOnlyAfterNext_whenArmedWhileRunning(@TempDir Path tmp)
      throws Exception {
    String pluginName = "DeferredPlugin";
    PluginJarUpdater updater = newUpdater(pluginName, tmp);

    // Acceptable required version
    byte[] jar = makeJarWithManifest(Integer.toString(Version.currentBuildNumber()));
    FetchResult result = fetchResultFromBytes(jar);

    // Temp file and fields
    File temp = Files.createTempFile(tmp, "plugin-", ".fblob.tmp").toFile();
    Files.write(temp.toPath(), new byte[] {7});
    updater.tempBlobFile = temp;

    // Loaded plugin with the older version
    PluginInfoWrapper loaded = org.mockito.Mockito.mock(PluginInfoWrapper.class);
    when(loaded.getPluginLongVersion()).thenReturn(0L);
    when(pluginManager.findPluginByIdentifier(pluginName)).thenReturn(loaded);
    when(pluginManager.isPluginLoaded(pluginName)).thenReturn(true);

    File dest = tmp.resolve(pluginName + ".jar").toFile();
    when(pluginManager.getPluginFilename(pluginName)).thenReturn(dest);

    // Complete the fetch
    updater.onSuccess(result, temp, Version.currentBuildNumber() + 2);

    // Arm as if updater was running earlier → deploy on next-but-one check
    updater.arm(true);
    boolean firstCall = updater.onNoRevocation();
    assertTrue(firstCall, "First call should schedule deployment after the next revocation check");

    // Now perform deployment on the following no-revocation signal
    boolean secondCall = updater.onNoRevocation();
    assertFalse(secondCall, "Second call performs deployment and does not request restart");

    verify(pluginManager, times(1)).killPluginByFilename(pluginName, Integer.MAX_VALUE, true);
    verify(pluginManager, times(1)).startPluginAuto(pluginName, true);
  }
}
