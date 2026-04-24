package network.crypta.apps.queuemanager;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QueueManagerBundleStagingTest {
  private static final String APP_VERSION_PROPERTY = "queueManager.appVersion";
  private static final String STAGE_DIR_PROPERTY = "queueManager.stageDir";
  private static final String EXPECTED_APP_ID = "queue-manager";
  private static final String EXPECTED_APP_NAME = "Queue Manager";
  private static final String EXPECTED_UI_ENTRY = "static/index.html";
  private static final String EXPECTED_LAUNCHER_PATH = "bin/queue-manager.sh";
  private static final String EXPECTED_PERMISSIONS = "queue.read,queue.write";

  @Test
  void stagedBundle_whenManifestParsed_expectExpectedAppHostFields() throws Exception {
    AppManifest manifest =
        AppManifestParser.parse(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    assertEquals(EXPECTED_APP_ID, manifest.appId());
    assertEquals(EXPECTED_APP_NAME, manifest.appName());
    assertEquals(EXPECTED_LAUNCHER_PATH, manifest.execPathText());
    assertEquals(AppUiMode.STATIC, manifest.uiMode());
    assertEquals(EXPECTED_UI_ENTRY, manifest.uiEntry());
    assertEquals(java.util.List.of("queue.read", "queue.write"), manifest.permissions());
    assertEquals(Long.valueOf(0L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(0L), manifest.cacheQuotaBytes());
  }

  @Test
  void stagedBundle_whenManifestRead_expectExpectedRenderedContent() throws Exception {
    String manifestText =
        Files.readString(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    assertTrue(manifestText.contains("manifest.version=1"));
    assertTrue(manifestText.contains("app.id=" + EXPECTED_APP_ID));
    assertTrue(manifestText.contains("app.name=" + EXPECTED_APP_NAME));
    assertTrue(manifestText.contains("app.version=" + System.getProperty(APP_VERSION_PROPERTY)));
    assertTrue(manifestText.contains("app.exec=" + EXPECTED_LAUNCHER_PATH));
    assertTrue(manifestText.contains("app.ui.mode=static"));
    assertTrue(manifestText.contains("app.ui.entry=" + EXPECTED_UI_ENTRY));
    assertTrue(manifestText.contains("app.permissions=" + EXPECTED_PERMISSIONS));
    assertTrue(manifestText.contains("quota.data.bytes=0"));
    assertTrue(manifestText.contains("quota.cache.bytes=0"));
  }

  @Test
  void stagedBundle_whenLauncherStaged_expectLongRunningExecutableLoop() throws Exception {
    Path launcher = stageDirectory().resolve(EXPECTED_LAUNCHER_PATH);
    String launcherScript = Files.readString(launcher);

    assertTrue(launcherScript.startsWith("#!/bin/sh\n"));
    assertTrue(launcherScript.contains("Queue Manager started"));
    assertTrue(launcherScript.contains("trap 'printf \"Queue Manager stopping"));
    assertTrue(launcherScript.contains("while :; do"));
    assertTrue(launcherScript.contains("sleep 5"));

    Assumptions.assumeTrue(Files.getFileStore(launcher).supportsFileAttributeView("posix"));
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(launcher);
    assertTrue(permissions.contains(PosixFilePermission.OWNER_EXECUTE));
    assertTrue(permissions.contains(PosixFilePermission.GROUP_EXECUTE));
    assertTrue(permissions.contains(PosixFilePermission.OTHERS_EXECUTE));
  }

  @Test
  void stagedBundle_whenStaticUiStaged_expectEntryAssetsPresent() throws Exception {
    Path staticDirectory = stageDirectory().resolve("static");

    assertTrue(Files.isRegularFile(staticDirectory.resolve("index.html")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("app.js")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("app.css")));
    assertTrue(Files.notExists(staticDirectory.resolve("README.txt")));
    String appScript = Files.readString(staticDirectory.resolve("app.js"));
    assertTrue(appScript.contains("cryptad-bootstrap.json"));
    assertTrue(appScript.contains("platformApiRoot"));
    assertTrue(appScript.contains("formPassword"));
    assertTrue(appScript.contains("url.searchParams.set(\"sortBy\", state.sortBy);"));
    assertTrue(appScript.contains("url.searchParams.set(\"reversed\", \"true\");"));
    assertTrue(appScript.contains("isQueueKeyListLink"));
    assertTrue(appScript.contains("queue/keys"));
    assertTrue(appScript.contains("downloadTextFile(`${state.page}-keys.txt`"));
    assertTrue(appScript.contains("unsupportedQueueAction"));
    assertTrue(appScript.contains("Queue action is not supported by Platform API yet."));
    assertFalse(appScript.contains("CRYPTAD_APP_TOKEN"));
  }

  private static Path stageDirectory() {
    return Path.of(System.getProperty(STAGE_DIR_PROPERTY));
  }
}
