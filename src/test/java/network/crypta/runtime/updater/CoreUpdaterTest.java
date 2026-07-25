package network.crypta.runtime.updater;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.fs.AppEnv;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.Version;
import network.crypta.support.HTMLNode;
import network.crypta.support.Ticker;
import network.crypta.support.http.ExternalLinkSupport;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class CoreUpdaterTest {
  private static final String VALID_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
  private static final String REPLACEMENT_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d52.xml";
  private static final String SELECTED_PACKAGE_KEY = "amd64.deb";
  private static final String STORE_PACKAGE_KEY = "amd64.flatpak";
  private static final String STORE_PACKAGE_ID = "network.crypta.Cryptad";
  private static final String STORE_PACKAGE_URL = "https://flathub.org/apps/" + STORE_PACKAGE_ID;

  @Test
  void parseJson_minimal() {
    String json =
        """
          {
            "version": "1.2.3+build123",
            "release_page_url": "https://example.com/r/1.2.3",
            "packages": {
              "amd64.deb": { "chk": "CHK@abc", "size": 10 },
              "arm64.dmg": { "chk": "CHK@def" }
            },
            "changelog_chk": "CHK@chg",
            "fullchangelog_chk": "CHK@full"
          }
        """;

    CoreInfo info = CoreJson.parse(json);

    assertEquals("1.2.3+build123", info.version());
    assertEquals("https://example.com/r/1.2.3", info.releasePageUrl());
    assertEquals("CHK@abc", info.packages().get("amd64.deb").chk());
    assertEquals(10L, info.packages().get("amd64.deb").size());
    assertEquals("CHK@chg", info.changelogChk());
    assertEquals("CHK@full", info.fullChangelogChk());
  }

  @Test
  void json_missingOptionalFields() {
    String json = "{ \"version\":\"2\", \"packages\": {\"amd64.exe\": {\"chk\":\"CHK@x\"}} }";

    CoreInfo info = CoreJson.parse(json);

    assertEquals("2", info.version());
    assertNotNull(info.packages().get("amd64.exe"));
    assertNull(info.releasePageUrl());
  }

  @Test
  void jsonParser_whenNumbersAndEscapesAreValid_expectTypedValues() {
    String json =
        "{\"negative\":-12,\"fraction\":1.25,\"exponent\":6.02e+23,"
            + "\"escaped\":\"quote:\\\" slash:\\\\ unicode:\\u00e9\"}";

    Map<String, Object> parsed = JsonMini.parseObject(json);

    assertEquals(-12L, parsed.get("negative"));
    assertEquals(1.25, parsed.get("fraction"));
    assertEquals(6.02e23, parsed.get("exponent"));
    assertEquals("quote:\" slash:\\ unicode:é", parsed.get("escaped"));
  }

  @Test
  void jsonParser_whenNumberOrEscapeIsMalformed_expectSpecificValidation() {
    IllegalArgumentException fractionError =
        assertThrows(IllegalArgumentException.class, () -> JsonMini.parseObject("{\"value\":1.}"));
    IllegalArgumentException unicodeError =
        assertThrows(
            IllegalArgumentException.class, () -> JsonMini.parseObject("{\"value\":\"\\u12xz\"}"));

    assertTrue(fractionError.getMessage().startsWith("Invalid JSON fraction at "));
    assertTrue(unicodeError.getMessage().startsWith("Invalid Unicode escape at "));
  }

  @Test
  void parseStrictIntegerVersion_whenInteger_expectParsedBuild() {
    assertEquals(1501, CoreUpdater.parseStrictIntegerVersion("1501"));
    assertEquals(1501, CoreUpdater.parseStrictIntegerVersion("001501"));
    assertEquals(1501, CoreUpdater.parseStrictIntegerVersion(" 1501 "));
  }

  @Test
  void parseStrictIntegerVersion_whenInvalid_expectNull() {
    assertNull(CoreUpdater.parseStrictIntegerVersion(null));
    assertNull(CoreUpdater.parseStrictIntegerVersion(""));
    assertNull(CoreUpdater.parseStrictIntegerVersion("  "));
    assertNull(CoreUpdater.parseStrictIntegerVersion("1.2.3+build123"));
    assertNull(CoreUpdater.parseStrictIntegerVersion("1501beta"));
    assertNull(CoreUpdater.parseStrictIntegerVersion("999999999999999999999"));
  }

  @Test
  void buildLinksNode_whenReleaseAndStoreUrlsPresent_expectEscapedExternalLinks() throws Exception {
    // Arrange
    CoreUpdater updater = createCoreUpdater();
    String releasePageUrl = "https://example.com/releases/core?q=a%20b";
    String storeUrl = "https://store.example.com/apps/core?id=cryptad%20pkg";
    CoreInfo info = new CoreInfo("1501", releasePageUrl, Map.of(), null, null);
    PackageSpec spec = new PackageSpec(null, null, storeUrl);

    // Act
    HTMLNode links = invokeBuildLinksNode(updater, info, spec);
    List<HTMLNode> anchors =
        links.getChildren().stream().filter(node -> "a".equals(node.getName())).toList();

    // Assert
    assertEquals(2, anchors.size());
    assertEquals(
        ExternalLinkSupport.escape(releasePageUrl), anchors.get(0).getAttributes().get("href"));
    assertEquals("Release Notes", anchors.get(0).generateChildren());
    assertEquals(ExternalLinkSupport.escape(storeUrl), anchors.get(1).getAttributes().get("href"));
    assertEquals("Open in Store", anchors.get(1).generateChildren());
  }

  @Test
  void isUiDownloadAvailable_whenSelectedPackageHasChk_expectTrue() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        Version.currentBuildNumber() + 1,
        SELECTED_PACKAGE_KEY,
        new PackageSpec(VALID_CHK, 10L, null));

    assertTrue(updater.isUiDownloadAvailable());
  }

  @Test
  void packageActions_whenAdvertisedBuildIsRevoked_expectPackageTargetBlocked() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int advertisedBuild = Version.currentBuildNumber() + 1;
    File completedPackage = Files.createTempFile("cryptad-revoked-package", ".deb").toFile();
    CoreUpdater.DescriptorSelection selection =
        setDescriptorSelection(
            updater, advertisedBuild, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher completedFetcher = mock(CoreUpdater.PackageFetcher.class);
    when(completedFetcher.matchesSelection(selection)).thenReturn(true);
    when(completedFetcher.isSuccess()).thenReturn(true);
    when(completedFetcher.completedFileOrNull()).thenReturn(completedPackage);
    setField(updater, "fetcher", completedFetcher);
    when(updater.manager.isCorePackageBuildRevoked(advertisedBuild)).thenReturn(true);

    assertFalse(updater.canUpdateNow());
    assertFalse(updater.isUiDownloadAvailable());
    assertFalse(updater.startDownloadFromUI());
    assertNull(updater.getDownloadedFile());
    assertTrue(updater.withDownloadedInstaller(completedPackage, _ -> "launched").isEmpty());
    verify(updater.core, never()).getClientContext();
  }

  @Test
  void packageActions_whenSuccessorReusesChk_expectOriginalFetcherRejected() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int originalBuild = Version.currentBuildNumber() + 1;
    int successorBuild = originalBuild + 1;
    File completedPackage = Files.createTempFile("cryptad-original-package", ".deb").toFile();
    CoreUpdater.DescriptorSelection originalSelection =
        setDescriptorSelection(
            updater, originalBuild, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher originalFetcher =
        updater.new PackageFetcher(originalSelection, completedPackage, new FreenetURI(VALID_CHK));
    setField(updater, "fetcher", originalFetcher);
    originalFetcher.onSuccess(mock(FetchResult.class), null);
    setDescriptorSelection(
        updater, successorBuild, "amd64.rpm", new PackageSpec(VALID_CHK, 10L, null));

    assertNull(updater.getDownloadedFile());
    assertTrue(updater.withDownloadedInstaller(completedPackage, _ -> "launched").isEmpty());
    assertTrue(updater.isUiDownloadAvailable());
    verify(updater.manager, never()).withNonRevokedCorePackageAction(eq(successorBuild), any());
  }

  @Test
  void withCurrentStoreTarget_whenSubmissionMatchesCurrentSelection_expectActionRuns()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        Version.currentBuildNumber() + 1,
        STORE_PACKAGE_KEY,
        new PackageSpec(null, null, STORE_PACKAGE_URL));

    assertEquals(
        Optional.of("launched"),
        updater.withCurrentStoreTarget(
            "flatpak", STORE_PACKAGE_ID, STORE_PACKAGE_URL, () -> "launched"));
    assertTrue(
        updater
            .withCurrentStoreTarget("snap", STORE_PACKAGE_ID, STORE_PACKAGE_URL, () -> "launched")
            .isEmpty());
    assertTrue(
        updater
            .withCurrentStoreTarget("flatpak", "other.package", STORE_PACKAGE_URL, () -> "launched")
            .isEmpty());
    assertTrue(
        updater
            .withCurrentStoreTarget(
                "flatpak",
                STORE_PACKAGE_ID,
                "https://flathub.org/apps/other.package",
                () -> "launched")
            .isEmpty());
  }

  @Test
  void withCurrentStoreTarget_whenSelectedBuildIsRevoked_expectActionRejected() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int advertisedBuild = Version.currentBuildNumber() + 1;
    setDescriptorSelection(
        updater,
        advertisedBuild,
        STORE_PACKAGE_KEY,
        new PackageSpec(null, null, STORE_PACKAGE_URL));
    doReturn(Optional.empty())
        .when(updater.manager)
        .withNonRevokedCorePackageAction(eq(advertisedBuild), any());

    assertTrue(
        updater
            .withCurrentStoreTarget(
                "flatpak", STORE_PACKAGE_ID, STORE_PACKAGE_URL, () -> "launched")
            .isEmpty());
  }

  @Test
  void withCurrentStoreTarget_whenVersionLabelIsNonInteger_expectActionRuns() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        new CoreInfo("legacy-release", null, Map.of(), null, null),
        null,
        STORE_PACKAGE_KEY,
        new PackageSpec(null, null, STORE_PACKAGE_URL));

    assertEquals(
        Optional.of("launched"),
        updater.withCurrentStoreTarget(
            "flatpak", STORE_PACKAGE_ID, STORE_PACKAGE_URL, () -> "launched"));
    verify(updater.manager).withNonRevokedCorePackageAction(isNull(), any());
  }

  @Test
  void withCurrentStoreTarget_whenIntegerBuildIsNotNewer_expectActionRejected() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        Version.currentBuildNumber(),
        STORE_PACKAGE_KEY,
        new PackageSpec(null, null, STORE_PACKAGE_URL));

    assertTrue(
        updater
            .withCurrentStoreTarget(
                "flatpak", STORE_PACKAGE_ID, STORE_PACKAGE_URL, () -> "launched")
            .isEmpty());
    verify(updater.manager, never()).withNonRevokedCorePackageAction(any(), any());
  }

  @Test
  void withCurrentStoreTarget_whenUriChangesDuringLaunch_expectChangeWaitsForLaunch()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int advertisedBuild = Version.currentBuildNumber() + 1;
    setDescriptorSelection(
        updater,
        advertisedBuild,
        STORE_PACKAGE_KEY,
        new PackageSpec(null, null, STORE_PACKAGE_URL));
    FreenetURI replacementUri =
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/replacement-info/1200");
    CountDownLatch launchEntered = new CountDownLatch(1);
    CountDownLatch releaseLaunch = new CountDownLatch(1);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<Optional<String>> launch =
          executor.submit(
              () ->
                  updater.withCurrentStoreTarget(
                      "flatpak",
                      STORE_PACKAGE_ID,
                      STORE_PACKAGE_URL,
                      () -> {
                        launchEntered.countDown();
                        await(releaseLaunch);
                        return "launched";
                      }));
      assertTrue(launchEntered.await(5, TimeUnit.SECONDS));
      Future<?> uriChange = executor.submit(() -> updater.onChangeURI(replacementUri, 1200));

      try {
        assertThrows(TimeoutException.class, () -> uriChange.get(200, TimeUnit.MILLISECONDS));
      } finally {
        releaseLaunch.countDown();
      }

      assertEquals(Optional.of("launched"), launch.get(5, TimeUnit.SECONDS));
      uriChange.get(5, TimeUnit.SECONDS);
    }
  }

  @Test
  void isUiDownloadAvailable_whenSelectedPackageHasChkAndVersionLabelIsNonInteger_expectTrue()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));

    assertTrue(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenSelectedPackageChkIsMalformed_expectFalse() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec("not-a-chk", 10L, null));

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenUpdatesDirectoryCannotBePrepared_expectFalse() throws Exception {
    File nonDirectoryNodeRoot =
        java.nio.file.Files.createTempFile("cryptad-core-updater", ".tmp").toFile();
    CoreUpdater updater = createCoreUpdater(nonDirectoryNodeRoot);
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenVersionDirectoryExistsButIsNotWritable_expectFalse()
      throws Exception {
    File nodeDir = Files.createTempDirectory("cryptad-core-updater").toFile();
    File versionDir = new File(nodeDir, "updates/core/1200");
    assertTrue(versionDir.mkdirs());
    try {
      Files.setPosixFilePermissions(
          versionDir.toPath(),
          Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE));
      assumeFalse(
          versionDir.canWrite(), "Test environment cannot simulate a non-writable directory.");

      CoreUpdater updater = createCoreUpdater(nodeDir);
      setDescriptorSelection(
          updater,
          new CoreInfo("1200", null, Map.of(), null, null),
          null,
          SELECTED_PACKAGE_KEY,
          new PackageSpec(VALID_CHK, 10L, null));

      assertFalse(updater.isUiDownloadAvailable());
    } finally {
      assertTrue(versionDir.setWritable(true, true));
    }
  }

  @Test
  void isUiDownloadAvailable_whenUpdatesPathIsBlockedByFile_expectFalse() throws Exception {
    File nodeDir = Files.createTempDirectory("cryptad-core-updater").toFile();
    File updatesFile = new File(nodeDir, "updates");
    assertTrue(updatesFile.createNewFile());

    CoreUpdater updater = createCoreUpdater(nodeDir);
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenSelectedPackageIsStoreBacked_expectFalse() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        Version.currentBuildNumber() + 1,
        SELECTED_PACKAGE_KEY,
        new PackageSpec(null, 10L, "https://store.example.com/apps/core?id=cryptad"));

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenMatchingPackageDownloadInProgress_expectFalse() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    CoreUpdater.DescriptorSelection selection =
        setDescriptorSelection(
            updater,
            Version.currentBuildNumber() + 1,
            SELECTED_PACKAGE_KEY,
            new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher fetcher = mock(CoreUpdater.PackageFetcher.class);
    when(fetcher.matchesSelection(selection)).thenReturn(true);
    when(fetcher.isInProgress()).thenReturn(true);
    setField(updater, "fetcher", fetcher);

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenMatchingPackageAlreadyFetched_expectFalse() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    CoreUpdater.DescriptorSelection selection =
        setDescriptorSelection(
            updater,
            Version.currentBuildNumber() + 1,
            SELECTED_PACKAGE_KEY,
            new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher fetcher = mock(CoreUpdater.PackageFetcher.class);
    when(fetcher.matchesSelection(selection)).thenReturn(true);
    when(fetcher.isInProgress()).thenReturn(false);
    when(fetcher.isSuccess()).thenReturn(true);
    setField(updater, "fetcher", fetcher);

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void isUiDownloadAvailable_whenOtherPackageDownloadInProgress_expectFalse() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        Version.currentBuildNumber() + 1,
        SELECTED_PACKAGE_KEY,
        new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher fetcher = mock(CoreUpdater.PackageFetcher.class);
    when(fetcher.isInProgress()).thenReturn(true);
    setField(updater, "fetcher", fetcher);

    assertFalse(updater.isUiDownloadAvailable());
  }

  @Test
  void startDownloadFromUI_whenUpdaterIsBlown_expectDownloadDoesNotStart() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    when(updater.manager.isBlown()).thenReturn(true);

    assertFalse(updater.startDownloadFromUI());
  }

  @Test
  void startDownloadFromUI_whenUpdaterWasPreKilled_expectDownloadDoesNotStart() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    updater.preKill();

    assertFalse(updater.startDownloadFromUI());
    verify(updater.core, never()).getClientContext();
  }

  @Test
  void start_whenPackageFetcherWasCancelledBeforeRegistration_expectDownloadDoesNotStart()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    CoreUpdater.DescriptorSelection selection =
        setDescriptorSelection(
            updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher fetcher =
        updater
        .new PackageFetcher(
            selection,
            Files.createTempFile("cryptad-package-fetch", ".deb").toFile(),
            new FreenetURI(VALID_CHK));
    fetcher.cancelForUpdaterStop();

    assertFalse(fetcher.start());
    verify(updater.core, never()).getClientContext();
  }

  @Test
  void onSuccess_whenAutomaticSelectionChangesDuringFetch_expectReplacementStarts()
      throws Exception {
    CoreUpdater updater = updaterWithActivePackageFetch();
    CoreUpdater.PackageFetcher originalFetcher = currentPackageFetcher(updater);
    CoreUpdater.DescriptorSelection replacementSelection =
        setDescriptorSelection(
            updater,
            Version.currentBuildNumber() + 2,
            SELECTED_PACKAGE_KEY,
            new PackageSpec(REPLACEMENT_CHK, 10L, null));
    ClientContext clientContext = updater.core.getClientContext();

    originalFetcher.onSuccess(mock(FetchResult.class), null);

    assertTrue(currentPackageFetcher(updater).matchesSelection(replacementSelection));
    verify(clientContext, times(2)).start(any(ClientGetter.class));
  }

  @Test
  void onFailure_whenAutomaticSelectionChangesDuringFetch_expectReplacementStarts()
      throws Exception {
    CoreUpdater updater = updaterWithActivePackageFetch();
    CoreUpdater.PackageFetcher originalFetcher = currentPackageFetcher(updater);
    CoreUpdater.DescriptorSelection replacementSelection =
        setDescriptorSelection(
            updater,
            Version.currentBuildNumber() + 2,
            SELECTED_PACKAGE_KEY,
            new PackageSpec(REPLACEMENT_CHK, 10L, null));
    ClientContext clientContext = updater.core.getClientContext();

    originalFetcher.onFailure(new FetchException(FetchExceptionMode.ROUTE_NOT_FOUND));

    assertTrue(currentPackageFetcher(updater).matchesSelection(replacementSelection));
    verify(clientContext, times(2)).start(any(ClientGetter.class));
  }

  @Test
  void onChangeURI_whenUpdaterResubscribes_expectPackageDownloadsRemainEnabled() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    FreenetURI replacementUri =
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/replacement-info/1200");
    updater.onChangeURI(replacementUri, 1200);
    setDescriptorSelection(
        updater, null, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));

    assertTrue(updater.startDownloadFromUI());
  }

  @Test
  void kill_whenPackageDownloadIsActive_expectDownloadCancelled() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    CoreUpdater.PackageFetcher fetcher = mock(CoreUpdater.PackageFetcher.class);
    setField(updater, "fetcher", fetcher);

    updater.kill();

    verify(fetcher).cancelForUpdaterStop();
  }

  @Test
  void lifecycleChange_whenSelectedBuildBecomesRevoked_expectActiveDownloadCancelled()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int advertisedBuild = Version.currentBuildNumber() + 1;
    setDescriptorSelection(updater, advertisedBuild, null, null);
    CoreUpdater.PackageFetcher fetcher = mock(CoreUpdater.PackageFetcher.class);
    setField(updater, "fetcher", fetcher);
    when(updater.manager.isCorePackageBuildRevoked(advertisedBuild)).thenReturn(true);

    updater.onSupportLifecycleStateChanged();

    verify(fetcher).cancelForBuildRevocation();
  }

  @Test
  void withDownloadedInstaller_whenUriChangesDuringLaunch_expectChangeWaitsForLaunch()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int advertisedBuild = Version.currentBuildNumber() + 1;
    File completedPackage = Files.createTempFile("cryptad-authorized-package", ".deb").toFile();
    CoreUpdater.DescriptorSelection selection =
        setDescriptorSelection(
            updater, advertisedBuild, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher completedFetcher = mock(CoreUpdater.PackageFetcher.class);
    when(completedFetcher.matchesSelection(selection)).thenReturn(true);
    when(completedFetcher.isSuccess()).thenReturn(true);
    when(completedFetcher.completedFileOrNull()).thenReturn(completedPackage);
    setField(updater, "fetcher", completedFetcher);
    FreenetURI replacementUri =
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/replacement-info/1200");
    CountDownLatch launchEntered = new CountDownLatch(1);
    CountDownLatch releaseLaunch = new CountDownLatch(1);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<Optional<String>> launch =
          executor.submit(
              () ->
                  updater.withDownloadedInstaller(
                      completedPackage,
                      installer -> {
                        launchEntered.countDown();
                        await(releaseLaunch);
                        return installer.getAbsolutePath();
                      }));
      assertTrue(launchEntered.await(5, TimeUnit.SECONDS));
      Future<?> uriChange = executor.submit(() -> updater.onChangeURI(replacementUri, 1200));

      try {
        assertThrows(TimeoutException.class, () -> uriChange.get(200, TimeUnit.MILLISECONDS));
      } finally {
        releaseLaunch.countDown();
      }

      assertEquals(
          Optional.of(completedPackage.getCanonicalPath()), launch.get(5, TimeUnit.SECONDS));
      uriChange.get(5, TimeUnit.SECONDS);
    }
  }

  @Test
  void withDownloadedInstaller_whenLifecycleRevokesDuringLaunch_expectCallbackWaitsForLaunch()
      throws Exception {
    CoreUpdater updater = createCoreUpdater();
    int advertisedBuild = Version.currentBuildNumber() + 1;
    File completedPackage = Files.createTempFile("cryptad-authorized-package", ".deb").toFile();
    CoreUpdater.DescriptorSelection selection =
        setDescriptorSelection(
            updater, advertisedBuild, SELECTED_PACKAGE_KEY, new PackageSpec(VALID_CHK, 10L, null));
    CoreUpdater.PackageFetcher completedFetcher = mock(CoreUpdater.PackageFetcher.class);
    when(completedFetcher.matchesSelection(selection)).thenReturn(true);
    when(completedFetcher.isSuccess()).thenReturn(true);
    when(completedFetcher.completedFileOrNull()).thenReturn(completedPackage);
    setField(updater, "fetcher", completedFetcher);
    AtomicBoolean revoked = new AtomicBoolean();
    when(updater.manager.isCorePackageBuildRevoked(advertisedBuild)).thenAnswer(_ -> revoked.get());
    CountDownLatch launchEntered = new CountDownLatch(1);
    CountDownLatch releaseLaunch = new CountDownLatch(1);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<Optional<String>> launch =
          executor.submit(
              () ->
                  updater.withDownloadedInstaller(
                      completedPackage,
                      installer -> {
                        launchEntered.countDown();
                        await(releaseLaunch);
                        return installer.getAbsolutePath();
                      }));
      assertTrue(launchEntered.await(5, TimeUnit.SECONDS));
      revoked.set(true);
      Future<?> lifecycleChange = executor.submit(updater::onSupportLifecycleStateChanged);

      try {
        assertThrows(TimeoutException.class, () -> lifecycleChange.get(200, TimeUnit.MILLISECONDS));
      } finally {
        releaseLaunch.countDown();
      }

      assertEquals(
          Optional.of(completedPackage.getCanonicalPath()), launch.get(5, TimeUnit.SECONDS));
      lifecycleChange.get(5, TimeUnit.SECONDS);
      verify(completedFetcher).cancelForBuildRevocation();
    }
  }

  private static CoreUpdater createCoreUpdater() throws Exception {
    return createCoreUpdater(
        java.nio.file.Files.createTempDirectory("cryptad-core-updater").toFile());
  }

  private static CoreUpdater createCoreUpdater(File nodeDir) throws Exception {
    NodeUpdateManager manager = mock(NodeUpdateManager.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Ticker ticker = mock(Ticker.class);

    when(manager.getNode()).thenReturn(node);
    when(node.nodeDir().dir()).thenReturn(nodeDir);
    when(node.services().clientCore()).thenReturn(core);
    when(node.network().ticker()).thenReturn(ticker);
    when(core.makeClient(anyShort(), anyBoolean(), anyBoolean())).thenReturn(client);
    when(client.getFetchContext()).thenReturn(createFetchContext());
    when(core.getUskManager()).thenReturn(mock(USKManager.class));
    when(core.getClientContext()).thenReturn(mock(ClientContext.class));

    CoreUpdater updater = new CoreUpdater(defaultParams(manager));
    when(manager.withCurrentCoreUpdaterAction(eq(updater), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Supplier<Optional<Object>> action = invocation.getArgument(1, Supplier.class);
              return action.get();
            });
    when(manager.withNonRevokedCorePackageAction(any(), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Supplier<Object> action = invocation.getArgument(1, Supplier.class);
              return Optional.of(action.get());
            });
    return updater;
  }

  private static CoreUpdater updaterWithActivePackageFetch() throws Exception {
    CoreUpdater updater = createCoreUpdater();
    setDescriptorSelection(
        updater,
        Version.currentBuildNumber() + 1,
        SELECTED_PACKAGE_KEY,
        new PackageSpec(VALID_CHK, 10L, null));
    when(updater.manager.isAutoUpdateAllowed()).thenReturn(true);
    assertTrue(updater.startDownloadFromUI());
    return updater;
  }

  private static NodeUpdaterParams defaultParams(NodeUpdateManager manager)
      throws MalformedURLException {
    return new NodeUpdaterParams(
        manager,
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/1200"),
        1200,
        -1,
        Integer.MAX_VALUE,
        "core-info-",
        1325);
  }

  private static FetchContext createFetchContext() {
    SimpleEventProducer eventProducer = new SimpleEventProducer();
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(1, 1, 1, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 1, 1)
            .behavior(true, false, false)
            .clientOptions(eventProducer, false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  private static HTMLNode invokeBuildLinksNode(CoreUpdater updater, CoreInfo info, PackageSpec spec)
      throws Exception {
    Method buildLinksNode =
        CoreUpdater.class.getDeclaredMethod(
            "buildLinksNode",
            CoreInfo.class,
            PackageSpec.class,
            String.class,
            AppEnv.EnvDetection.class);
    buildLinksNode.setAccessible(true);
    return (HTMLNode) buildLinksNode.invoke(updater, info, spec, SELECTED_PACKAGE_KEY, null);
  }

  @SuppressWarnings("unchecked")
  private static <T> void setField(CoreUpdater updater, String fieldName, T value)
      throws Exception {
    Field field = CoreUpdater.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    ((AtomicReference<T>) field.get(updater)).set(value);
  }

  private static CoreUpdater.DescriptorSelection setDescriptorSelection(
      CoreUpdater updater, Integer buildVersion, String packageKey, PackageSpec packageSpec)
      throws Exception {
    CoreInfo info =
        new CoreInfo(
            buildVersion != null ? buildVersion.toString() : "test", null, Map.of(), null, null);
    return setDescriptorSelection(updater, info, buildVersion, packageKey, packageSpec);
  }

  private static CoreUpdater.DescriptorSelection setDescriptorSelection(
      CoreUpdater updater,
      CoreInfo info,
      Integer buildVersion,
      String packageKey,
      PackageSpec packageSpec)
      throws Exception {
    CoreUpdater.DescriptorSelection selection =
        new CoreUpdater.DescriptorSelection(info, buildVersion, null, packageKey, packageSpec);
    setField(updater, "descriptorSelection", selection);
    return selection;
  }

  @SuppressWarnings("unchecked")
  private static CoreUpdater.PackageFetcher currentPackageFetcher(CoreUpdater updater)
      throws Exception {
    Field field = CoreUpdater.class.getDeclaredField("fetcher");
    field.setAccessible(true);
    return ((AtomicReference<CoreUpdater.PackageFetcher>) field.get(updater)).get();
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(5, TimeUnit.SECONDS)) {
        throw new AssertionError("Timed out waiting for installer launch test coordination");
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Installer launch test was interrupted", e);
    }
  }
}
