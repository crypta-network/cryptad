package network.crypta.platform.api.appupdates;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileAppUpdateSchedulerStoreTest {
  private static final String APP_ID = "queue-manager";
  private static final Instant CHECKED_AT = Instant.parse("2026-05-12T00:00:00Z");

  @TempDir private Path tempDir;

  @Test
  void readAppState_whenStatePersisted_expectRoundTripPathFreeState() throws Exception {
    FileAppUpdateSchedulerStore store = new FileAppUpdateSchedulerStore(tempDir);
    AppUpdateSchedulerState state =
        new AppUpdateSchedulerState(
            APP_ID,
            true,
            AppUpdateSchedulerStatus.BACKOFF,
            CHECKED_AT,
            CHECKED_AT.plusSeconds(30),
            AppUpdateSchedulerState.RESULT_FAILED,
            CHECKED_AT,
            2,
            "update_failed",
            "Scheduler update check failed.");

    store.writeAppState(state);

    AppUpdateSchedulerState restored = store.readAppState(APP_ID).orElseThrow();
    assertEquals(state, restored);
    assertFalse(restored.toJsonValue().toString().contains(tempDir.toString()));
  }

  @Test
  void readAppState_whenStateFileIsCorrupt_expectStateIgnored() throws Exception {
    Files.createDirectories(tempDir.resolve("_internal"));
    Files.writeString(
        tempDir.resolve(APP_ID + ".properties"),
        """
        version=1
        appId=../secret-token
        enabled=true
        status=success
        lastResult=success
        failureCount=0
        """);
    FileAppUpdateSchedulerStore store = new FileAppUpdateSchedulerStore(tempDir);

    assertTrue(store.readAppState(APP_ID).isEmpty());
  }

  @Test
  void readAppState_whenStateFileContainsDifferentValidAppId_expectStateIgnored() throws Exception {
    Files.createDirectories(tempDir.resolve("_internal"));
    Files.writeString(
        tempDir.resolve(APP_ID + ".properties"),
        """
        version=1
        appId=publisher
        enabled=true
        status=success
        lastResult=success
        failureCount=0
        """);
    FileAppUpdateSchedulerStore store = new FileAppUpdateSchedulerStore(tempDir);

    assertTrue(store.readAppState(APP_ID).isEmpty());
  }

  @Test
  void readCatalogState_whenStateFileContainsDifferentValidTarget_expectStateIgnored()
      throws Exception {
    Files.createDirectories(tempDir.resolve("_internal"));
    Files.writeString(
        tempDir.resolve("_internal").resolve("catalog-refresh.properties"),
        """
        version=1
        appId=publisher
        enabled=true
        status=success
        lastResult=success
        failureCount=0
        """);
    FileAppUpdateSchedulerStore store = new FileAppUpdateSchedulerStore(tempDir);

    assertTrue(store.readCatalogState().isEmpty());
  }

  @Test
  void readStates_whenAppIdMatchesCatalogRefresh_expectAppAndCatalogStatesDoNotCollide()
      throws Exception {
    FileAppUpdateSchedulerStore store = new FileAppUpdateSchedulerStore(tempDir);
    AppUpdateSchedulerState appState =
        new AppUpdateSchedulerState(
            "catalog-refresh",
            true,
            AppUpdateSchedulerStatus.SUCCESS,
            CHECKED_AT,
            CHECKED_AT.plusSeconds(60),
            AppUpdateSchedulerState.RESULT_SUCCESS,
            null,
            0,
            null,
            "Scheduler update check completed.");
    AppUpdateSchedulerState catalogState =
        new AppUpdateSchedulerState(
            "catalog-refresh",
            true,
            AppUpdateSchedulerStatus.BACKOFF,
            CHECKED_AT,
            CHECKED_AT.plusSeconds(120),
            AppUpdateSchedulerState.RESULT_FAILED,
            CHECKED_AT,
            1,
            "catalog_refresh_failed",
            "Scheduler catalog refresh failed.");

    store.writeAppState(appState);
    store.writeCatalogState(catalogState);

    assertEquals(appState, store.readAppState("catalog-refresh").orElseThrow());
    assertEquals(catalogState, store.readCatalogState().orElseThrow());
  }

  @Test
  void clearAppState_whenAppIdMatchesCatalogRefresh_expectCatalogStatePreserved() throws Exception {
    FileAppUpdateSchedulerStore store = new FileAppUpdateSchedulerStore(tempDir);
    AppUpdateSchedulerState appState =
        new AppUpdateSchedulerState(
            "catalog-refresh",
            true,
            AppUpdateSchedulerStatus.SUCCESS,
            CHECKED_AT,
            CHECKED_AT.plusSeconds(60),
            AppUpdateSchedulerState.RESULT_SUCCESS,
            null,
            0,
            null,
            "Scheduler update check completed.");
    AppUpdateSchedulerState catalogState =
        new AppUpdateSchedulerState(
            "catalog-refresh",
            true,
            AppUpdateSchedulerStatus.BACKOFF,
            CHECKED_AT,
            CHECKED_AT.plusSeconds(120),
            AppUpdateSchedulerState.RESULT_FAILED,
            CHECKED_AT,
            1,
            "catalog_refresh_failed",
            "Scheduler catalog refresh failed.");
    store.writeAppState(appState);
    store.writeCatalogState(catalogState);

    store.clearAppState("catalog-refresh");

    assertTrue(store.readAppState("catalog-refresh").isEmpty());
    assertEquals(catalogState, store.readCatalogState().orElseThrow());
  }
}
