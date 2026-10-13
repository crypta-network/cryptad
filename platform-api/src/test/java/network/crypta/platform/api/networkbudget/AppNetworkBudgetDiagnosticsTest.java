package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.TrustGraphProcessBudgetFixture;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.platform.trustgraph.TrustGraphStoreConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Real file faults distinguish missing durable observations from zero measured usage. */
class AppNetworkBudgetDiagnosticsTest {
  private static final String SELECTED_APP = "selected-app";
  private static final String CONTROL_APP = "control-app";
  private static final String SCOPE_BINDINGS = "scopeBindings";
  @TempDir Path root;
  private static final Clock CLOCK = Clock.systemUTC();

  @Test
  void genuinelyEmptyStoreIsValidAndDoesNotInitializeFiles() {
    var budgets = service();
    assertTrue(budgets.diagnostics().valid());
    assertTrue(budgets.diagnostics().usage().isEmpty());
    assertFalse(Files.exists(root.resolve("budget")));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"malformed-record", "identity-mismatch", "special-member", "bounded-exhaustion"})
  void strictEnumerationFaultPreservesChargesAndFreshRecovery(String variant) throws Exception {
    var budgets = seeded();
    var graph = graph();
    var before = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
    var initial = store().observe(4096);
    var injected = new ArrayList<Path>();
    boolean requiredReadable =
        !variant.equals("malformed-record") && !variant.equals("identity-mismatch");
    String target = requiredReadable ? SELECTED_APP : "fault-app";
    if (!requiredReadable) {
      Path directory = Files.createDirectory(root.resolve("budget/fault-app"));
      Path member = directory.resolve("trust_graph_import.properties");
      if (variant.equals("malformed-record")) Files.writeString(member, "broken=true");
      else {
        var template =
            Files.readString(root.resolve("budget/control-app/trust_graph_import.properties"));
        Files.writeString(
            member, template); // Correct file shape, incorrect persisted authenticated identity.
      }
      injected.add(member);
      injected.add(directory);
    } else if (variant.equals("special-member")) {
      injected.add(Files.createDirectory(root.resolve("budget/selected-app/hostile-member")));
    } else {
      // Strict diagnostics count visited members, including empty directories. This is bounded.
      for (int index = 0; index < 4097; index++) {
        injected.add(Files.createDirectory(root.resolve("budget/inspection-" + index)));
      }
    }
    try {
      var diagnostic = budgets.diagnostics();
      assertFalse(diagnostic.valid());
      assertTrue(diagnostic.usage().isEmpty());
      assertEquals(0, diagnostic.activeFamilyLeases());
      AppNetworkBudgetDecision request;
      if (!requiredReadable) {
        var denied = budgets.acquire(target, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
        request = denied;
        assertFalse(denied.allowed());
        assertEquals("network_budget_unavailable", denied.errorCode());
        assertEquals("App network budget service is unavailable.", denied.message());
        assertFalse(denied.message().contains(root.toString()));
      } else {
        request = charge(budgets, SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
      }
      var during = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
      assertFalse((Boolean) ((Map<?, ?>) during.get("diagnostics")).get("valid"));
      for (Path path : injected) Files.delete(path);
      injected.clear();
      var after = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
      assertTrue(budgets.diagnostics().valid());
      assertConservative(initial, store().observe(4096));
      var recoveryRequest =
          charge(budgets, SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
      var recovery = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
      assertConservative(initial, store().observe(4096));
      export(
          variant,
          new DiagnosticObservations(before, during, after, recovery, request, recoveryRequest),
          Map.of(
              "kind",
              variant,
              "targetAppId",
              target,
              "requiredKeyReadable",
              requiredReadable,
              "enumerationReadable",
              true,
              "restored",
              true,
              "contentsRestored",
              false));
    } finally {
      for (Path path : injected) Files.deleteIfExists(path);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"enumeration-only", "required-key-unreadable"})
  void actualUidAccessDenialPreservesUnknownIntervalAndRestoresOnlyAccess(String variant)
      throws Exception {
    assumeTrue(
        root.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "POSIX access profile unavailable");
    var budgets = seeded();
    var graph = graph();
    var before = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
    var initial = store().observe(4096);
    boolean enumerationOnly = variant.equals("enumeration-only");
    String targetApp = enumerationOnly ? CONTROL_APP : SELECTED_APP;
    Path target =
        root.resolve(
            enumerationOnly
                ? "budget/control-app"
                : "budget/selected-app/foreground_content_fetch.properties");
    Set<PosixFilePermission> originalMode = Files.getPosixFilePermissions(target);
    Object fileKey =
        Files.readAttributes(target, java.nio.file.attribute.BasicFileAttributes.class).fileKey();
    try {
      Files.setPosixFilePermissions(
          target, PosixFilePermissions.fromString(enumerationOnly ? "-wx------" : "-w-------"));
      boolean actualDenied = enumerationOnly ? enumerationDenied(target) : readDenied(target);
      assumeTrue(actualDenied, "Current UID/provider bypasses selected permission fault");
      assertFalse(budgets.diagnostics().valid());
      assertTrue(budgets.diagnostics().usage().isEmpty());
      AppNetworkBudgetDecision request;
      if (enumerationOnly) {
        assertEquals(
            1,
            store()
                .read(CONTROL_APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)
                .orElseThrow()
                .count());
        request = charge(budgets, SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
      } else {
        var denied =
            budgets.acquire(SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
        request = denied;
        assertFalse(denied.allowed());
        assertEquals("network_budget_unavailable", denied.errorCode());
      }
      var during = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
      assertEquals(
          fileKey,
          Files.readAttributes(target, java.nio.file.attribute.BasicFileAttributes.class)
              .fileKey());
      Files.setPosixFilePermissions(target, originalMode);
      var after = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
      assertTrue(budgets.diagnostics().valid());
      assertConservative(initial, store().observe(4096));
      var recoveryRequest =
          charge(budgets, SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
      var recovery = TrustGraphProcessBudgetFixture.phaseValue(budgets, graph);
      assertConservative(initial, store().observe(4096));
      export(
          variant,
          new DiagnosticObservations(before, during, after, recovery, request, recoveryRequest),
          Map.of(
              "kind",
              variant,
              "targetAppId",
              targetApp,
              "requiredKeyReadable",
              enumerationOnly,
              "enumerationReadable",
              !enumerationOnly,
              "restored",
              true,
              "contentsRestored",
              false));
    } finally {
      if (fileKey.equals(
          Files.readAttributes(target, java.nio.file.attribute.BasicFileAttributes.class)
              .fileKey())) Files.setPosixFilePermissions(target, originalMode);
    }
  }

  @Test
  void invalidViewSeparatelyReportsLiveInMemoryHoldsWithoutCreditingDurableZero() throws Exception {
    var budgets = seeded();
    try (var reservation =
        budgets.reserve("pending-app", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)) {
      assertTrue(reservation.allowed());
      Path bad = Files.createFile(root.resolve("budget/unrecognized-root-member"));
      var diagnostic = budgets.diagnostics();
      assertFalse(diagnostic.valid());
      assertTrue(diagnostic.usage().isEmpty());
      assertEquals(2, diagnostic.activeFamilyLeases());
      assertEquals(2, diagnostic.reservedFamilyRates());
      Files.delete(bad);
    }
    assertEquals(0, budgets.diagnostics().activeFamilyLeases());
    assertTrue(budgets.diagnostics().valid());
    assertFalse(
        store().read("pending-app", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT).isPresent());
  }

  private AppNetworkBudgetService seeded() {
    var budgets = service();
    charge(budgets, SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    charge(budgets, CONTROL_APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    return budgets;
  }

  @Test
  void symbolicScopeMemberCannotSupplyAValidStrictViewOrModifyItsTarget() throws Exception {
    assumeTrue(
        root.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "Symbolic link fixture unavailable");
    var budgets = seeded();
    var control =
        store().read(CONTROL_APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT).orElseThrow();
    Path link = root.resolve("budget/linked-scope");
    Files.createSymbolicLink(link, root.resolve("budget/control-app"));
    try {
      assertFalse(budgets.diagnostics().valid());
      assertFalse(
          budgets.snapshots().isEmpty(),
          "A tolerant partial listing cannot replace strict validity");
      charge(budgets, SELECTED_APP, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
      assertEquals(
          control,
          store().read(CONTROL_APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT).orElseThrow());
    } finally {
      Files.delete(link);
    }
    assertTrue(budgets.diagnostics().valid());
  }

  private AppNetworkBudgetService service() {
    return new AppNetworkBudgetService(
        store(), new AppNetworkBudgetConfig(10, 100, 1, 16, 10, 100, 1, 8, 10, 100, 1, 8), CLOCK);
  }

  private FileAppNetworkBudgetStore store() {
    return new FileAppNetworkBudgetStore(root.resolve("budget"));
  }

  private FileTrustGraphStore graph() {
    return new FileTrustGraphStore(root.resolve("graph"), TrustGraphStoreConfig.defaults(), CLOCK);
  }

  private static AppNetworkBudgetDecision charge(
      AppNetworkBudgetService budgets, String app, AppNetworkBudgetOperation operation) {
    var decision = budgets.acquire(app, operation);
    assertTrue(decision.allowed());
    decision.lease().close();
    return decision;
  }

  private static void assertConservative(
      List<AppNetworkBudgetUsage> before, List<AppNetworkBudgetUsage> after) {
    assertEquals(before.size(), after.size());
    for (var original : before) {
      var current =
          after.stream()
              .filter(
                  row ->
                      row.appId().equals(original.appId())
                          && row.operation() == original.operation())
              .findFirst()
              .orElseThrow();
      assertEquals(original.window(), current.window());
      if (original.windowStart().equals(current.windowStart())) {
        assertTrue(current.count() >= original.count());
      } else {
        assertTrue(current.windowStart().isAfter(original.windowStart()));
        assertTrue(
            current.count() > 0,
            "A new applicable window requires an independently charged request");
      }
      if (original.appId().equals(CONTROL_APP)) assertEquals(original, current);
    }
  }

  private static boolean enumerationDenied(Path target) {
    try (var entries = Files.newDirectoryStream(target)) {
      for (Path member : entries) {
        assertTrue(member.startsWith(target), "Enumeration probe escaped its selected directory");
      }
      return false;
    } catch (IOException _) {
      return true;
    }
  }

  private static boolean readDenied(Path target) {
    try {
      Files.readString(target);
      return false;
    } catch (IOException _) {
      return true;
    }
  }

  private record DiagnosticObservations(
      Map<String, Object> before,
      Map<String, Object> during,
      Map<String, Object> after,
      Map<String, Object> recovery,
      AppNetworkBudgetDecision request,
      AppNetworkBudgetDecision recoveryRequest) {}

  private static void export(
      String variant, DiagnosticObservations observations, Map<String, Object> fault)
      throws IOException {
    var evidence = new LinkedHashMap<String, Object>();
    evidence.put("schemaVersion", 1);
    evidence.put("caseId", "diagnostics-unavailable");
    evidence.put("variant", variant);
    evidence.put("evidenceClass", "controlled-native-file-backed");
    evidence.put("before", observations.before());
    evidence.put("during", observations.during());
    evidence.put("after", observations.after());
    evidence.put("recovery", observations.recovery());
    evidence.put("fault", fault);
    evidence.put("selectedFingerprint", null);
    evidence.put("requestStatus", observations.request().statusCode());
    evidence.put("requestCode", observations.request().errorCode());
    evidence.put("recoveryStatus", observations.recoveryRequest().statusCode());
    Path directory = Path.of("build", "test-results", "pr319-native");
    TrustGraphProcessBudgetFixture.writePrivate(
        directory.resolve(variant + ".json"), PlatformApiJsonWriter.write(evidence));
    var original = new LinkedHashMap<String, Object>();
    original.put("fault", fault);
    original.put("selectedFingerprint", null);
    original.put(
        SCOPE_BINDINGS,
        Map.of(
            "before",
            observations.before().get(SCOPE_BINDINGS),
            "during",
            observations.during().get(SCOPE_BINDINGS),
            "after",
            observations.after().get(SCOPE_BINDINGS),
            "recovery",
            observations.recovery().get(SCOPE_BINDINGS)));
    TrustGraphProcessBudgetFixture.writePrivate(
        directory.resolve(variant + "-original.json"), PlatformApiJsonWriter.write(original));
  }
}
