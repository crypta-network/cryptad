package network.crypta.platform.api;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.platform.trustgraph.TrustGraphStoreConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Actual JVM termination around real stores; this is process evidence, not installed-role proof.
 */
class TrustGraphProcessBudgetTest {
  private static final String ACTIVE_PROPERTY = "active";
  private static final String BEFORE_PHASE = "before";
  private static final String RESERVED_PROPERTY = "reserved";
  private static final String COLLECTOR_EPOCH_PROPERTY = "collectorEpoch";
  private static final String RECOVERY_PHASE = "recovery";
  private static final String WORKER_PHASE = "worker";
  @TempDir Path root;

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void settledChargesAndCompleteGraphMetadataSurviveActualProcessRestart(boolean forced)
      throws IOException, InterruptedException {
    restart(forced, false);
  }

  @Test
  void abruptActiveOwnerRetainsKnownPrefixWithoutInventingCompletion()
      throws IOException, InterruptedException {
    restart(true, true);
  }

  private void restart(boolean forced, boolean active) throws IOException, InterruptedException {
    // A real hour boundary is a different oracle; never edit or silently normalize the clock.
    long secondInHour = Math.floorMod(Instant.now().getEpochSecond(), 3600);
    assumeTrue(secondInHour < 3540, "Same-hour subprocess precondition unavailable");
    Object initialIdentity = Files.readAttributes(root, BasicFileAttributes.class).fileKey();
    Map<String, Object> dataIdentity = Map.of("fileKey", String.valueOf(initialIdentity));
    String settledVariant = forced ? "settled-abrupt" : "settled-graceful";
    String variant = active ? "inflight-abrupt" : settledVariant;
    String caseId = forced ? "abrupt-restart" : "graceful-restart";
    Map<String, Object> transition;
    Properties beforeFacts;
    List<network.crypta.platform.api.networkbudget.AppNetworkBudgetUsage> beforeRates;
    List<network.crypta.platform.trustgraph.TrustGraphStore.StoredTrustStatement> beforeGraph;
    long oldPid;
    int exitCode;

    try (var original = start(false)) {
      original.command("seed");
      if (active) original.command(ACTIVE_PROPERTY);
      original.command(BEFORE_PHASE);
      beforeFacts = facts(BEFORE_PHASE);
      beforeRates = rates();
      beforeGraph = graph().statements();
      assertEquals(2, beforeGraph.size());
      assertEquals(active ? "4" : "0", beforeFacts.getProperty(ACTIVE_PROPERTY));
      assertEquals(active ? "2" : "0", beforeFacts.getProperty(RESERVED_PROPERTY));
      assertTrue(
          beforeRates.stream()
              .noneMatch(
                  row ->
                      row.appId().equals("pending-app")
                          && row.operation() == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
      oldPid = original.process.pid();
      assertTrue(original.process.isAlive());
      if (forced) original.process.destroyForcibly();
      else original.write("stop");
      assertTrue(
          original.process.waitFor(10, TimeUnit.SECONDS), "Old owner must die before new start");
      assertFalse(original.process.isAlive());
      exitCode = original.process.exitValue();
      if (!forced) assertEquals(0, exitCode, "Graceful exit cannot be an escalation");
      else assertNotEquals(0, exitCode);
    }

    assertEquals(initialIdentity, Files.readAttributes(root, BasicFileAttributes.class).fileKey());
    try (var recovered = start(true)) {
      recovered.command("after");
      var afterFacts = facts("after");
      assertNotEquals(oldPid, recovered.process.pid());
      assertNotEquals(
          beforeFacts.getProperty(COLLECTOR_EPOCH_PROPERTY),
          afterFacts.getProperty(COLLECTOR_EPOCH_PROPERTY));
      assertEquals("0", afterFacts.getProperty(ACTIVE_PROPERTY));
      assertEquals("0", afterFacts.getProperty(RESERVED_PROPERTY));
      assertEquals(
          beforeRates,
          rates(),
          "All retained windows and decision metadata must match before admission");
      assertEquals(
          beforeGraph,
          graph().statements(),
          "Equal cardinality cannot hide changed graph metadata");
      transition =
          Map.of(
              "kind",
              forced ? "forced" : "graceful",
              "oldPid",
              oldPid,
              "aliveBefore",
              true,
              "exitCode",
              exitCode,
              "deadBeforeRestart",
              true,
              "newPid",
              recovered.process.pid(),
              "forced",
              forced);
      recovered.command(RECOVERY_PHASE);
      assertEquals(
          "trust_graph_import_budget_exhausted", facts("recovery-result").getProperty("denial"));
      assertRecoveryState(beforeRates, beforeGraph);
      export(variant, caseId, transition, dataIdentity, active);
      recovered.write("stop");
      assertTrue(recovered.process.waitFor(10, TimeUnit.SECONDS));
      assertEquals(0, recovered.process.exitValue());
    }
  }

  private void assertRecoveryState(
      List<network.crypta.platform.api.networkbudget.AppNetworkBudgetUsage> beforeRates,
      List<network.crypta.platform.trustgraph.TrustGraphStore.StoredTrustStatement> beforeGraph)
      throws IOException {
    var afterRates = rates();
    for (var before : beforeRates) {
      var after =
          afterRates.stream()
              .filter(
                  row ->
                      row.appId().equals(before.appId()) && row.operation() == before.operation())
              .findFirst()
              .orElseThrow();
      assertEquals(before.windowStart(), after.windowStart());
      assertTrue(after.count() >= before.count());
      if (before.appId().equals("control-app")) assertEquals(before, after);
    }
    assertEquals(
        1,
        afterRates.stream()
            .filter(
                row ->
                    row.appId().equals("pending-app")
                        && row.operation() == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)
            .findFirst()
            .orElseThrow()
            .count());
    assertEquals(3, graph().statements().size());
    for (var before : beforeGraph) assertTrue(graph().statements().contains(before));
    assertEquals("0", facts(RECOVERY_PHASE).getProperty(ACTIVE_PROPERTY));
    assertEquals("0", facts(RECOVERY_PHASE).getProperty(RESERVED_PROPERTY));
  }

  @Test
  void workerOnlyProcessRestartLeavesDaemonEpochAndQuotaUnchanged() throws Exception {
    try (var daemon = start(false)) {
      daemon.command("seed");
      daemon.command(BEFORE_PHASE);
      var before = facts(BEFORE_PHASE);
      var beforeRates = rates();
      daemon.command(WORKER_PHASE);
      assertEquals(before.getProperty("pid"), facts(WORKER_PHASE).getProperty("pid"));
      assertEquals(
          before.getProperty(COLLECTOR_EPOCH_PROPERTY),
          facts(WORKER_PHASE).getProperty(COLLECTOR_EPOCH_PROPERTY));
      assertNotEquals(before.getProperty("pid"), facts("worker-witness").getProperty("pid"));
      assertEquals(beforeRates, rates());
      daemon.command(RECOVERY_PHASE);
      assertEquals(
          "trust_graph_import_budget_exhausted", facts("recovery-result").getProperty("denial"));
    }
  }

  private void export(
      String variant,
      String caseId,
      Map<String, Object> transition,
      Map<String, Object> dataIdentity,
      boolean active)
      throws IOException {
    String bindings =
        "{\"before\":"
            + Files.readString(root.resolve("before-bindings.json"))
            + ",\"after\":"
            + Files.readString(root.resolve("after-bindings.json"))
            + ",\"recovery\":"
            + Files.readString(root.resolve("recovery-bindings.json"))
            + "}";
    String pending = active ? pendingIds() : "[]";
    String selectedFingerprint =
        graph().statements().stream()
            .filter(row -> "selected-before".equals(row.sourceLabel()))
            .findFirst()
            .orElseThrow()
            .documentFingerprint();
    String evidence =
        "{\"schemaVersion\":1,\"caseId\":"
            + PlatformApiJsonWriter.write(caseId)
            + ",\"variant\":"
            + PlatformApiJsonWriter.write(variant)
            + ",\"evidenceClass\":\"controlled-native-process-file-backed\",\"before\":"
            + Files.readString(root.resolve("before.json"))
            + ",\"after\":"
            + Files.readString(root.resolve("after.json"))
            + ",\"recovery\":"
            + Files.readString(root.resolve("recovery.json"))
            + ",\"transition\":"
            + PlatformApiJsonWriter.write(transition)
            + ",\"dataIdentity\":"
            + PlatformApiJsonWriter.write(dataIdentity)
            + ",\"pendingOperationIds\":"
            + pending
            + ",\"selectedFingerprint\":"
            + PlatformApiJsonWriter.write(selectedFingerprint)
            + ",\"tailStatus\":"
            + PlatformApiJsonWriter.write(active ? "censored" : "complete")
            + "}";
    Path directory = Path.of("build", "test-results", "pr319-native");
    TrustGraphProcessBudgetFixture.writePrivate(directory.resolve(variant + ".json"), evidence);
    TrustGraphProcessBudgetFixture.writePrivate(
        directory.resolve(variant + "-original.json"),
        "{\"transition\":"
            + PlatformApiJsonWriter.write(transition)
            + ",\"dataIdentity\":"
            + PlatformApiJsonWriter.write(dataIdentity)
            + ",\"scopeBindings\":"
            + bindings
            + ",\"selectedFingerprint\":"
            + PlatformApiJsonWriter.write(selectedFingerprint)
            + "}");
  }

  private String pendingIds() throws IOException {
    String json = Files.readString(root.resolve("before-pending.json"));
    assertNotEquals("[]", json, "Observed pending native owners are required");
    return json;
  }

  private Child start(boolean recovering) throws IOException {
    Path stderr = root.resolve(recovering ? "new-stderr.txt" : "old-stderr.txt");
    var process =
        new ProcessBuilder(
                TrustGraphProcessBudgetFixture.javaExecutable(),
                "-cp",
                TrustGraphProcessBudgetFixture.childClasspath(),
                TrustGraphProcessBudgetFixture.class.getName(),
                root.toString(),
                recovering ? "recover" : "initial")
            .redirectError(stderr.toFile())
            .redirectOutput(root.resolve(recovering ? "new-stdout.txt" : "old-stdout.txt").toFile())
            .start();
    return new Child(process, stderr);
  }

  private Properties facts(String phase) throws IOException {
    var result = new Properties();
    try (var input = Files.newInputStream(root.resolve(phase + ".properties"))) {
      result.load(input);
    }
    return result;
  }

  private List<network.crypta.platform.api.networkbudget.AppNetworkBudgetUsage> rates()
      throws IOException {
    return new FileAppNetworkBudgetStore(root.resolve("budget")).observe(4096);
  }

  private FileTrustGraphStore graph() {
    return new FileTrustGraphStore(
        root.resolve("graph"), TrustGraphStoreConfig.defaults(), Clock.systemUTC());
  }

  private final class Child implements AutoCloseable {
    final Process process;
    final BufferedWriter input;
    final Path stderr;

    Child(Process process, Path stderr) {
      this.process = process;
      this.stderr = stderr;
      input =
          new BufferedWriter(
              new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
    }

    void write(String command) throws IOException {
      input.write(command);
      input.newLine();
      input.flush();
    }

    void command(String command) throws IOException, InterruptedException {
      Path done = root.resolve(command + ".done");
      try (var watcher = root.getFileSystem().newWatchService()) {
        root.register(watcher, StandardWatchEventKinds.ENTRY_CREATE);
        Files.deleteIfExists(done);
        write(command);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        boolean waiting = true;
        while (waiting && !Files.exists(done) && process.isAlive()) {
          long remaining = deadline - System.nanoTime();
          var key = remaining > 0 ? watcher.poll(remaining, TimeUnit.NANOSECONDS) : null;
          if (key == null) {
            waiting = false;
          } else {
            boolean completed =
                key.pollEvents().stream()
                    .anyMatch(event -> done.getFileName().equals(event.context()));
            waiting = key.reset() && !completed;
          }
        }
      }
      assertTrue(
          Files.exists(done),
          "Native child failed command " + command + ": " + Files.readString(stderr));
    }

    @Override
    public void close() throws IOException, InterruptedException {
      if (process.isAlive()) {
        process.destroyForcibly();
        assertTrue(process.waitFor(10, TimeUnit.SECONDS), "Owned test JVM leaked");
      }
      input.close();
    }
  }
}
