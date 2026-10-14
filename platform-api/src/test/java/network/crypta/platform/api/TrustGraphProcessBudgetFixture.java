package network.crypta.platform.api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetScope;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustGraphStoreConfig;
import network.crypta.platform.trustgraph.TrustIssuer;
import network.crypta.platform.trustgraph.TrustSignatureEnvelope;
import network.crypta.platform.trustgraph.TrustStatementCanonicalizer;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementFingerprint;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;

/** Test-only child JVM producer; every rate and graph mutation uses the native implementations. */
public final class TrustGraphProcessBudgetFixture {
  private static final String SELECTED_APP = "selected-app";
  private static final String CONTROL_APP = "control-app";
  private static final String PENDING_APP = "pending-app";
  private static final String RECOVERY_APP = "recovery-app";
  private static final String WORKER_PHASE = "worker";
  private static final String ACTIVE_PHASE = "active";
  static final List<String> APPS =
      List.of(SELECTED_APP, CONTROL_APP, PENDING_APP, RECOVERY_APP, "fault-app");
  private final Path root;
  private final AppNetworkBudgetService budgets;
  private final FileTrustGraphStore graph;
  private final TrustGraphApiHandler handler;

  private TrustGraphProcessBudgetFixture(Path root, boolean recovering) {
    this.root = root;
    var clock = Clock.systemUTC();
    budgets =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(root.resolve("budget")), limits());
    graph = new FileTrustGraphStore(root.resolve("graph"), TrustGraphStoreConfig.defaults(), clock);
    handler = new TrustGraphApiHandler(graph, clock, budgets);
    // Deliberately alter app scope numbering across epochs; identities must come from bindings.
    if (recovering) budgets.observation().scope(RECOVERY_APP);
  }

  static AppNetworkBudgetConfig limits() {
    return new AppNetworkBudgetConfig(10, 100, 1, 16, 10, 100, 1, 8, 1, 100, 1, 8);
  }

  static void main(String[] args)
      throws IOException,
          InterruptedException,
          GeneralSecurityException,
          ReflectiveOperationException {
    if (args.length == 1 && args[0].equals(WORKER_PHASE)) return;
    var fixture = new TrustGraphProcessBudgetFixture(Path.of(args[0]), args[1].equals("recover"));
    try (var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
      for (String command; (command = input.readLine()) != null; ) {
        switch (command) {
          case "seed" -> fixture.seed();
          case ACTIVE_PHASE -> fixture.active();
          case "before", "after" -> fixture.phase(command);
          case "recovery" -> fixture.recover();
          case WORKER_PHASE -> fixture.worker();
          case "stop" -> {
            return;
          }
          default -> throw new IllegalArgumentException("Unknown test command");
        }
      }
    }
  }

  private void seed() throws IOException, GeneralSecurityException, ReflectiveOperationException {
    invoke(CONTROL_APP, signedStatement(25), "control-before");
    invoke(SELECTED_APP, signedStatement(50), "selected-before");
    charge(CONTROL_APP, AppNetworkBudgetOperation.SUBSCRIPTION_POLL);
    phase("seed");
  }

  private void active()
      throws IOException,
          InterruptedException,
          GeneralSecurityException,
          ReflectiveOperationException {
    var entered = new CountDownLatch(1);
    var neverRelease = new CountDownLatch(1);
    var document = signedStatement(75);
    var thread =
        new Thread(
            () ->
                handler.importUri(
                    Map.of("uri", List.of("CHK@synthetic-pr319")),
                    request -> {
                      entered.countDown();
                      try {
                        neverRelease.await();
                      } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("Interrupted test owner", exception);
                      }
                      return new network.crypta.runtime.spi.BoundedContentFetchResult(
                          PlatformApiJsonWriter.write(document.toJson())
                              .getBytes(StandardCharsets.UTF_8),
                          request.uri(),
                          request.uri(),
                          "ok");
                    },
                    PENDING_APP),
            "pr319-native-fetch-owner");
    thread.start();
    if (!entered.await(10, TimeUnit.SECONDS))
      throw new IllegalStateException("Native owner not active");
    phase(ACTIVE_PHASE);
  }

  private void recover()
      throws IOException, GeneralSecurityException, ReflectiveOperationException {
    Properties result = new Properties();
    try {
      invoke(
          SELECTED_APP,
          graph.statements().stream()
              .filter(row -> "selected-before".equals(row.sourceLabel()))
              .findFirst()
              .orElseThrow()
              .document(),
          "denied-recovery");
      throw new IllegalStateException("Exhausted quota reset");
    } catch (PlatformApiException exception) {
      result.setProperty("denial", exception.errorCode());
    }
    invoke(RECOVERY_APP, signedStatement(90), "independent-recovery");
    // The dead owner's pending reservation must not consume this hour's import quota.
    charge(PENDING_APP, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    try (var output = Files.newOutputStream(root.resolve("recovery-result.properties"))) {
      result.store(output, "native result");
    }
    phase("recovery");
  }

  private void worker() throws IOException, InterruptedException, ReflectiveOperationException {
    Process worker =
        new ProcessBuilder(
                javaExecutable(), "-cp", childClasspath(), getClass().getName(), WORKER_PHASE)
            .start();
    if (!worker.waitFor(10, TimeUnit.SECONDS) || worker.exitValue() != 0) {
      worker.destroyForcibly();
      throw new IllegalStateException("Worker control failed");
    }
    Properties witness = new Properties();
    witness.setProperty("pid", Long.toString(worker.pid()));
    try (var output = Files.newOutputStream(root.resolve("worker-witness.properties"))) {
      witness.store(output, "test worker control");
    }
    phase(WORKER_PHASE);
  }

  static String javaExecutable() {
    return Path.of(System.getProperty("java.home"), "bin", "java").toString();
  }

  static String childClasspath() {
    // Gradle may use a worker bootstrap jar rather than the full application classpath property.
    var entries = new java.util.LinkedHashSet<String>();
    for (ClassLoader loader = TrustGraphProcessBudgetFixture.class.getClassLoader();
        loader != null;
        loader = loader.getParent()) {
      if (loader instanceof java.net.URLClassLoader urls) {
        for (var url : urls.getURLs()) {
          try {
            entries.add(Path.of(url.toURI()).toString());
          } catch (java.net.URISyntaxException exception) {
            throw new IllegalStateException(exception);
          }
        }
      }
    }
    for (Class<?> type :
        List.of(
            TrustGraphProcessBudgetFixture.class,
            AppNetworkBudgetService.class,
            FileTrustGraphStore.class,
            network.crypta.platform.apphost.manifest.AppManifest.class,
            network.crypta.fs.AppEnv.class,
            network.crypta.runtime.spi.ContentFetchPort.class,
            network.crypta.support.SimpleFieldSet.class)) {
      try {
        entries.add(
            Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
      } catch (java.net.URISyntaxException exception) {
        throw new IllegalStateException(exception);
      }
    }
    entries.add(System.getProperty("java.class.path"));
    return String.join(java.io.File.pathSeparator, entries);
  }

  private void invoke(String app, TrustStatementDocument document, String label) {
    handler.importStatement(
        Map.of(
            "document",
            List.of(PlatformApiJsonWriter.write(document.toJson())),
            "source",
            List.of("manual"),
            "sourceLabel",
            List.of(label),
            "subscriptionId",
            List.of("synthetic-control")),
        app);
  }

  private void charge(String app, AppNetworkBudgetOperation family) {
    var decision = budgets.acquire(app, family);
    if (!decision.allowed()) throw new IllegalStateException("Native admission missing");
    decision.lease().close();
  }

  private void phase(String name) throws IOException, ReflectiveOperationException {
    Map<String, Object> phase = phaseValue(budgets, graph);
    writePrivate(root.resolve(name + ".json"), PlatformApiJsonWriter.write(phase));
    Properties facts = new Properties();
    facts.setProperty("pid", Long.toString(ProcessHandle.current().pid()));
    facts.setProperty("collectorEpoch", budgets.observation().snapshot().collectorEpoch());
    facts.setProperty(ACTIVE_PHASE, Long.toString(budgets.diagnostics().activeFamilyLeases()));
    facts.setProperty("reserved", Long.toString(budgets.diagnostics().reservedFamilyRates()));
    facts.setProperty("valid", Boolean.toString(budgets.diagnostics().valid()));
    try (var output = Files.newOutputStream(root.resolve(name + ".properties"))) {
      facts.store(output, "native phase facts");
    }
    writePrivate(
        root.resolve(name + "-bindings.json"),
        PlatformApiJsonWriter.write(phase.get("scopeBindings")));
    var pending = new java.util.LinkedHashSet<Long>();
    var held = new LinkedHashMap<Long, Integer>();
    for (var event : budgets.observation().snapshot().events()) {
      switch (event.kind()) {
        case CONCURRENCY_HELD -> held.merge(event.operationId(), 1, Integer::sum);
        case CONCURRENCY_RELEASED -> held.merge(event.operationId(), -1, Integer::sum);
        default -> {
          // Only concurrency transitions identify currently held budget operations.
        }
      }
    }
    held.forEach(
        (id, count) -> {
          if (count > 0) pending.add(id);
        });
    writePrivate(root.resolve(name + "-pending.json"), PlatformApiJsonWriter.write(pending));
    writePrivate(root.resolve(name + ".done"), "ready");
  }

  public static Map<String, Object> phaseValue(
      AppNetworkBudgetService budgets, FileTrustGraphStore graph)
      throws ReflectiveOperationException {
    var diagnostic = budgets.diagnostics();
    var bindings = new ArrayList<Map<String, Object>>();
    var scopes = new ArrayList<>(APPS);
    scopes.add(AppNetworkBudgetScope.GLOBAL);
    scopes.add(AppNetworkBudgetScope.HOST_OPERATOR);
    for (String app : scopes)
      bindings.add(Map.of("appId", app, "scope", budgets.observation().scope(app)));
    Map<String, Object> diagnostics = new LinkedHashMap<>();
    diagnostics.put("valid", diagnostic.valid());
    diagnostics.put("observedAt", diagnostic.observedAt().toString());
    diagnostics.put("activeFamilyLeases", diagnostic.activeFamilyLeases());
    diagnostics.put("reservedFamilyRates", diagnostic.reservedFamilyRates());
    var usage = new ArrayList<Map<String, Object>>();
    for (var row : diagnostic.usage()) {
      var value = new LinkedHashMap<String, Object>();
      value.put("appId", row.appId());
      value.put("operation", row.operation().jsonValue());
      value.put("windowStart", row.windowStart().toString());
      value.put("windowSeconds", row.windowSeconds());
      value.put("count", row.count());
      value.put("limit", row.limit());
      value.put("lastDecision", row.lastDecision());
      value.put("lastDecisionAt", string(row.lastDecisionAt()));
      value.put("nextAvailableAt", string(row.nextAvailableAt()));
      usage.add(value);
    }
    diagnostics.put("usage", usage);
    return Map.of(
        "pid",
        ProcessHandle.current().pid(),
        "collectorEpoch",
        budgets.observation().snapshot().collectorEpoch(),
        "nativeSnapshot",
        jsonValue(budgets.observation().snapshot()),
        "diagnostics",
        diagnostics,
        "scopeBindings",
        bindings,
        "graph",
        jsonValue(graph.statements()));
  }

  private static String string(Object value) {
    return value == null ? null : value.toString();
  }

  private static Object jsonValue(Object value) throws ReflectiveOperationException {
    if (value == null
        || value instanceof Number
        || value instanceof Boolean
        || value instanceof String) return value;
    if (value instanceof Instant || value instanceof Enum<?>) return value.toString();
    if (value instanceof TrustStatementDocument document) return document.toJson();
    if (value instanceof List<?> list) {
      var result = new ArrayList<>();
      for (Object item : list) result.add(jsonValue(item));
      return result;
    }
    if (value.getClass().isRecord()) {
      var result = new LinkedHashMap<String, Object>();
      for (var component : value.getClass().getRecordComponents())
        result.put(component.getName(), jsonValue(component.getAccessor().invoke(value)));
      return result;
    }
    throw new IllegalArgumentException("Unsupported native fixture value");
  }

  public static void writePrivate(Path target, String text) throws IOException {
    Files.createDirectories(target.getParent());
    if (target.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(
          target.getParent(), java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
      if (!Files.exists(target))
        Files.createFile(
            target,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
      Files.setPosixFilePermissions(
          target, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
    }
    Files.writeString(target, text);
  }

  private static TrustStatementDocument signedStatement(int score) throws GeneralSecurityException {
    var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var payload =
        new TrustStatementPayload(
            new TrustIssuer(
                "fixture-" + score,
                TrustStatementFingerprint.sha256Hex(pair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                "USK@example/profile"),
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/subject", null),
            "profile",
            score,
            80,
            "synthetic",
            List.of("fixture"),
            Instant.now().minusSeconds(60),
            null);
    var signature = Signature.getInstance("Ed25519");
    signature.initSign(pair.getPrivate());
    signature.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    return new TrustStatementDocument(
        TrustDocumentTypes.TRUST_STATEMENT_V1,
        payload,
        new TrustSignatureEnvelope(
            TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            Base64.getEncoder().encodeToString(signature.sign())));
  }
}
