package network.crypta.platform.devtools;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityFinding;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityFindingSeverity;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityVerificationResult;
import network.crypta.platform.api.PlatformApiContractVerifier;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogBuildRequest;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogSecurityAction;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisoryRecord;
import network.crypta.platform.appcatalog.AppCatalogSecurityPolicy;
import network.crypta.platform.appcatalog.AppCatalogSecuritySeverity;
import network.crypta.platform.appcatalog.AppCatalogSecurityStatus;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appcatalog.AppCatalogVersionDenylistEntry;
import network.crypta.platform.appcatalog.AppCatalogWriter;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptIO;
import network.crypta.platform.appcatalog.AppReviewReceiptPayload;
import network.crypta.platform.appcatalog.AppReviewReceiptSigner;
import network.crypta.platform.appcatalog.AppReviewReceiptStatus;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTransparencyVerificationResult;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.FileAppReviewTransparencyStore;
import network.crypta.platform.appcatalog.TrustedReviewerKey;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.AppDistributionTool;
import network.crypta.platform.appdist.PackagedAppBundle;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.devtools.devserver.CryptaAppDevServer;
import network.crypta.platform.devtools.devserver.DevServerConfig;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine;

/**
 * Command-line entry point for third-party Crypta app development workflows.
 *
 * <p>The CLI focuses on standalone staged bundles and catalog authoring. It delegates signing,
 * verification, bundle parsing, and catalog parsing to the production leaf modules instead of
 * reimplementing those formats locally. The commands are intentionally thin: scaffolding lives in
 * this developer-tooling module, bundle packaging stays in {@code platform-appdist}, and catalog
 * writing/signing stays in {@code platform-appcatalog}.
 *
 * <p>The installed command is named {@code crypta-app}. It is designed for app authors who do not
 * depend on Cryptad's first-party Gradle tasks: initialize a staged bundle, validate it, sign it,
 * package it as a deterministic ZIP, then create and sign a catalog that references the ZIP.
 * Runtime installation, app hosting, and remote catalog transport remain outside this tooling entry
 * point.
 */
@Command(
    name = "crypta-app",
    mixinStandardHelpOptions = true,
    description = "Create, validate, lint, package, sign, and catalog Crypta app bundles.",
    subcommands = {
      CryptaAppCli.InitCommand.class,
      CryptaAppCli.DevCommand.class,
      CryptaAppCli.AppTestCommand.class,
      CryptaAppCli.ValidateCommand.class,
      CryptaAppCli.KeysCommand.class,
      CryptaAppCli.PackCommand.class,
      CryptaAppCli.SignCommand.class,
      CryptaAppCli.VerifyCommand.class,
      CryptaAppCli.ApiCommand.class,
      CryptaAppCli.CompatCommand.class,
      CryptaAppCli.UiCommand.class,
      CryptaAppCli.ReviewCommand.class,
      CryptaAppCli.CatalogCommand.class,
      CryptaAppCli.PublishUskCommand.class
    })
public final class CryptaAppCli implements Runnable {
  private static final String WARNING_PREFIX = "Warning: ";
  private static final String FIELD_ACTION = "action";
  private static final String FIELD_REPLACEMENT_APP_ID = "replacementAppId";
  private static final String FIELD_SAFE_UNINSTALL_GUIDANCE = "safeUninstallGuidance";
  private static final String FIELD_SEVERITY = "severity";
  private static final String FIELD_STATUS = "status";
  private static final String OPTION_SECURITY_ADVISORY_RECORD = "--security-advisory-record";
  private static final String OPTION_SECURITY_DENYLIST_ENTRY = "--security-denylist-entry";

  private static final AtomicReference<LiveUskPublisher> LIVE_USK_PUBLISHER_OVERRIDE =
      new AtomicReference<>();

  private CommandSpec spec;

  /**
   * Creates a root command instance for picocli.
   *
   * <p>Production launches normally enter through {@link #main(String[])}. Tests and embedded
   * tooling may create an instance indirectly through {@link CommandLine} when they need the same
   * command tree without starting a new JVM process.
   */
  public CryptaAppCli() {
    // Picocli uses the no-argument constructor before injecting command metadata.
  }

  // Picocli discovers this method through @Spec when it builds the command model.
  @SuppressWarnings("unused")
  @Spec
  void setSpec(CommandSpec spec) {
    this.spec = spec;
  }

  /**
   * Runs the command-line application.
   *
   * <p>The method wires UTF-8 writers around standard output streams so help text, diagnostics, and
   * generated paths are printed consistently when the Gradle application plugin launches the tool.
   * The process exits with picocli's command status code.
   *
   * @param arguments command-line arguments passed to {@code crypta-app}
   */
  public static void main(String[] arguments) {
    System.exit(
        execute(
            new PrintWriter(
                new OutputStreamWriter(
                    new FileOutputStream(FileDescriptor.out), StandardCharsets.UTF_8),
                true),
            new PrintWriter(
                new OutputStreamWriter(
                    new FileOutputStream(FileDescriptor.err), StandardCharsets.UTF_8),
                true),
            arguments));
  }

  /**
   * Executes the CLI with caller-provided output streams.
   *
   * <p>Tests use this method to capture stdout and stderr without launching a new process. Runtime
   * command failures are rendered as concise messages through picocli's execution exception handler
   * and converted to a software error exit code.
   *
   * @param out stream used for command output and help text
   * @param err stream used for command diagnostics
   * @param arguments command-line arguments to parse and execute
   * @return picocli exit code for the command invocation
   */
  static int execute(PrintWriter out, PrintWriter err, String... arguments) {
    CommandLine commandLine = new CommandLine(new CryptaAppCli());
    commandLine.setOut(out);
    commandLine.setErr(err);
    commandLine.setExecutionExceptionHandler(
        (exception, parsedCommand, _) -> {
          parsedCommand.getErr().println(exception.getMessage());
          return CommandLine.ExitCode.SOFTWARE;
        });
    return commandLine.execute(arguments);
  }

  static AutoCloseable useLiveUskPublisherForTesting(LiveUskPublisher publisher) {
    LiveUskPublisher previous = LIVE_USK_PUBLISHER_OVERRIDE.getAndSet(publisher);
    return () -> LIVE_USK_PUBLISHER_OVERRIDE.set(previous);
  }

  /** Prints root command usage when no subcommand is selected. */
  @Override
  public void run() {
    commandLine().usage(commandLine().getOut());
  }

  private CommandLine commandLine() {
    return spec.commandLine();
  }

  /**
   * Implements {@code crypta-app init} for standalone staged bundle scaffolding.
   *
   * <p>The command converts CLI options into an {@link AppTemplateScaffolder.ScaffoldRequest}. It
   * does not register a Gradle project or modify repository settings; the output is just a staged
   * bundle directory that can be validated, signed, and packaged by the other commands.
   */
  @Command(name = "init", description = "Scaffold a standalone staged app bundle.")
  static final class InitCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--dir", required = true, description = "Target staged bundle directory.")
    private Path directory;

    @Option(names = "--app-id", required = true, description = "Stable app id.")
    private String appId;

    @Option(names = "--name", required = true, description = "Display name.")
    private String name;

    @Option(names = "--version", required = true, description = "App version.")
    private String version;

    @Option(
        names = "--ui-mode",
        defaultValue = "static",
        description = "UI template mode: static, shell-panel, or none.")
    private String uiMode;

    @Option(
        names = "--template",
        defaultValue = "static-basic",
        description =
            "Beta app template: ${COMPLETION-CANDIDATES}. Supported: "
                + "static-basic, queue-dashboard, publisher, vault-profile.")
    private String template;

    @Option(names = "--permission", description = "Manifest permission to add; repeatable.")
    private List<String> permissions = new ArrayList<>();

    @Option(names = "--overwrite", description = "Overwrite scaffold-managed files.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      Path scaffolded =
          AppTemplateScaffolder.scaffold(
              new AppTemplateScaffolder.ScaffoldRequest(
                  directory,
                  appId,
                  name,
                  version,
                  AppTemplateScaffolder.UiMode.parse(uiMode),
                  AppTemplateKind.parse(template),
                  permissions,
                  overwrite));
      super.commandLine().getOut().println("Initialized app bundle at " + scaffolded);
      return CommandLine.ExitCode.OK;
    }
  }

  /** Implements {@code crypta-app dev} for local static UI and mock Platform API serving. */
  @Command(name = "dev", description = "Serve a staged static app bundle with a mock Platform API.")
  static final class DevCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--host", defaultValue = "127.0.0.1", description = "Listener host.")
    private String host;

    @Option(names = "--port", defaultValue = "0", description = "Listener port, or 0 for any.")
    private int port;

    @Option(names = "--fixture-dir", description = "Directory containing JSON mock fixtures.")
    private Path fixtureDir;

    @Option(
        names = "--open",
        defaultValue = "false",
        arity = "1",
        description = "Print browser-open hint: true or false.")
    private boolean open;

    @Option(
        names = "--session-ttl-seconds",
        defaultValue = "3600",
        description = "Mock browser-session lifetime.")
    private long sessionTtlSeconds;

    @Option(
        names = "--allow-non-loopback",
        description = "Allow binding the dev server to a non-loopback host.")
    private boolean allowNonLoopback;

    @Override
    public Integer call() throws Exception {
      try (CryptaAppDevServer server =
          CryptaAppDevServer.start(
              new DevServerConfig(
                  bundleDir,
                  host,
                  port,
                  fixtureDir,
                  allowNonLoopback,
                  Duration.ofSeconds(sessionTtlSeconds)))) {
        Runtime.getRuntime().addShutdownHook(new Thread(server::close, "crypta-app-dev-shutdown"));
        super.commandLine().getOut().println(server.startupSummary());
        if (open) {
          super.commandLine().getOut().println("Open: " + server.uiUrl());
        }
        Thread.currentThread().join();
      }
      return CommandLine.ExitCode.OK;
    }
  }

  /** Implements {@code crypta-app test} for offline developer checks. */
  @Command(name = "test", description = "Run the offline app developer test suite.")
  static final class AppTestCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--strict", description = "Treat warnings as failures.")
    private boolean strict;

    @Option(names = "--contract", description = "Platform API contract JSON snapshot.")
    private Path contract;

    @Option(names = "--catalog-entry", description = "Optional catalog entry descriptor.")
    private Path catalogEntry;

    @Option(names = "--json", description = "Write deterministic JSON report.")
    private Path jsonOutput;

    @Override
    public Integer call() throws Exception {
      AppTestReport report =
          AppTestSuite.run(new AppTestSuite.Request(bundleDir, strict, contract, catalogEntry));
      for (AppTestCheck check : report.checks()) {
        super.commandLine()
            .getOut()
            .println(check.id() + " " + check.status().jsonValue() + ": " + check.summary());
      }
      super.commandLine()
          .getOut()
          .println(
              "App test suite "
                  + report.status().jsonValue()
                  + ": "
                  + report.appId()
                  + " "
                  + report.version());
      if (jsonOutput != null) {
        Path normalizedJsonOutput = jsonOutput.toAbsolutePath().normalize();
        Path parent = normalizedJsonOutput.getParent();
        if (parent != null) {
          Files.createDirectories(parent);
        }
        Files.writeString(
            normalizedJsonOutput, AppTestReportJson.write(report), StandardCharsets.UTF_8);
      }
      return report.status() == AppTestStatus.FAIL
          ? CommandLine.ExitCode.SOFTWARE
          : CommandLine.ExitCode.OK;
    }
  }

  /** Parent command for local developer signing key operations. */
  @Command(
      name = "keys",
      description = "Generate local developer app signing keys.",
      subcommands = {KeysGenerateCommand.class})
  static final class KeysCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app keys generate}. */
  @Command(name = "generate", description = "Generate a local Ed25519 app signing key pair.")
  static final class KeysGenerateCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--key-id", required = true, description = "Signing key id.")
    private String keyId;

    @Option(names = "--private-key-file", required = true, description = "Private key output file.")
    private Path privateKeyFile;

    @Option(names = "--public-key-file", required = true, description = "Public key output file.")
    private Path publicKeyFile;

    @Option(names = "--trusted-keys-file", description = "Trusted app keys properties output.")
    private Path trustedKeysFile;

    @Option(names = "--overwrite", description = "Replace existing key files.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      printKeyPathWarning(privateKeyFile);
      printKeyPathWarning(publicKeyFile);
      if (trustedKeysFile != null) {
        printKeyPathWarning(trustedKeysFile);
      }
      DeveloperKeyGenerator.GeneratedKeys generated =
          DeveloperKeyGenerator.generate(
              keyId, privateKeyFile, publicKeyFile, trustedKeysFile, overwrite);
      super.commandLine()
          .getOut()
          .println(
              "Generated app signing key: "
                  + keyId
                  + " public="
                  + generated.publicKeyFile().getFileName());
      if (generated.trustedKeysFile() != null) {
        super.commandLine().getOut().println("Wrote trusted keys file.");
      }
      return CommandLine.ExitCode.OK;
    }

    private void printKeyPathWarning(Path path) {
      String warning = DeveloperKeyGenerator.repoPathWarning(path);
      if (!warning.isBlank()) {
        super.commandLine().getErr().println(warning);
      }
    }
  }

  /**
   * Implements {@code crypta-app validate} for staged bundle checks.
   *
   * <p>The command reports production parser and structure failures as command failures. Unknown
   * capability names remain warnings unless strict mode is enabled, which lets developers adopt new
   * manifest permissions deliberately while keeping CI policies enforceable.
   */
  @Command(name = "validate", description = "Validate a staged app bundle.")
  static final class ValidateCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(
        names = "--strict",
        description = "Treat validation, compatibility, and UI lint warnings as failures.")
    private boolean strict;

    @Override
    public Integer call() throws Exception {
      BundleValidation validation = BundleValidator.validate(bundleDir, false);
      if (validation.permissionLint().hasUnknownPermissions()) {
        super.commandLine()
            .getErr()
            .println(
                WARNING_PREFIX
                    + "unknown app permission(s): "
                    + String.join(", ", validation.permissionLint().unknownPermissions()));
      }
      CompatibilityVerificationResult compatibility =
          PlatformApiContractVerifier.verify(
              validation.manifest().apiCompatibility(),
              validation.manifest().permissions(),
              DevtoolsCapabilityVocabulary.currentValidationContract(),
              strict);
      printCompatibilityFindings(super.commandLine(), compatibility);
      if (compatibility.hasErrors()) {
        throw new AppDistributionException("compatibility verification failed");
      }
      if (strict) {
        AppUiLintResult uiLint = AppUiLinter.lint(bundleDir, true);
        printUiLintFindings(super.commandLine(), uiLint);
        if (uiLint.hasErrors()) {
          throw new AppDistributionException("UI lint failed");
        }
      }
      super.commandLine()
          .getOut()
          .println(
              "Bundle is valid: "
                  + validation.manifest().appId()
                  + " "
                  + validation.manifest().appVersion());
      return CommandLine.ExitCode.OK;
    }
  }

  /**
   * Parent command for app-owned UI developer checks.
   *
   * <p>The group keeps UI-only checks separate from package signing and catalog tooling so app
   * authors can run fast offline feedback before a bundle is signed.
   */
  @Command(
      name = "ui",
      description = "Inspect app-owned browser UI assets.",
      subcommands = {CryptaAppCli.UiLintCommand.class})
  static final class UiCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app ui lint} for staged static app bundles. */
  @Command(name = "lint", description = "Run offline app-owned UI lint checks.")
  static final class UiLintCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--strict", description = "Promote strict UI lint warnings to errors.")
    private boolean strict;

    @Option(names = "--json", description = "Write deterministic JSON lint output.")
    private Path jsonOutput;

    @Override
    public Integer call() throws Exception {
      AppUiLintResult result = AppUiLinter.lint(bundleDir, strict);
      if (jsonOutput != null) {
        Path normalizedJsonOutput = jsonOutput.toAbsolutePath().normalize();
        Path parent = normalizedJsonOutput.getParent();
        if (parent != null) {
          Files.createDirectories(parent);
        }
        Files.writeString(normalizedJsonOutput, result.toJson(), StandardCharsets.UTF_8);
      }
      printUiLintFindings(super.commandLine(), result);
      if (!result.applicable()) {
        super.commandLine()
            .getOut()
            .println("UI lint not applicable for app.ui.mode=" + result.uiMode());
        return CommandLine.ExitCode.OK;
      }
      super.commandLine()
          .getOut()
          .println(
              "UI lint "
                  + (result.hasErrors() ? "failed" : "passed")
                  + ": "
                  + result.errorCount()
                  + " error(s), "
                  + result.warningCount()
                  + " warning(s)");
      return result.hasErrors() ? CommandLine.ExitCode.SOFTWARE : CommandLine.ExitCode.OK;
    }
  }

  /**
   * Parent command for Platform API contract operations.
   *
   * <p>The group currently exposes offline snapshot generation so app authors and release
   * certification can verify bundles without contacting a running node.
   */
  @Command(
      name = "api",
      description = "Inspect the Platform API compatibility contract.",
      subcommands = {ApiSnapshotCommand.class})
  static final class ApiCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app api snapshot}. */
  @Command(name = "snapshot", description = "Write the current Platform API contract snapshot.")
  static final class ApiSnapshotCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--output", required = true, description = "Contract JSON file to write.")
    private Path output;

    @Override
    public Integer call() throws Exception {
      Path normalizedOutput = output.toAbsolutePath().normalize();
      Path parent = normalizedOutput.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      Files.writeString(
          normalizedOutput,
          PlatformApiContractJson.writeEnvelope(PlatformApiContract.current()),
          StandardCharsets.UTF_8);
      super.commandLine().getOut().println("Wrote Platform API contract: " + normalizedOutput);
      return CommandLine.ExitCode.OK;
    }
  }

  /**
   * Parent command for offline compatibility verification.
   *
   * <p>The verifier compares staged bundles and catalog entry descriptors with a target Platform
   * API contract snapshot. It never requires a running node.
   */
  @Command(
      name = "compat",
      description = "Verify app compatibility metadata against a Platform API contract.",
      subcommands = {CompatVerifyCommand.class})
  static final class CompatCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app compat verify}. */
  @Command(name = "verify", description = "Verify a staged bundle or catalog entry descriptor.")
  static final class CompatVerifyCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", description = "Staged bundle directory to verify.")
    private Path bundleDir;

    @Option(names = "--catalog-entry", description = "Catalog entry descriptor to verify.")
    private Path catalogEntry;

    @Option(names = "--contract", description = "Target Platform API contract JSON snapshot.")
    private Path contractFile;

    @Option(names = "--strict", description = "Treat compatibility warnings as failures.")
    private boolean strict;

    @Override
    public Integer call() throws Exception {
      requireExactlyOneCompatTarget();
      PlatformApiContract contract = loadContract(contractFile);
      CompatibilityVerificationResult result =
          bundleDir == null
              ? verifyCatalogEntry(catalogEntry, contract, strict)
              : verifyBundle(bundleDir, contract, strict);
      printCompatibilityFindings(super.commandLine(), result);
      if (result.hasErrors()) {
        throw new AppDistributionException("compatibility verification failed");
      }
      super.commandLine().getOut().println("Compatibility verified.");
      return CommandLine.ExitCode.OK;
    }

    private void requireExactlyOneCompatTarget() throws AppDistributionException {
      if ((bundleDir == null) == (catalogEntry == null)) {
        throw new AppDistributionException(
            "specify exactly one of --bundle-dir or --catalog-entry");
      }
    }

    private static PlatformApiContract loadContract(Path contractFile) throws java.io.IOException {
      if (contractFile == null) {
        return DevtoolsCapabilityVocabulary.currentValidationContract();
      }
      return PlatformApiContractJson.parse(Files.readString(contractFile, StandardCharsets.UTF_8));
    }

    private static CompatibilityVerificationResult verifyBundle(
        Path bundleDir, PlatformApiContract contract, boolean strict) throws java.io.IOException {
      BundleValidation validation = BundleValidator.validate(bundleDir, false);
      return PlatformApiContractVerifier.verify(
          validation.manifest().apiCompatibility(),
          validation.manifest().permissions(),
          contract,
          strict);
    }

    private static CompatibilityVerificationResult verifyCatalogEntry(
        Path descriptorFile, PlatformApiContract contract, boolean strict)
        throws java.io.IOException {
      AppCatalogWriter.CatalogEntryInspection inspection =
          AppCatalogWriter.inspectEntryDescriptor(descriptorFile);
      CompatibilityVerificationResult result =
          PlatformApiContractVerifier.verify(
              inspection.entry().compatibility().apiCompatibility(),
              inspection.entry().permissions(),
              contract,
              strict);
      List<CompatibilityFinding> findings = new ArrayList<>(result.findings());
      inspection
          .descriptor()
          .permissionsOverride()
          .ifPresent(
              permissions -> {
                if (!permissions.equals(inspection.manifest().permissions())) {
                  findings.add(
                      compatibilityFinding(
                          "catalog_permission_mismatch",
                          strict,
                          "Catalog descriptor permissions differ from bundle manifest"
                              + " permissions."));
                }
              });
      AppCatalogCompatibilityMetadata descriptorCompatibility =
          inspection.descriptor().compatibility();
      AppApiCompatibilityMetadata descriptorApi = descriptorCompatibility.apiCompatibility();
      AppApiCompatibilityMetadata manifestApi = inspection.manifest().apiCompatibility();
      if (descriptorCompatibility.apiCompatibility().declared()
          && !descriptorApi.equals(manifestApi)) {
        String code =
            descriptorApi.targetStability() != manifestApi.targetStability()
                    || descriptorApi.targetStabilityDeclared()
                        != manifestApi.targetStabilityDeclared()
                ? "catalog_api_target_stability_mismatch"
                : "catalog_api_compatibility_mismatch";
        findings.add(
            compatibilityFinding(
                code,
                strict,
                "Catalog descriptor API compatibility metadata differs from bundle manifest"
                    + " metadata."));
      }
      return new CompatibilityVerificationResult(List.copyOf(findings));
    }

    private static CompatibilityFinding compatibilityFinding(
        String code, boolean strict, String message) {
      return new CompatibilityFinding(
          code,
          strict ? CompatibilityFindingSeverity.ERROR : CompatibilityFindingSeverity.WARNING,
          message);
    }
  }

  /**
   * Parent command for independent app review receipt operations.
   *
   * <p>Review receipts are signed and verified separately from catalog signatures and app bundle
   * signatures. The commands operate on catalog entry descriptors so developers can produce and
   * validate receipts before embedding them into a signed catalog.
   */
  @Command(
      name = "review",
      description = "Sign and verify independent app review receipts.",
      subcommands = {
        ReviewSignCommand.class,
        ReviewVerifyCommand.class,
        ReviewFingerprintCommand.class,
        ReviewKeysCommand.class,
        ReviewTransparencyCommand.class
      })
  static final class ReviewCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app review sign}. */
  @Command(name = "sign", description = "Sign an independent app review receipt.")
  static final class ReviewSignCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--catalog-entry", required = true, description = "Catalog entry descriptor.")
    private Path catalogEntry;

    @Option(names = "--receipt-file", required = true, description = "Receipt properties file.")
    private Path receiptFile;

    @Option(names = "--reviewer-key-id", required = true, description = "Reviewer key id.")
    private String reviewerKeyId;

    @Option(names = "--reviewer-private-key-base64", description = "Base64 or PEM reviewer key.")
    private String reviewerPrivateKeyBase64;

    @Option(names = "--reviewer-private-key-file", description = "Reviewer Ed25519 private key.")
    private Path reviewerPrivateKeyFile;

    @Option(names = "--reviewer-private-key-env", description = "Environment variable key source.")
    private String reviewerPrivateKeyEnv;

    @Option(names = "--policy-id", required = true, description = "Review policy id.")
    private String policyId;

    @Option(names = "--policy-version", required = true, description = "Review policy version.")
    private String policyVersion;

    @Option(names = "--status", required = true, description = "reviewed, caution, or rejected.")
    private String status;

    @Option(names = "--reviewed-at", description = "Review instant; defaults to current time.")
    private Instant reviewedAt;

    @Option(names = "--expires-at", description = "Optional receipt expiry instant.")
    private Instant expiresAt;

    @Option(names = "--bundle-key-id", description = "Optional signed-bundle key id.")
    private String bundleKeyId;

    @Option(names = "--evidence-file", description = "Evidence file whose SHA-256 is recorded.")
    private Path evidenceFile;

    @Option(names = "--evidence-sha256", description = "Precomputed evidence SHA-256.")
    private String evidenceSha256;

    @Option(names = "--evidence-uri", description = "HTTPS or crypta evidence URI.")
    private URI evidenceUri;

    @Option(names = "--note", description = "Optional single-line reviewer note.")
    private String note;

    @Option(names = "--overwrite", description = "Replace an existing receipt file.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      Path normalizedReceiptFile = receiptFile.toAbsolutePath().normalize();
      if (Files.exists(normalizedReceiptFile) && !overwrite) {
        throw new AppDistributionException(
            "review receipt already exists: " + normalizedReceiptFile);
      }
      AppCatalogWriter.CatalogEntryInspection inspection =
          AppCatalogWriter.inspectEntryDescriptor(catalogEntry);
      PrivateKey privateKey =
          KeyMaterialLoader.loadPrivateKey(
              reviewerPrivateKeyBase64, reviewerPrivateKeyFile, reviewerPrivateKeyEnv);
      AppReviewReceiptPayload payload =
          new AppReviewReceiptPayload(
              AppReviewReceiptPayload.RECEIPT_VERSION,
              inspection.entry().appId(),
              inspection.entry().version(),
              inspection.entry().bundleSha256(),
              inspection.entry().bundleSizeBytes(),
              Optional.ofNullable(bundleKeyId),
              policyId,
              policyVersion,
              AppReviewReceiptStatus.parse(status, "--status"),
              reviewerKeyId,
              reviewedAt == null ? Instant.now() : reviewedAt,
              Optional.ofNullable(expiresAt),
              evidenceSha256(),
              Optional.ofNullable(evidenceUri),
              Optional.ofNullable(note));
      AppReviewReceipt receipt = AppReviewReceiptSigner.sign(payload, privateKey);
      AppReviewReceiptIO.write(normalizedReceiptFile, receipt);
      super.commandLine()
          .getOut()
          .println(
              "Signed review receipt: "
                  + payload.appId()
                  + " "
                  + payload.appVersion()
                  + " "
                  + payload.status().catalogValue());
      return CommandLine.ExitCode.OK;
    }

    private Optional<String> evidenceSha256() throws java.io.IOException {
      if (evidenceFile != null && evidenceSha256 != null) {
        throw new AppDistributionException(
            "configure evidence digest by --evidence-file or --evidence-sha256, not both");
      }
      if (evidenceSha256 != null) {
        return Optional.of(evidenceSha256);
      }
      if (evidenceFile == null) {
        return Optional.empty();
      }
      return Optional.of(sha256Hex(Files.readAllBytes(evidenceFile)));
    }

    private static String sha256Hex(byte[] bytes) {
      try {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
      } catch (NoSuchAlgorithmException exception) {
        throw new IllegalStateException("SHA-256 is not available", exception);
      }
    }
  }

  /** Implements {@code crypta-app review verify}. */
  @Command(name = "verify", description = "Verify an independent app review receipt.")
  static final class ReviewVerifyCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--catalog-entry", required = true, description = "Catalog entry descriptor.")
    private Path catalogEntry;

    @Option(names = "--receipt-file", required = true, description = "Receipt properties file.")
    private Path receiptFile;

    @Option(
        names = "--trusted-reviewer-keys-file",
        required = true,
        description = "Trusted reviewer keys properties file.")
    private Path trustedReviewerKeysFile;

    @Override
    public Integer call() throws Exception {
      AppCatalogWriter.CatalogEntryInspection inspection =
          AppCatalogWriter.inspectEntryDescriptor(catalogEntry);
      AppReviewReceipt receipt = AppReviewReceiptIO.read(receiptFile);
      TrustedReviewerKeys trustedKeys = TrustedReviewerKeys.load(trustedReviewerKeysFile);
      AppReviewTrustDecision decision =
          AppReviewReceiptVerifier.evaluate(
              inspection.entry(), receipt, trustedKeys, AppReviewPolicy.DEFAULT, Instant.now());
      if (!decision.trusted()) {
        throw new AppDistributionException(
            "review receipt did not verify: " + decision.status().jsonValue());
      }
      super.commandLine()
          .getOut()
          .println(
              "Verified review receipt: "
                  + decision.status().jsonValue()
                  + " reviewer="
                  + decision.reviewerKeyId()
                  + " fingerprintSha256="
                  + receipt.fingerprintSha256());
      return CommandLine.ExitCode.OK;
    }
  }

  /** Implements {@code crypta-app review fingerprint}. */
  @Command(name = "fingerprint", description = "Print a redacted review receipt fingerprint.")
  static final class ReviewFingerprintCommand extends SpecAwareCommand
      implements Callable<Integer> {
    @Option(names = "--receipt-file", required = true, description = "Receipt properties file.")
    private Path receiptFile;

    @Override
    public Integer call() throws Exception {
      AppReviewReceipt receipt = AppReviewReceiptIO.read(receiptFile);
      super.commandLine()
          .getOut()
          .println(
              "Review receipt fingerprint: fingerprintSha256="
                  + receipt.fingerprintSha256()
                  + " payloadSha256="
                  + receipt.payloadSha256()
                  + " reviewer="
                  + receipt.payload().reviewerKeyId());
      return CommandLine.ExitCode.OK;
    }
  }

  /** Parent command for trusted reviewer-key lifecycle tooling. */
  @Command(
      name = "keys",
      description = "Inspect and validate trusted reviewer-key lifecycle registries.",
      subcommands = {
        ReviewKeysInspectCommand.class,
        ReviewKeysMigrateCommand.class,
        ReviewKeysVerifyLifecycleCommand.class
      })
  static final class ReviewKeysCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app review keys inspect}. */
  @Command(name = "inspect", description = "Inspect a redacted trusted reviewer-key registry.")
  static final class ReviewKeysInspectCommand extends SpecAwareCommand
      implements Callable<Integer> {
    @Option(
        names = "--trusted-reviewer-keys-file",
        required = true,
        description = "Trusted reviewer keys properties file.")
    private Path trustedReviewerKeysFile;

    @Override
    public Integer call() throws Exception {
      TrustedReviewerKeys keys = TrustedReviewerKeys.load(trustedReviewerKeysFile);
      PrintWriter out = super.commandLine().getOut();
      out.println(
          "Trusted reviewer registry: version="
              + keys.registryVersion()
              + " configured="
              + !keys.isEmpty());
      out.println("Receipt revocations: " + keys.receiptRevocations().size());
      for (var summary : keys.summaries()) {
        out.println(
            "Reviewer key: "
                + summary.keyId()
                + " status="
                + summary.status().jsonValue()
                + " algorithm="
                + summary.algorithm()
                + " policy="
                + nullToDash(summary.policyId())
                + "/"
                + nullToDash(summary.policyVersion())
                + " displayName="
                + nullToDash(summary.displayName()));
      }
      List<String> warnings = keys.summary().warnings();
      out.println("Warnings: " + warnings.size());
      for (String warning : warnings) {
        out.println(WARNING_PREFIX + warning);
      }
      return CommandLine.ExitCode.OK;
    }
  }

  /** Implements {@code crypta-app review keys migrate}. */
  @Command(name = "migrate", description = "Migrate a trusted reviewer-key registry to v2.")
  static final class ReviewKeysMigrateCommand extends SpecAwareCommand
      implements Callable<Integer> {
    @Option(
        names = "--trusted-reviewer-keys-file",
        required = true,
        description = "Trusted reviewer keys properties file.")
    private Path trustedReviewerKeysFile;

    @Option(names = "--output", required = true, description = "Output v2 registry file.")
    private Path output;

    @Option(names = "--overwrite", description = "Replace an existing output file.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      TrustedReviewerKeys keys = TrustedReviewerKeys.load(trustedReviewerKeysFile);
      Path normalizedOutput = output.toAbsolutePath().normalize();
      if (Files.exists(normalizedOutput) && !overwrite) {
        throw new AppDistributionException("trusted reviewer output already exists: " + output);
      }
      Files.createDirectories(normalizedOutput.getParent());
      Files.writeString(normalizedOutput, serializeV2ReviewerKeys(keys), StandardCharsets.UTF_8);
      super.commandLine()
          .getOut()
          .println("Migrated trusted reviewer registry to v2: keys=" + keys.summaries().size());
      return CommandLine.ExitCode.OK;
    }

    private static String serializeV2ReviewerKeys(TrustedReviewerKeys keys) {
      StringBuilder builder = new StringBuilder("trusted.reviewers.version=2\n\n");
      int index = 1;
      for (TrustedReviewerKey key : keys.all()) {
        int reviewerIndex = index;
        appendReviewerProperty(builder, reviewerIndex, "id", key.keyId());
        appendReviewerProperty(builder, reviewerIndex, "algorithm", key.algorithm());
        appendReviewerProperty(
            builder,
            reviewerIndex,
            "public.key.base64",
            Base64.getEncoder().encodeToString(key.publicKey().getEncoded()));
        key.displayName()
            .ifPresent(
                value -> appendReviewerProperty(builder, reviewerIndex, "display.name", value));
        key.policyId()
            .ifPresent(value -> appendReviewerProperty(builder, reviewerIndex, "policy.id", value));
        key.policyVersion()
            .ifPresent(
                value -> appendReviewerProperty(builder, reviewerIndex, "policy.version", value));
        appendReviewerProperty(builder, reviewerIndex, FIELD_STATUS, key.status().jsonValue());
        key.lifecycle()
            .validFrom()
            .ifPresent(
                value ->
                    appendReviewerProperty(builder, reviewerIndex, "valid.from", value.toString()));
        key.lifecycle()
            .validUntil()
            .ifPresent(
                value ->
                    appendReviewerProperty(
                        builder, reviewerIndex, "valid.until", value.toString()));
        key.lifecycle()
            .revokedAt()
            .ifPresent(
                value ->
                    appendReviewerProperty(builder, reviewerIndex, "revoked.at", value.toString()));
        key.lifecycle()
            .revocationReason()
            .ifPresent(
                value ->
                    appendReviewerProperty(builder, reviewerIndex, "revocation.reason", value));
        key.lifecycle()
            .rotatesFrom()
            .ifPresent(
                value -> appendReviewerProperty(builder, reviewerIndex, "rotates.from", value));
        key.lifecycle()
            .rotatesTo()
            .ifPresent(
                value -> appendReviewerProperty(builder, reviewerIndex, "rotates.to", value));
        builder.append('\n');
        index++;
      }
      return builder.toString();
    }

    private static void appendReviewerProperty(
        StringBuilder builder, int index, String field, String value) {
      builder
          .append("reviewer.")
          .append(index)
          .append('.')
          .append(field)
          .append('=')
          .append(value)
          .append('\n');
    }
  }

  /** Implements {@code crypta-app review keys verify-lifecycle}. */
  @Command(
      name = "verify-lifecycle",
      description = "Validate reviewer-key lifecycle metadata without printing key material.")
  static final class ReviewKeysVerifyLifecycleCommand extends SpecAwareCommand
      implements Callable<Integer> {
    @Option(
        names = "--trusted-reviewer-keys-file",
        required = true,
        description = "Trusted reviewer keys properties file.")
    private Path trustedReviewerKeysFile;

    @Override
    public Integer call() throws Exception {
      TrustedReviewerKeys keys = TrustedReviewerKeys.load(trustedReviewerKeysFile);
      List<String> warnings = keys.summary().warnings();
      PrintWriter out = super.commandLine().getOut();
      out.println(
          "Reviewer key lifecycle valid: keys="
              + keys.summaries().size()
              + " receiptRevocations="
              + keys.receiptRevocations().size()
              + " warnings="
              + warnings.size());
      for (String warning : warnings) {
        out.println(WARNING_PREFIX + warning);
      }
      return CommandLine.ExitCode.OK;
    }
  }

  /** Parent command for local review transparency-log tooling. */
  @Command(
      name = "transparency",
      description = "Inspect local review transparency logs.",
      subcommands = {ReviewTransparencyVerifyCommand.class})
  static final class ReviewTransparencyCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app review transparency verify}. */
  @Command(name = "verify", description = "Verify a local review transparency-log hash chain.")
  static final class ReviewTransparencyVerifyCommand extends SpecAwareCommand
      implements Callable<Integer> {
    @Option(names = "--log-file", required = true, description = "Review transparency JSONL log.")
    private Path logFile;

    @Override
    public Integer call() throws Exception {
      if (!Files.isRegularFile(logFile)) {
        throw new AppDistributionException("review transparency log file not found");
      }
      AppReviewTransparencyVerificationResult result =
          FileAppReviewTransparencyStore.verifyFile(logFile);
      if (!result.verified()) {
        throw new AppDistributionException(
            "review transparency log verification failed: " + result.error());
      }
      super.commandLine()
          .getOut()
          .println(
              "Verified review transparency log: records="
                  + result.recordCount()
                  + " latestHash="
                  + nullToDash(result.latestRecordHash()));
      return CommandLine.ExitCode.OK;
    }
  }

  private static String nullToDash(String value) {
    return value == null || value.isBlank() ? "-" : value;
  }

  /**
   * Implements {@code crypta-app pack} for deterministic ZIP artifact creation.
   *
   * <p>The command validates the staged bundle before writing the artifact, respects an explicit
   * overwrite flag, and delegates archive construction to {@link AppBundlePackager} so CLI and
   * library callers share the same install-compatible ZIP rules.
   */
  @Command(name = "pack", description = "Package a staged app bundle as a deterministic ZIP.")
  static final class PackCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--output", required = true, description = "ZIP artifact to write.")
    private Path output;

    @Option(names = "--overwrite", description = "Replace an existing output ZIP.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      Path normalizedOutput = output.toAbsolutePath().normalize();
      if (Files.exists(normalizedOutput) && !overwrite) {
        throw new AppDistributionException("output ZIP already exists: " + normalizedOutput);
      }
      BundleValidator.validate(bundleDir, false);
      PackagedAppBundle packaged = AppBundlePackager.packageBundle(bundleDir, normalizedOutput);
      super.commandLine()
          .getOut()
          .println(
              "Packaged bundle: "
                  + packaged.artifact()
                  + " "
                  + packaged.sizeBytes()
                  + " bytes "
                  + packaged.artifactSha256());
      return CommandLine.ExitCode.OK;
    }
  }

  /**
   * Implements {@code crypta-app sign} for staged bundle signatures.
   *
   * <p>The command forwards key material options to {@link AppDistributionTool} to preserve the
   * established first-party signing semantics while exposing the same workflow through the
   * developer CLI.
   */
  @Command(name = "sign", description = "Sign a staged app bundle.")
  static final class SignCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--key-id", required = true, description = "Signing key id.")
    private String keyId;

    @Option(names = "--private-key-base64", description = "Base64 or PEM Ed25519 private key.")
    private String privateKeyBase64;

    @Option(names = "--private-key-file", description = "Ed25519 private key file.")
    private Path privateKeyFile;

    @Option(names = "--private-key-env", description = "Environment variable containing key text.")
    private String privateKeyEnv;

    @Override
    public Integer call() throws Exception {
      AppDistributionTool.main(bundleSignArguments());
      super.commandLine()
          .getOut()
          .println("Signed bundle: " + bundleDir.toAbsolutePath().normalize());
      return CommandLine.ExitCode.OK;
    }

    private String[] bundleSignArguments() {
      List<String> args = new ArrayList<>();
      args.add("sign");
      args.add("--bundle-dir");
      args.add(bundleDir.toString());
      args.add("--key-id");
      args.add(keyId);
      addOptional(args, "--private-key-base64", privateKeyBase64);
      addOptional(args, "--private-key-file", privateKeyFile);
      addOptional(args, "--private-key-env", privateKeyEnv);
      return args.toArray(String[]::new);
    }
  }

  /**
   * Implements {@code crypta-app verify} for staged bundle signature checks.
   *
   * <p>Trusted key options intentionally mirror the existing distribution tool. The command may
   * also allow fully unsigned bundles for local development when the caller opts in with {@code
   * --allow-unsigned}.
   */
  @Command(name = "verify", description = "Verify a staged app bundle.")
  static final class VerifyCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--bundle-dir", required = true, description = "Staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--allow-unsigned", description = "Allow fully unsigned development bundles.")
    private boolean allowUnsigned;

    @Option(names = "--trusted-keys-file", description = "Trusted keys properties file.")
    private Path trustedKeysFile;

    @Option(names = "--trusted-key-id", description = "Trusted key id for direct public key input.")
    private String trustedKeyId;

    @Option(names = "--trusted-public-key-base64", description = "Base64 or PEM public key.")
    private String trustedPublicKeyBase64;

    @Option(names = "--trusted-public-key-file", description = "Public key file.")
    private Path trustedPublicKeyFile;

    @Override
    public Integer call() throws Exception {
      AppDistributionTool.main(bundleVerifyArguments());
      super.commandLine()
          .getOut()
          .println("Verified bundle: " + bundleDir.toAbsolutePath().normalize());
      return CommandLine.ExitCode.OK;
    }

    private String[] bundleVerifyArguments() {
      List<String> args = new ArrayList<>();
      args.add("verify");
      args.add("--bundle-dir");
      args.add(bundleDir.toString());
      if (allowUnsigned) {
        args.add("--allow-unsigned");
      }
      addOptional(args, "--trusted-keys-file", trustedKeysFile);
      addOptional(args, "--trusted-key-id", trustedKeyId);
      addOptional(args, "--trusted-public-key-base64", trustedPublicKeyBase64);
      addOptional(args, "--trusted-public-key-file", trustedPublicKeyFile);
      return args.toArray(String[]::new);
    }
  }

  /**
   * Parent command for catalog authoring subcommands.
   *
   * <p>The group keeps catalog creation, signing, and verification under one namespace while
   * leaving bundle commands at the top level of {@code crypta-app}.
   */
  @Command(
      name = "catalog",
      description = "Create, sign, and verify signed app catalogs.",
      subcommands = {
        CatalogEntryCommand.class,
        CatalogCreateCommand.class,
        CatalogSignCommand.class,
        CatalogVerifyCommand.class
      })
  static final class CatalogCommand extends SpecAwareCommand implements Runnable {
    @Override
    public void run() {
      super.commandLine().usage(super.commandLine().getOut());
    }
  }

  /** Implements {@code crypta-app catalog entry}. */
  @Command(name = "entry", description = "Generate a catalog entry descriptor for a signed bundle.")
  static final class CatalogEntryCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(
        names = "--bundle-dir",
        required = true,
        description = "Signed staged bundle directory.")
    private Path bundleDir;

    @Option(names = "--artifact", required = true, description = "Packaged ZIP artifact.")
    private Path artifact;

    @Option(names = "--bundle-uri", required = true, description = "Public bundle artifact URI.")
    private URI bundleUri;

    @Option(names = "--output", required = true, description = "Catalog entry descriptor output.")
    private Path output;

    @Option(names = "--summary", required = true, description = "Catalog summary.")
    private String summary;

    @Option(names = "--homepage", description = "App homepage URI.")
    private URI homepage;

    @Option(names = "--source", description = "Source code URI.")
    private URI source;

    @Option(names = "--license", description = "License identifier.")
    private String license;

    @Option(names = "--category", description = "Catalog category list.")
    private String category;

    @Option(names = "--minimum-crypta-version", description = "Minimum Crypta build/version.")
    private String minimumCryptaVersion;

    @Option(names = "--maximum-crypta-version", description = "Maximum Crypta build/version.")
    private String maximumCryptaVersion;

    @Option(
        names = "--channel",
        description = "Catalog channel: stable, beta, nightly, deprecated.")
    private String channel;

    @Option(
        names = "--support-status",
        description =
            "Support status: supported, maintenance, experimental, deprecated, unsupported.")
    private String supportStatus;

    @Option(
        names = "--deprecation-status",
        description = "Deprecation status: none, deprecated, retired.")
    private String deprecationStatus;

    @Option(names = "--deprecation-message", description = "Short deprecation message.")
    private String deprecationMessage;

    @Option(names = "--replacement-app-id", description = "Replacement app id for deprecated apps.")
    private String replacementAppId;

    @Option(
        names = "--security-advisory",
        description = "Security advisory reference in id=uri form; repeatable.")
    private List<String> securityAdvisories = new ArrayList<>();

    @Option(names = "--maintenance-owner", description = "First-party maintenance owner.")
    private String maintenanceOwner;

    @Option(names = "--maintenance-owner-uri", description = "Maintenance owner URI.")
    private URI maintenanceOwnerUri;

    @Option(names = "--maintenance-support-level", description = "Maintenance support level.")
    private String maintenanceSupportLevel;

    @Option(
        names = "--maintenance-data-schema-policy",
        description = "App-data schema maintenance policy.")
    private String maintenanceDataSchemaPolicy;

    @Option(
        names = "--maintenance-migration-policy",
        description = "App-data migration maintenance policy.")
    private String maintenanceMigrationPolicy;

    @Option(names = "--maintenance-backup-restore", description = "Backup/restore support policy.")
    private String maintenanceBackupRestore;

    @Option(
        names = "--maintenance-security-policy",
        description = "Maintenance security handling policy.")
    private String maintenanceSecurityPolicy;

    @Option(
        names = "--maintenance-deprecation-policy",
        description = "Maintenance deprecation policy.")
    private String maintenanceDeprecationPolicy;

    @Option(names = "--maintenance-support-uri", description = "App-specific support URI.")
    private URI maintenanceSupportUri;

    @Option(
        names = "--review-receipt",
        description = "Review receipt to copy advisory metadata from.")
    private Path reviewReceipt;

    @Option(names = "--changelog-summary", description = "Short changelog summary.")
    private String changelogSummary;

    @Option(
        names = "--permission-rationale",
        description = "Permission rationale in permission=text form; repeatable.")
    private List<String> permissionRationales = new ArrayList<>();

    @Option(names = "--screenshot", description = "Screenshot URI; repeatable.")
    private List<URI> screenshots = new ArrayList<>();

    @Option(names = "--strict", description = "Require a rationale for every permission.")
    private boolean strict;

    @Option(names = "--overwrite", description = "Replace an existing descriptor.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      CatalogEntryDescriptorGenerator.Result result =
          CatalogEntryDescriptorGenerator.write(
              new CatalogEntryDescriptorGenerator.Request(
                  bundleDir,
                  artifact,
                  bundleUri,
                  output,
                  summary,
                  Optional.ofNullable(homepage),
                  Optional.ofNullable(source),
                  Optional.ofNullable(license),
                  Optional.ofNullable(category),
                  Optional.ofNullable(minimumCryptaVersion),
                  Optional.ofNullable(maximumCryptaVersion),
                  Optional.ofNullable(channel),
                  Optional.ofNullable(supportStatus),
                  Optional.ofNullable(deprecationStatus),
                  Optional.ofNullable(deprecationMessage),
                  Optional.ofNullable(replacementAppId),
                  CatalogEntryDescriptorGenerator.normalizeSecurityAdvisories(securityAdvisories),
                  Optional.ofNullable(maintenanceOwner),
                  Optional.ofNullable(maintenanceOwnerUri),
                  Optional.ofNullable(maintenanceSupportLevel),
                  Optional.ofNullable(maintenanceDataSchemaPolicy),
                  Optional.ofNullable(maintenanceMigrationPolicy),
                  Optional.ofNullable(maintenanceBackupRestore),
                  Optional.ofNullable(maintenanceSecurityPolicy),
                  Optional.ofNullable(maintenanceDeprecationPolicy),
                  Optional.ofNullable(maintenanceSupportUri),
                  reviewReceipt,
                  Optional.ofNullable(changelogSummary),
                  CatalogEntryDescriptorGenerator.normalizeRationales(permissionRationales),
                  screenshots,
                  strict,
                  overwrite));
      for (String permission : result.missingRationales()) {
        super.commandLine()
            .getErr()
            .println(WARNING_PREFIX + "missing permission rationale for " + permission);
      }
      super.commandLine()
          .getOut()
          .println(
              "Wrote catalog entry descriptor: "
                  + result.appId()
                  + " "
                  + result.version()
                  + " -> "
                  + output.toAbsolutePath().normalize().getFileName());
      return CommandLine.ExitCode.OK;
    }
  }

  /**
   * Implements {@code crypta-app catalog create} from entry descriptor files.
   *
   * <p>The command collects catalog metadata, applies the current time only when the caller omits
   * {@code --generated-at}, and delegates descriptor parsing and artifact inspection to {@link
   * AppCatalogWriter}. The generated file is unsigned until {@code catalog sign} is run.
   */
  @Command(name = "create", description = "Create catalog properties from entry descriptors.")
  static final class CatalogCreateCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--catalog-file", required = true, description = "Catalog properties file.")
    private Path catalogFile;

    @Option(names = "--catalog-id", required = true, description = "Stable catalog id.")
    private String catalogId;

    @Option(names = "--name", required = true, description = "Catalog display name.")
    private String name;

    @Option(
        names = "--generated-at",
        description = "Catalog generation instant; defaults to the current time.")
    private Instant generatedAt;

    @Option(names = "--entry", required = true, description = "Entry descriptor file; repeatable.")
    private List<Path> entries = new ArrayList<>();

    @Option(
        names = "--review-receipt",
        description = "Review receipt properties file to embed; repeatable.")
    private List<Path> reviewReceipts = new ArrayList<>();

    @Option(
        names = OPTION_SECURITY_ADVISORY_RECORD,
        description =
            "Catalog security advisory as semicolon-separated key=value fields; repeatable.")
    private List<String> securityAdvisoryRecords = new ArrayList<>();

    @Option(
        names = OPTION_SECURITY_DENYLIST_ENTRY,
        description =
            "Exact app-version denylist as semicolon-separated key=value fields; repeatable.")
    private List<String> securityDenylistEntries = new ArrayList<>();

    @Option(names = "--overwrite", description = "Replace an existing catalog file.")
    private boolean overwrite;

    @Override
    public Integer call() throws Exception {
      Path normalizedCatalogFile = catalogFile.toAbsolutePath().normalize();
      if (Files.exists(normalizedCatalogFile) && !overwrite) {
        throw new AppDistributionException("catalog file already exists: " + normalizedCatalogFile);
      }
      AppCatalogWriter.WriteResult result =
          AppCatalogWriter.write(
              new AppCatalogBuildRequest(
                  catalogId,
                  name,
                  generatedAt == null ? Instant.now() : generatedAt,
                  entries,
                  reviewReceipts,
                  securityPolicy(securityAdvisoryRecords, securityDenylistEntries),
                  normalizedCatalogFile));
      int entryCount = result.catalog().entries().size();
      super.commandLine()
          .getOut()
          .println(
              "Created catalog: "
                  + result.catalog().catalogId()
                  + " with "
                  + entryCount
                  + " "
                  + (entryCount == 1 ? "entry" : "entries"));
      return CommandLine.ExitCode.OK;
    }

    private static AppCatalogSecurityPolicy securityPolicy(
        List<String> advisorySpecs, List<String> denylistSpecs) {
      if (advisorySpecs.isEmpty() && denylistSpecs.isEmpty()) {
        return AppCatalogSecurityPolicy.EMPTY;
      }
      List<AppCatalogSecurityAdvisoryRecord> advisories =
          advisorySpecs.stream().map(CatalogCreateCommand::securityAdvisory).toList();
      List<AppCatalogVersionDenylistEntry> denylist =
          denylistSpecs.stream().map(CatalogCreateCommand::securityDenylistEntry).toList();
      return new AppCatalogSecurityPolicy(advisories, denylist);
    }

    private static AppCatalogSecurityAdvisoryRecord securityAdvisory(String spec) {
      Map<String, String> fields = fieldSpec(spec, OPTION_SECURITY_ADVISORY_RECORD);
      rejectUnknownFields(
          fields,
          OPTION_SECURITY_ADVISORY_RECORD,
          Set.of(
              "id",
              "uri",
              "title",
              FIELD_SEVERITY,
              FIELD_STATUS,
              FIELD_ACTION,
              "summary",
              "publishedAt",
              "updatedAt",
              FIELD_REPLACEMENT_APP_ID,
              FIELD_SAFE_UNINSTALL_GUIDANCE));
      return new AppCatalogSecurityAdvisoryRecord(
          requiredField(fields, "id", OPTION_SECURITY_ADVISORY_RECORD),
          URI.create(requiredField(fields, "uri", OPTION_SECURITY_ADVISORY_RECORD)),
          requiredField(fields, "title", OPTION_SECURITY_ADVISORY_RECORD),
          AppCatalogSecuritySeverity.parseCatalog(
              requiredField(fields, FIELD_SEVERITY, OPTION_SECURITY_ADVISORY_RECORD),
              FIELD_SEVERITY),
          AppCatalogSecurityStatus.parse(
              requiredField(fields, FIELD_STATUS, OPTION_SECURITY_ADVISORY_RECORD), FIELD_STATUS),
          AppCatalogSecurityAction.parse(
              requiredField(fields, FIELD_ACTION, OPTION_SECURITY_ADVISORY_RECORD), FIELD_ACTION),
          requiredField(fields, "summary", OPTION_SECURITY_ADVISORY_RECORD),
          Instant.parse(requiredField(fields, "publishedAt", OPTION_SECURITY_ADVISORY_RECORD)),
          Instant.parse(requiredField(fields, "updatedAt", OPTION_SECURITY_ADVISORY_RECORD)),
          Optional.ofNullable(optionalField(fields, FIELD_REPLACEMENT_APP_ID)),
          Optional.ofNullable(optionalField(fields, FIELD_SAFE_UNINSTALL_GUIDANCE)));
    }

    private static AppCatalogVersionDenylistEntry securityDenylistEntry(String spec) {
      Map<String, String> fields = fieldSpec(spec, OPTION_SECURITY_DENYLIST_ENTRY);
      rejectUnknownFields(
          fields,
          OPTION_SECURITY_DENYLIST_ENTRY,
          Set.of(
              "id",
              "appId",
              "version",
              "advisoryId",
              "reason",
              FIELD_REPLACEMENT_APP_ID,
              FIELD_SAFE_UNINSTALL_GUIDANCE));
      return new AppCatalogVersionDenylistEntry(
          requiredField(fields, "id", OPTION_SECURITY_DENYLIST_ENTRY),
          requiredField(fields, "appId", OPTION_SECURITY_DENYLIST_ENTRY),
          requiredField(fields, "version", OPTION_SECURITY_DENYLIST_ENTRY),
          requiredField(fields, "advisoryId", OPTION_SECURITY_DENYLIST_ENTRY),
          requiredField(fields, "reason", OPTION_SECURITY_DENYLIST_ENTRY),
          Optional.ofNullable(optionalField(fields, FIELD_REPLACEMENT_APP_ID)),
          Optional.ofNullable(optionalField(fields, FIELD_SAFE_UNINSTALL_GUIDANCE)));
    }

    private static Map<String, String> fieldSpec(String spec, String optionName) {
      LinkedHashMap<String, String> fields = new LinkedHashMap<>();
      for (String field : spec.split(";", -1)) {
        int separator = field.indexOf('=');
        if (separator <= 0 || separator == field.length() - 1) {
          throw new IllegalArgumentException(optionName + " fields must use key=value syntax");
        }
        String key = field.substring(0, separator).trim();
        String value = field.substring(separator + 1).trim();
        if (fields.putIfAbsent(key, value) != null) {
          throw new IllegalArgumentException(optionName + " duplicate field: " + key);
        }
      }
      return Map.copyOf(fields);
    }

    private static void rejectUnknownFields(
        Map<String, String> fields, String optionName, Set<String> allowedKeys) {
      for (String key : fields.keySet()) {
        if (!allowedKeys.contains(key)) {
          throw new IllegalArgumentException(optionName + " unknown field: " + key);
        }
      }
    }

    private static String requiredField(Map<String, String> fields, String key, String optionName) {
      String value = optionalField(fields, key);
      if (value == null) {
        throw new IllegalArgumentException(optionName + " missing field: " + key);
      }
      return value;
    }

    private static String optionalField(Map<String, String> fields, String key) {
      String value = fields.get(key);
      return value == null || value.isBlank() ? null : value;
    }
  }

  /**
   * Implements {@code crypta-app catalog sign} for catalog signature sidecars.
   *
   * <p>The command loads exactly one private key source and signs the catalog file bytes through
   * {@link AppCatalogSigner}. The signature is written next to the catalog using the catalog
   * module's canonical sidecar name.
   */
  @Command(name = "sign", description = "Sign a catalog properties file.")
  static final class CatalogSignCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--catalog-file", required = true, description = "Catalog properties file.")
    private Path catalogFile;

    @Option(names = "--key-id", required = true, description = "Signing key id.")
    private String keyId;

    @Option(names = "--private-key-base64", description = "Base64 or PEM Ed25519 private key.")
    private String privateKeyBase64;

    @Option(names = "--private-key-file", description = "Ed25519 private key file.")
    private Path privateKeyFile;

    @Option(names = "--private-key-env", description = "Environment variable containing key text.")
    private String privateKeyEnv;

    @Override
    public Integer call() throws Exception {
      PrivateKey privateKey =
          KeyMaterialLoader.loadPrivateKey(privateKeyBase64, privateKeyFile, privateKeyEnv);
      AppCatalogSignature signature = AppCatalogSigner.sign(catalogFile, keyId, privateKey);
      super.commandLine().getOut().println("Signed catalog with key: " + signature.keyId());
      return CommandLine.ExitCode.OK;
    }
  }

  /**
   * Implements {@code crypta-app catalog verify} for signed catalog files.
   *
   * <p>The command accepts either a trusted-keys file or direct trusted public key inputs and
   * checks that the sibling signature sidecar exists before delegating trust verification to {@link
   * AppCatalogVerifier}.
   */
  @Command(name = "verify", description = "Verify a signed catalog properties file.")
  static final class CatalogVerifyCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--catalog-file", required = true, description = "Catalog properties file.")
    private Path catalogFile;

    @Option(names = "--trusted-keys-file", description = "Trusted keys properties file.")
    private Path trustedKeysFile;

    @Option(names = "--trusted-key-id", description = "Trusted key id for direct public key input.")
    private String trustedKeyId;

    @Option(names = "--trusted-public-key-base64", description = "Base64 or PEM public key.")
    private String trustedPublicKeyBase64;

    @Option(names = "--trusted-public-key-file", description = "Public key file.")
    private Path trustedPublicKeyFile;

    @Override
    public Integer call() throws Exception {
      TrustedAppKeys trustedKeys =
          KeyMaterialLoader.loadTrustedKeys(
              trustedKeysFile, trustedKeyId, trustedPublicKeyBase64, trustedPublicKeyFile);
      Path signatureFile =
          catalogFile
              .toAbsolutePath()
              .normalize()
              .resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME);
      if (!Files.exists(signatureFile)) {
        throw new AppDistributionException("missing catalog signature: " + signatureFile);
      }
      AppCatalog catalog = AppCatalogVerifier.verify(catalogFile, trustedKeys);
      super.commandLine().getOut().println("Verified catalog: " + catalog.catalogId());
      return CommandLine.ExitCode.OK;
    }
  }

  /** Implements {@code crypta-app publish-usk}. */
  @Command(name = "publish-usk", description = "Plan or publish a signed catalog to a Crypta USK.")
  static final class PublishUskCommand extends SpecAwareCommand implements Callable<Integer> {
    @Option(names = "--catalog-file", required = true, description = "Catalog properties file.")
    private Path catalogFile;

    @Option(
        names = "--catalog-signature-file",
        required = true,
        description = "Catalog signature sidecar.")
    private Path catalogSignatureFile;

    @Option(
        names = "--catalog-source",
        required = true,
        description = "Public crypta:USK catalog source URI.")
    private String catalogSource;

    @Option(
        names = "--output",
        required = true,
        description = "Publication plan or summary output.")
    private Path output;

    @Option(names = "--dry-run", description = "Generate a plan without live insertion.")
    private boolean dryRun;

    @Option(names = "--live", description = "Publish through the configured localhost node.")
    private boolean live;

    @Option(
        names = "--private-insert-uri-env",
        description =
            "Environment variable containing the matching private USK directory insert URI.")
    private String privateInsertUriEnv;

    @Option(
        names = "--private-insert-uri-file",
        description = "Protected file containing the matching private USK directory insert URI.")
    private Path privateInsertUriFile;

    @Option(names = "--node-base-url", description = "Local node URL, with or without /api/v1.")
    private String nodeBaseUrl;

    @Option(
        names = "--form-password-env",
        description = "Environment variable containing the form password.")
    private String formPasswordEnv;

    @Option(
        names = "--form-password-file",
        description = "Protected file containing the form password.")
    private Path formPasswordFile;

    @Option(names = "--trusted-keys-file", description = "Trusted keys properties file.")
    private Path trustedKeysFile;

    @Option(names = "--trusted-key-id", description = "Trusted key id for direct public key input.")
    private String trustedKeyId;

    @Option(names = "--trusted-public-key-base64", description = "Base64 or PEM public key.")
    private String trustedPublicKeyBase64;

    @Option(names = "--trusted-public-key-file", description = "Public key file.")
    private Path trustedPublicKeyFile;

    @Option(
        names = "--verify-live-fetch",
        description = "Require immediate live fetch verification.")
    private boolean verifyLiveFetch;

    @Override
    public Integer call() throws Exception {
      if (dryRun == live) {
        throw new AppDistributionException(
            "publish-usk requires exactly one of --dry-run or --live");
      }
      if (dryRun) {
        return writeDryRunPlan();
      }
      return publishLive();
    }

    private Integer writeDryRunPlan() throws IOException {
      PublicationPlanWriter.Result result =
          PublicationPlanWriter.write(
              new PublicationPlanWriter.Request(
                  catalogFile, catalogSignatureFile, catalogSource, output));
      super.commandLine()
          .getOut()
          .println(
              "Wrote Crypta USK publication plan: "
                  + result.catalogId()
                  + " entries="
                  + result.entryCount()
                  + " output="
                  + result.output().getFileName());
      return CommandLine.ExitCode.OK;
    }

    private Integer publishLive() throws IOException {
      TrustedAppKeys trustedKeys =
          KeyMaterialLoader.loadTrustedKeys(
              trustedKeysFile, trustedKeyId, trustedPublicKeyBase64, trustedPublicKeyFile);
      LiveUskPublicationResult result =
          LiveUskPublicationService.publish(
              new LiveUskPublicationService.Request(
                  catalogFile,
                  catalogSignatureFile,
                  catalogSource,
                  output,
                  loadSecureText(privateInsertUriEnv, privateInsertUriFile, "private insert URI"),
                  nodeBaseUrl,
                  loadSecureText(formPasswordEnv, formPasswordFile, "form password"),
                  verifyLiveFetch),
              trustedKeys,
              liveUskPublisher());
      super.commandLine()
          .getOut()
          .println(
              "Published Crypta USK catalog: "
                  + result.catalogId()
                  + " entries="
                  + result.entryCount()
                  + " output="
                  + result.output().getFileName()
                  + " catalogStatus="
                  + result.catalogInsertStatus()
                  + " signatureStatus="
                  + result.signatureInsertStatus());
      return CommandLine.ExitCode.OK;
    }

    private static String loadSecureText(String environmentName, Path file, String label)
        throws IOException {
      int sourceCount = (environmentName == null ? 0 : 1) + (file == null ? 0 : 1);
      if (sourceCount != 1) {
        throw new AppDistributionException(
            label + " must be configured by exactly one env or file source");
      }
      String value;
      if (environmentName != null) {
        value = System.getenv(environmentName);
        if (value == null || value.isBlank()) {
          throw new AppDistributionException("missing required environment variable for " + label);
        }
      } else {
        Path normalized = file.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(normalized)
            || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
          throw new AppDistributionException(label + " file must be a regular file");
        }
        value = Files.readString(normalized, StandardCharsets.UTF_8);
      }
      String trimmed = value.trim();
      if (trimmed.isEmpty()) {
        throw new AppDistributionException(label + " must not be blank");
      }
      return trimmed;
    }

    private static LiveUskPublisher liveUskPublisher() {
      LiveUskPublisher publisher = LIVE_USK_PUBLISHER_OVERRIDE.get();
      return publisher == null ? new PlatformApiLiveUskPublisher() : publisher;
    }
  }

  private abstract static class SpecAwareCommand {
    private CommandSpec spec;

    // Picocli invokes this setter reflectively for each subcommand instance.
    @SuppressWarnings("unused")
    @Spec
    void setSpec(CommandSpec spec) {
      this.spec = spec;
    }

    final CommandLine commandLine() {
      return spec.commandLine();
    }
  }

  private static void printCompatibilityFindings(
      CommandLine commandLine, CompatibilityVerificationResult result) {
    for (CompatibilityFinding finding : result.findings()) {
      String prefix =
          finding.severity() == CompatibilityFindingSeverity.ERROR ? "Error: " : WARNING_PREFIX;
      commandLine.getErr().println(prefix + finding.message());
    }
  }

  private static void printUiLintFindings(CommandLine commandLine, AppUiLintResult result) {
    for (AppUiLintFinding finding : result.findings()) {
      PrintWriter writer =
          finding.severity() == AppUiLintSeverity.ERROR
              ? commandLine.getErr()
              : commandLine.getOut();
      String location = finding.path().isBlank() ? "" : finding.path() + ": ";
      writer.println(
          finding.severity().name().toLowerCase(Locale.ROOT)
              + ": "
              + location
              + finding.id()
              + ": "
              + finding.message());
    }
  }

  /**
   * Adds an optional path-valued argument pair to a delegated command invocation.
   *
   * @param args mutable argument list being assembled for the delegate tool
   * @param name option name to append when {@code value} is present
   * @param value optional path value; {@code null} means the option is omitted
   */
  private static void addOptional(List<String> args, String name, Path value) {
    if (value != null) {
      args.add(name);
      args.add(value.toString());
    }
  }

  /**
   * Adds an optional string-valued argument pair to a delegated command invocation.
   *
   * @param args mutable argument list being assembled for the delegate tool
   * @param name option name to append when {@code value} is present
   * @param value optional string value; {@code null} means the option is omitted
   */
  private static void addOptional(List<String> args, String name, String value) {
    if (value != null) {
      args.add(name);
      args.add(value);
    }
  }
}
