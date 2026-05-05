package network.crypta.platform.devtools;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityFinding;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityFindingSeverity;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityVerificationResult;
import network.crypta.platform.api.PlatformApiContractVerifier;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogBuildRequest;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appcatalog.AppCatalogWriter;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptIO;
import network.crypta.platform.appcatalog.AppReviewReceiptPayload;
import network.crypta.platform.appcatalog.AppReviewReceiptSigner;
import network.crypta.platform.appcatalog.AppReviewReceiptStatus;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.AppDistributionTool;
import network.crypta.platform.appdist.PackagedAppBundle;
import network.crypta.platform.appdist.TrustedAppKeys;
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
    description = "Create, validate, package, sign, and catalog Crypta app bundles.",
    subcommands = {
      CryptaAppCli.InitCommand.class,
      CryptaAppCli.ValidateCommand.class,
      CryptaAppCli.PackCommand.class,
      CryptaAppCli.SignCommand.class,
      CryptaAppCli.VerifyCommand.class,
      CryptaAppCli.ApiCommand.class,
      CryptaAppCli.CompatCommand.class,
      CryptaAppCli.ReviewCommand.class,
      CryptaAppCli.CatalogCommand.class
    })
public final class CryptaAppCli implements Runnable {
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
                  permissions,
                  overwrite));
      super.commandLine().getOut().println("Initialized app bundle at " + scaffolded);
      return CommandLine.ExitCode.OK;
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

    @Option(names = "--strict", description = "Treat permission lint warnings as failures.")
    private boolean strict;

    @Override
    public Integer call() throws Exception {
      BundleValidation validation = BundleValidator.validate(bundleDir, false);
      if (validation.permissionLint().hasUnknownPermissions()) {
        super.commandLine()
            .getErr()
            .println(
                "Warning: unknown app permission(s): "
                    + String.join(", ", validation.permissionLint().unknownPermissions()));
      }
      CompatibilityVerificationResult compatibility =
          PlatformApiContractVerifier.verify(
              validation.manifest().apiCompatibility(),
              validation.manifest().permissions(),
              PlatformApiContract.current(),
              strict);
      printCompatibilityFindings(super.commandLine(), compatibility);
      if (compatibility.hasErrors()) {
        throw new AppDistributionException("compatibility verification failed");
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
        return PlatformApiContract.current();
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
      if (descriptorCompatibility.apiCompatibility().declared()
          && !descriptorCompatibility
              .apiCompatibility()
              .equals(inspection.manifest().apiCompatibility())) {
        findings.add(
            compatibilityFinding(
                "catalog_api_compatibility_mismatch",
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
      subcommands = {ReviewSignCommand.class, ReviewVerifyCommand.class})
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
                  + decision.reviewerKeyId());
      return CommandLine.ExitCode.OK;
    }
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
          finding.severity() == CompatibilityFindingSeverity.ERROR ? "Error: " : "Warning: ";
      commandLine.getErr().println(prefix + finding.message());
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
