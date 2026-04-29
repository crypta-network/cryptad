package network.crypta.platform.devtools;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogBuildRequest;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appcatalog.AppCatalogWriter;
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
      BundleValidation validation = BundleValidator.validate(bundleDir, strict);
      if (validation.permissionLint().hasUnknownPermissions()) {
        super.commandLine()
            .getErr()
            .println(
                "Warning: unknown app permission(s): "
                    + String.join(", ", validation.permissionLint().unknownPermissions()));
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
                  Optional.of(normalizedCatalogFile)));
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
