package network.crypta.platform.apphost.sandbox;

import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Linux bubblewrap provider for enforced AppHost restricted-process launches.
 *
 * <p>The provider wraps the original AppHost child command with {@code bwrap}. It enforces a
 * filesystem boundary around the installed bundle and AppHost-managed mutable directories, keeps
 * the app working directory at the installed bundle root, and passes the sanitized child
 * environment through unchanged. It never emits {@code --setenv} arguments for {@code
 * CRYPTAD_APP_TOKEN} or any other environment value.
 *
 * <p>The public status reports {@link AppSandboxSupportLevel#ENFORCED} only after a concrete
 * bubblewrap command has been generated for the launch. The status warnings deliberately do not
 * claim CPU, memory, or network isolation because this first provider version does not enforce
 * those controls.
 *
 * <p>{@link AppSandboxProviders} owns fallback selection. This provider answers only for Linux
 * bubblewrap launches that pass the availability preflight and launch-context validation. Optional
 * apps on unsupported hosts can therefore degrade to the best-effort provider, while required apps
 * fail closed before AppHost starts the child process.
 */
public final class BubblewrapSandboxProvider implements AppSandboxProvider {
  /** Stable provider name exposed through AppHost and Platform API status. */
  public static final String PROVIDER_NAME = "bubblewrap";

  private final BubblewrapAvailability availability;
  private final BubblewrapCommandBuilder commandBuilder;

  /**
   * Creates a provider with the supplied availability probe and default command builder.
   *
   * <p>This is the production constructor used by the default provider registry. The availability
   * probe decides whether bubblewrap is present and can create namespaces on the current host; the
   * command builder supplies the conservative filesystem plan for each accepted launch.
   *
   * @param availability host and tool availability probe used before launch planning
   */
  public BubblewrapSandboxProvider(BubblewrapAvailability availability) {
    this(availability, new BubblewrapCommandBuilder());
  }

  /**
   * Creates a provider with explicit dependencies for deterministic tests.
   *
   * <p>Tests use this constructor to simulate host combinations without depending on the CI
   * machine's operating system, {@code PATH}, or namespace settings. Production embeddings can use
   * it for the same reason if they provide their own probe implementation.
   *
   * @param availability host and tool availability probe used before launch planning
   * @param commandBuilder bubblewrap command builder for accepted launch contexts
   */
  public BubblewrapSandboxProvider(
      BubblewrapAvailability availability, BubblewrapCommandBuilder commandBuilder) {
    this.availability = Objects.requireNonNull(availability, "availability");
    this.commandBuilder = Objects.requireNonNull(commandBuilder, "commandBuilder");
  }

  /**
   * Returns the stable bubblewrap provider name.
   *
   * @return {@code bubblewrap}, safe for public sandbox status output
   */
  @Override
  public String providerName() {
    return PROVIDER_NAME;
  }

  /**
   * Returns whether bubblewrap is available for a restricted-process policy.
   *
   * <p>A {@code true} result means the manifest requested {@code restricted-process} and the
   * availability probe accepted the host. It does not by itself claim that the current launch is
   * enforced; that public claim is made only by {@link #prepareLaunch(AppSandboxLaunchContext)}
   * after the wrapper command has been generated successfully.
   *
   * @param policy requested sandbox policy from the app manifest
   * @return {@code true} when the policy is restricted-process and bubblewrap is available
   */
  @Override
  public boolean supports(AppSandboxPolicy policy) {
    return Objects.requireNonNull(policy, "policy").mode() == AppSandboxMode.RESTRICTED_PROCESS
        && availability.probe().available();
  }

  /**
   * Builds an enforced bubblewrap launch plan.
   *
   * <p>The method validates that AppHost supplied the installed bundle as the working directory,
   * that mutable directories are scoped to the app id, and that the sanitized AppHost environment
   * contains the required app identity and token keys. It then wraps the command while preserving
   * the environment map for {@link ProcessBuilder#environment()}; no environment value is copied to
   * bubblewrap arguments. The returned status is active and enforced because the launch plan now
   * contains a concrete bubblewrap wrapper command.
   *
   * @param context sensitive AppHost launch context for one restricted-process start attempt
   * @return launch plan with a bubblewrap command and enforced public status
   * @throws AppSandboxException if bubblewrap is unavailable or the launch context is invalid
   */
  @Override
  public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context)
      throws AppSandboxException {
    AppSandboxLaunchContext checkedContext = Objects.requireNonNull(context, "context");
    if (checkedContext.policy().mode() != AppSandboxMode.RESTRICTED_PROCESS) {
      throw new AppSandboxException(
          "unsupported_sandbox",
          "Provider bubblewrap cannot handle sandbox mode "
              + checkedContext.policy().mode().manifestValue());
    }
    BubblewrapAvailability.Result availabilityResult = availability.probe();
    if (!availabilityResult.available()) {
      throw new AppSandboxException(
          "unsupported_sandbox",
          availabilityResult.unavailableReason(),
          unavailableStatus(checkedContext));
    }
    validateRestrictedLaunchContext(checkedContext);
    BubblewrapCommandBuilder.CommandPlan commandPlan =
        commandBuilder.build(availabilityResult.executable(), checkedContext);
    return new AppSandboxLaunchPlan(
        commandPlan.command(),
        checkedContext.environment(),
        checkedContext.workingDirectory(),
        enforcedStatus(checkedContext.policy()));
  }

  private static void validateRestrictedLaunchContext(AppSandboxLaunchContext context)
      throws AppSandboxException {
    if (!context.workingDirectory().equals(context.installDir())) {
      throw new AppSandboxException(
          "invalid_sandbox_launch",
          "bubblewrap launch requires the installed bundle as working directory");
    }
    requireAppScopedDirectory(context.appId(), context.dataDir(), "dataDir");
    requireAppScopedDirectory(context.appId(), context.cacheDir(), "cacheDir");
    requireAppScopedDirectory(context.appId(), context.runDir(), "runDir");
    if (!context.logDir().equals(context.runDir())) {
      throw new AppSandboxException(
          "invalid_sandbox_launch", "bubblewrap launch requires logs under runDir");
    }
    if (!context.environment().containsKey("CRYPTAD_APP_ID")
        || !context.environment().containsKey("CRYPTAD_APP_TOKEN")) {
      throw new AppSandboxException(
          "invalid_sandbox_launch", "bubblewrap launch requires the sanitized AppHost environment");
    }
  }

  private static void requireAppScopedDirectory(String appId, java.nio.file.Path path, String label)
      throws AppSandboxException {
    java.nio.file.Path fileName = path.getFileName();
    if (fileName == null || !appId.equals(fileName.toString())) {
      throw new AppSandboxException(
          "invalid_sandbox_launch", "bubblewrap launch requires an app-scoped " + label);
    }
  }

  private static AppSandboxStatus unavailableStatus(AppSandboxLaunchContext context) {
    return AppSandboxStatus.unsupported(
        context.policy(), "bubblewrap sandbox is unavailable for this launch");
  }

  private static AppSandboxStatus enforcedStatus(AppSandboxPolicy policy) {
    return new AppSandboxStatus(
        policy.mode(),
        policy.required(),
        AppSandboxSupportLevel.ENFORCED,
        PROVIDER_NAME,
        true,
        "Linux bubblewrap sandbox active",
        List.of(
            "Filesystem sandbox active for installed bundle and AppHost-managed mutable"
                + " directories",
            "CPU, memory, and network restrictions are not enforced by this provider"));
  }
}
