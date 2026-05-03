package network.crypta.platform.apphost.sandbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppSandboxMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BubblewrapSandboxProviderTest {
  private static final String SECRET_TOKEN = "secret-token";

  @TempDir private Path tempDir;

  @Test
  void supports_whenLinuxAndBwrapAvailable_expectRestrictedProcessOnly() {
    BubblewrapSandboxProvider provider = provider(linux(), true);

    assertTrue(provider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.NONE, false)));
    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.WASM_PREVIEW, false)));
  }

  @Test
  void supports_whenMacOrWindows_expectNoBubblewrapSupport() {
    BubblewrapSandboxProvider macProvider = provider(new AppEnv(Map.of(), "Mac OS X"), true);
    BubblewrapSandboxProvider windowsProvider = provider(new AppEnv(Map.of(), "Windows 11"), true);

    assertFalse(
        macProvider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
    assertFalse(
        windowsProvider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
  }

  @Test
  void supports_whenOtherUnixHost_expectNoBubblewrapSupport() {
    BubblewrapSandboxProvider provider = provider(new AppEnv(Map.of(), "FreeBSD"), true);

    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
  }

  @Test
  void supports_whenExecutablePresentButNamespacePreflightFails_expectNoBubblewrapSupport() {
    BubblewrapSandboxProvider provider = provider(linux(), true, false);

    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
  }

  @Test
  void prepareLaunch_whenBubblewrapAvailable_expectEnforcedWrappedCommand() throws Exception {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxLaunchPlan plan = provider(linux(), true).prepareLaunch(context);

    assertEquals("bwrap", plan.command().getFirst());
    int separator = plan.command().indexOf("--");
    assertTrue(separator > 0);
    assertEquals(context.command(), plan.command().subList(separator + 1, plan.command().size()));
    assertEquals(context.environment(), plan.environment());
    assertEquals(context.workingDirectory(), plan.workingDirectory());
    assertEquals(AppSandboxSupportLevel.ENFORCED, plan.sandboxStatus().supportLevel());
    assertEquals(BubblewrapSandboxProvider.PROVIDER_NAME, plan.sandboxStatus().providerName());
    assertTrue(plan.sandboxStatus().active());
  }

  @Test
  void prepareLaunch_whenExplicitExecutableConfigured_expectCommandUsesNormalizedExecutable()
      throws Exception {
    Path executable = tempDir.resolve("tools").resolve("bwrap");
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));
    BubblewrapSandboxProvider provider =
        new BubblewrapSandboxProvider(availability(linux(), executable.toString(), true, true));

    AppSandboxLaunchPlan plan = provider.prepareLaunch(context);

    assertEquals(executable.toAbsolutePath().normalize().toString(), plan.command().getFirst());
  }

  @Test
  void probe_whenExplicitExecutableIsRelative_expectUnavailablePathFreeReason() {
    BubblewrapAvailability.Result result =
        availability(linux(), "relative/bwrap", true, true).probe();

    assertFalse(result.available());
    assertEquals(
        "configured bubblewrap executable must be an absolute path", result.unavailableReason());
    assertFalse(result.unavailableReason().contains("relative/bwrap"));
  }

  @Test
  void prepareLaunch_whenContextContainsToken_expectCommandDoesNotExposeEnvironmentValues()
      throws Exception {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxLaunchPlan plan = provider(linux(), true).prepareLaunch(context);

    String commandText = plan.command().toString();
    assertFalse(commandText.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(commandText.contains(SECRET_TOKEN));
    assertFalse(commandText.contains("--setenv"));
    assertFalse(plan.sandboxStatus().toString().contains(SECRET_TOKEN));
    assertFalse(plan.sandboxStatus().toString().contains(tempDir.toString()));
  }

  @Test
  void commandBuilder_whenBuildingPlan_expectAppMountsUseExpectedAccess() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));
    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder().build("bwrap", context);

    assertMount(plan, context.installDir(), BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(plan, context.dataDir(), BubblewrapCommandBuilder.MountAccess.READ_WRITE);
    assertMount(plan, context.cacheDir(), BubblewrapCommandBuilder.MountAccess.READ_WRITE);
    assertMount(plan, context.runDir(), BubblewrapCommandBuilder.MountAccess.READ_WRITE);
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(mount -> mount.source().equals(tempDir.resolve("daemon-private"))));
  }

  @Test
  void commandBuilder_whenBuildingPlan_expectDirectoryMountsPrecedeBindMounts() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder().build("bwrap", context);

    assertTrue(
        plan.directoryMounts()
            .contains(context.installDir().toAbsolutePath().normalize().getParent()));
    int firstDirectoryMount = plan.command().indexOf("--dir");
    int firstReadOnlyBind = plan.command().indexOf("--ro-bind");
    int firstReadWriteBind = plan.command().indexOf("--bind");
    int firstBindMount = Math.min(firstReadOnlyBind, firstReadWriteBind);
    assertTrue(firstDirectoryMount > 0);
    assertTrue(firstDirectoryMount < firstBindMount);
  }

  @Test
  void commandBuilder_whenAlternativesDirectoryAvailable_expectReadOnlyMountWithoutEtcBind()
      throws IOException {
    Path alternatives = tempDir.resolve("etc").resolve("alternatives");
    Files.createDirectories(alternatives);
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder(List.of(alternatives)).build("bwrap", context);

    assertMount(plan, alternatives, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    Path etc = alternatives.getParent().toAbsolutePath().normalize();
    assertTrue(plan.directoryMounts().contains(etc));
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(mount -> mount.source().equals(etc) && mount.destination().equals(etc)));
  }

  @Test
  void commandBuilder_whenUsingDefaults_expectSystemAlternativesConsidered() {
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.ETC_ALTERNATIVES));
  }

  @Test
  void commandBuilder_whenExecutableBlank_expectRejectsLaunchPlan() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));
    BubblewrapCommandBuilder commandBuilder = new BubblewrapCommandBuilder();

    assertThrows(IllegalArgumentException.class, () -> commandBuilder.build("  ", context));
  }

  @Test
  void prepareLaunch_whenBubblewrapUnavailable_expectPathFreeUnsupportedFailure() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxException exception =
        assertThrows(
            AppSandboxException.class, () -> provider(linux(), false).prepareLaunch(context));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertFalse(exception.getMessage().contains(SECRET_TOKEN));
    assertFalse(exception.getMessage().contains(tempDir.toString()));
    assertTrue(exception.sandboxStatus().isPresent());
  }

  private static void assertMount(
      BubblewrapCommandBuilder.CommandPlan plan,
      Path destination,
      BubblewrapCommandBuilder.MountAccess access) {
    Path normalized = destination.toAbsolutePath().normalize();
    assertTrue(
        plan.bindMounts().stream()
            .anyMatch(
                mount ->
                    mount.destination().equals(normalized)
                        && mount.source().equals(normalized)
                        && mount.access() == access),
        () -> "missing " + access + " mount for " + normalized);
  }

  private BubblewrapSandboxProvider provider(AppEnv appEnv, boolean available) {
    return provider(appEnv, available, available);
  }

  private BubblewrapSandboxProvider provider(
      AppEnv appEnv, boolean executableAvailable, boolean namespaceAvailable) {
    return new BubblewrapSandboxProvider(
        availability(appEnv, "", executableAvailable, namespaceAvailable));
  }

  private BubblewrapAvailability availability(
      AppEnv appEnv,
      String configuredExecutable,
      boolean executableAvailable,
      boolean namespaceAvailable) {
    return new BubblewrapAvailability(
        appEnv,
        configuredExecutable,
        new BubblewrapAvailability.ExecutableProbe() {
          @Override
          public boolean onPath(AppEnv ignoredAppEnv, String command) {
            return executableAvailable;
          }

          @Override
          public boolean isExecutable(Path executable) {
            return executableAvailable;
          }

          @Override
          public boolean sandboxPreflightFails(String executable) {
            return !namespaceAvailable;
          }
        });
  }

  private AppSandboxLaunchContext context(AppSandboxPolicy policy) {
    return new AppSandboxLaunchContext(
        "sample-app",
        tempDir.resolve("installed").resolve("sample-app"),
        tempDir.resolve("data").resolve("sample-app"),
        tempDir.resolve("cache").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"),
        List.of("bin/launch.sh", "--serve"),
        Map.of("CRYPTAD_APP_ID", "sample-app", "CRYPTAD_APP_TOKEN", SECRET_TOKEN),
        tempDir.resolve("installed").resolve("sample-app"),
        policy,
        linux());
  }

  private static AppEnv linux() {
    return new AppEnv(Map.of(), "Linux");
  }
}
