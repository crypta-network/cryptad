package network.crypta.platform.apphost.sandbox;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppSandboxMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppSandboxProvidersTest {
  @TempDir private Path tempDir;

  @Test
  void noSandboxProvider_whenPreparingLaunch_expectDeterministicNoSandboxStatus() {
    AppSandboxLaunchContext context = context(new AppSandboxPolicy(AppSandboxMode.NONE, false));

    AppSandboxLaunchPlan plan = new NoSandboxProvider().prepareLaunch(context);

    assertEquals(List.of("bin/launch.sh"), plan.command());
    assertEquals(context.environment(), plan.environment());
    assertEquals(context.workingDirectory(), plan.workingDirectory());
    assertEquals(AppSandboxMode.NONE, plan.sandboxStatus().mode());
    assertEquals(AppSandboxSupportLevel.NONE, plan.sandboxStatus().supportLevel());
    assertEquals("no-sandbox", plan.sandboxStatus().providerName());
    assertFalse(plan.sandboxStatus().active());
  }

  @Test
  void restrictedProvider_whenPreparingLaunch_expectBestEffortStatus() throws Exception {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxLaunchPlan plan = new RestrictedProcessSandboxProvider().prepareLaunch(context);

    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, plan.sandboxStatus().mode());
    assertEquals(AppSandboxSupportLevel.BEST_EFFORT, plan.sandboxStatus().supportLevel());
    assertEquals("restricted-process", plan.sandboxStatus().providerName());
    assertTrue(plan.sandboxStatus().active());
    assertTrue(plan.sandboxStatus().warnings().toString().contains("best-effort"));
  }

  @Test
  void providers_whenRequiredWasmPreviewRequested_expectUnsupportedSandboxFailure() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.WASM_PREVIEW, true));

    AppSandboxException exception =
        assertThrows(
            AppSandboxException.class, () -> AppSandboxProviders.defaults().prepareLaunch(context));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertTrue(exception.getMessage().contains("wasm-preview"));
  }

  @Test
  void providers_whenOptionalWasmPreviewRequested_expectUnsupportedLaunchPlan() throws Exception {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.WASM_PREVIEW, false));

    AppSandboxLaunchPlan plan = AppSandboxProviders.defaults().prepareLaunch(context);

    assertEquals(context.command(), plan.command());
    assertEquals(context.environment(), plan.environment());
    assertEquals(context.workingDirectory(), plan.workingDirectory());
    assertEquals(AppSandboxMode.WASM_PREVIEW, plan.sandboxStatus().mode());
    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, plan.sandboxStatus().supportLevel());
    assertEquals("unsupported", plan.sandboxStatus().providerName());
    assertFalse(plan.sandboxStatus().active());
    assertTrue(plan.sandboxStatus().warnings().toString().contains("wasm-preview"));
  }

  @Test
  void providers_whenBubblewrapAvailable_expectRestrictedProcessUsesEnforcedProvider()
      throws Exception {
    AppSandboxProviders providers =
        new AppSandboxProviders(
            new NoSandboxProvider(),
            List.of(availableBubblewrapProvider(), new RestrictedProcessSandboxProvider()),
            false,
            null);
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxLaunchPlan plan = providers.prepareLaunch(context);

    assertEquals(AppSandboxSupportLevel.ENFORCED, plan.sandboxStatus().supportLevel());
    assertEquals("bubblewrap", plan.sandboxStatus().providerName());
    assertTrue(plan.command().contains("--"));
    assertFalse(plan.command().toString().contains("secret-token"));
  }

  @Test
  void inactiveStatusFor_whenBubblewrapAvailable_expectEnforcedInactiveRestrictedStatus() {
    AppSandboxProviders providers =
        new AppSandboxProviders(
            new NoSandboxProvider(),
            List.of(availableBubblewrapProvider(), new RestrictedProcessSandboxProvider()),
            false,
            null);
    AppSandboxPolicy policy = new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false);

    AppSandboxStatus status = providers.inactiveStatusFor(policy);

    assertEquals(AppSandboxSupportLevel.ENFORCED, status.supportLevel());
    assertEquals("bubblewrap", status.providerName());
    assertFalse(status.active());
    assertTrue(status.reason().contains("will be used on start"));
    assertFalse(status.toString().contains("secret-token"));
    assertFalse(status.toString().contains(tempDir.toString()));
  }

  @Test
  void providers_whenOptionalRestrictedProcessBubblewrapUnavailable_expectBestEffortFallback()
      throws Exception {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(linuxWithoutPath(), Map.of());
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxLaunchPlan plan = providers.prepareLaunch(context);

    assertEquals(AppSandboxSupportLevel.BEST_EFFORT, plan.sandboxStatus().supportLevel());
    assertEquals("restricted-process", plan.sandboxStatus().providerName());
  }

  @Test
  void inactiveStatusFor_whenAutoBubblewrapUnavailable_expectBestEffortInactiveRestrictedStatus() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(linuxWithoutPath(), Map.of());
    AppSandboxPolicy policy = new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false);

    AppSandboxStatus status = providers.inactiveStatusFor(policy);

    assertEquals(AppSandboxSupportLevel.BEST_EFFORT, status.supportLevel());
    assertEquals("restricted-process", status.providerName());
    assertFalse(status.active());
    assertTrue(status.warnings().toString().contains("best-effort"));
  }

  @Test
  void providers_whenBubblewrapPreflightFails_expectOptionalRestrictedProcessBestEffortFallback()
      throws Exception {
    AppSandboxProviders providers =
        new AppSandboxProviders(
            new NoSandboxProvider(),
            List.of(
                bubblewrapProviderWithNamespacePreflight(false),
                new RestrictedProcessSandboxProvider()),
            false,
            null);
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxLaunchPlan plan = providers.prepareLaunch(context);

    assertEquals(AppSandboxSupportLevel.BEST_EFFORT, plan.sandboxStatus().supportLevel());
    assertEquals("restricted-process", plan.sandboxStatus().providerName());
  }

  @Test
  void providers_whenRequiredRestrictedProcessBubblewrapUnavailable_expectFailClosed() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(linuxWithoutPath(), Map.of());
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxException exception =
        assertThrows(AppSandboxException.class, () -> providers.prepareLaunch(context));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertTrue(exception.getMessage().contains("restricted-process"));
    assertFalse(exception.getMessage().contains("secret-token"));
    assertFalse(exception.getMessage().contains(tempDir.toString()));
    assertTrue(exception.sandboxStatus().isPresent());
    assertEquals(
        AppSandboxSupportLevel.UNSUPPORTED, exception.sandboxStatus().orElseThrow().supportLevel());
  }

  @Test
  void providers_whenForcedBestEffort_expectRestrictedProcessNeverReportsEnforced()
      throws Exception {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "best-effort"));
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxLaunchPlan plan = providers.prepareLaunch(context);

    assertEquals(AppSandboxSupportLevel.BEST_EFFORT, plan.sandboxStatus().supportLevel());
    assertEquals("restricted-process", plan.sandboxStatus().providerName());
  }

  @Test
  void inactiveStatusFor_whenForcedBestEffortRequired_expectUnsupportedRequiredRestrictedStatus() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "best-effort"));
    AppSandboxPolicy policy = new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true);

    AppSandboxStatus status = providers.inactiveStatusFor(policy);

    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.supportLevel());
    assertEquals("unsupported", status.providerName());
    assertTrue(status.required());
    assertFalse(status.active());
    assertTrue(status.reason().contains("requires an enforced provider"));
  }

  @Test
  void providers_whenForcedBubblewrapUnavailable_expectUnsupportedSandboxFailure() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithoutPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "bubblewrap"));
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxException exception =
        assertThrows(AppSandboxException.class, () -> providers.prepareLaunch(context));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertFalse(exception.getMessage().contains(tempDir.toString()));
  }

  @Test
  void inactiveStatusFor_whenForcedBubblewrapUnavailable_expectUnsupportedRestrictedStatus() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithoutPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "bubblewrap"));
    AppSandboxPolicy policy = new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false);

    AppSandboxStatus status = providers.inactiveStatusFor(policy);

    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.supportLevel());
    assertEquals("unsupported", status.providerName());
    assertFalse(status.active());
    assertTrue(status.reason().contains("restricted-process"));
  }

  @Test
  void providers_whenForcedNoneOptionalRestrictedProcess_expectUnsupportedLaunchPlan()
      throws Exception {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "none"));
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxLaunchPlan plan = providers.prepareLaunch(context);

    assertEquals(context.command(), plan.command());
    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, plan.sandboxStatus().supportLevel());
    assertEquals("unsupported", plan.sandboxStatus().providerName());
    assertFalse(plan.sandboxStatus().active());
  }

  @Test
  void inactiveStatusFor_whenForcedNoneOptionalRestrictedProcess_expectUnsupportedStatus() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "none"));
    AppSandboxPolicy policy = new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false);

    AppSandboxStatus status = providers.inactiveStatusFor(policy);

    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.supportLevel());
    assertEquals("unsupported", status.providerName());
    assertFalse(status.required());
    assertFalse(status.active());
  }

  @Test
  void providers_whenForcedNoneRequiredRestrictedProcess_expectFailClosed() {
    AppSandboxProviders providers =
        AppSandboxProviders.fromHostConfiguration(
            linuxWithPath(), Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "none"));
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxException exception =
        assertThrows(AppSandboxException.class, () -> providers.prepareLaunch(context));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertTrue(exception.sandboxStatus().isPresent());
    assertEquals(
        AppSandboxSupportLevel.UNSUPPORTED, exception.sandboxStatus().orElseThrow().supportLevel());
  }

  @Test
  void providers_whenMacOrWindowsHost_expectRestrictedProcessIsNotEnforced() throws Exception {
    for (AppEnv appEnv :
        List.of(new AppEnv(Map.of(), "Mac OS X"), new AppEnv(Map.of(), "Windows 11"))) {
      AppSandboxProviders providers = AppSandboxProviders.fromHostConfiguration(appEnv, Map.of());
      AppSandboxLaunchPlan plan =
          providers.prepareLaunch(
              context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));

      assertNotSame(AppSandboxSupportLevel.ENFORCED, plan.sandboxStatus().supportLevel());
    }
  }

  @Test
  void restrictedProvider_whenWorkingDirectoryDiffers_expectInvalidLaunchFailure() {
    AppSandboxLaunchContext context =
        context(
            new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true),
            tempDir.resolve("elsewhere"));

    AppSandboxException exception =
        assertThrows(
            AppSandboxException.class,
            () -> new RestrictedProcessSandboxProvider().prepareLaunch(context));

    assertEquals("invalid_sandbox_launch", exception.errorCode());
    assertTrue(exception.getMessage().contains("installed bundle"));
    assertFalse(exception.getMessage().contains("secret-token"));
  }

  @Test
  void launchContextToString_whenEnvironmentContainsToken_expectTokenValueOmitted() {
    AppSandboxLaunchContext context = context(new AppSandboxPolicy(AppSandboxMode.NONE, false));

    String text = context.toString();

    assertTrue(text.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(text.contains("secret-token"));
    assertFalse(text.contains(tempDir.toString()));
  }

  @Test
  void launchPlanToString_whenEnvironmentContainsToken_expectTokenValueOmitted() {
    AppSandboxLaunchPlan plan =
        new NoSandboxProvider()
            .prepareLaunch(context(new AppSandboxPolicy(AppSandboxMode.NONE, false)));

    String text = plan.toString();

    assertTrue(text.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(text.contains("secret-token"));
    assertFalse(text.contains("bin/launch.sh"));
    assertFalse(text.contains(tempDir.toString()));
  }

  private AppSandboxLaunchContext context(AppSandboxPolicy policy) {
    return context(policy, appRoot());
  }

  private AppSandboxLaunchContext context(AppSandboxPolicy policy, Path workingDirectory) {
    Path root = appRoot();
    return new AppSandboxLaunchContext(
        "sample-app",
        root,
        tempDir.resolve("data").resolve("sample-app"),
        tempDir.resolve("cache").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"),
        List.of("bin/launch.sh"),
        Map.of("CRYPTAD_APP_ID", "sample-app", "CRYPTAD_APP_TOKEN", "secret-token"),
        workingDirectory,
        policy,
        linuxWithPath());
  }

  private Path appRoot() {
    return tempDir.resolve("installed").resolve("sample-app");
  }

  private static AppEnv linuxWithPath() {
    return new AppEnv(Map.of("PATH", "/usr/bin"), "Linux");
  }

  private static AppEnv linuxWithoutPath() {
    return new AppEnv(Map.of("PATH", ""), "Linux");
  }

  private static BubblewrapSandboxProvider availableBubblewrapProvider() {
    return bubblewrapProviderWithNamespacePreflight(true);
  }

  private static BubblewrapSandboxProvider bubblewrapProviderWithNamespacePreflight(
      boolean namespaceAvailable) {
    BubblewrapAvailability availability =
        new BubblewrapAvailability(
            linuxWithPath(),
            "",
            new BubblewrapAvailability.ExecutableProbe() {
              @Override
              public boolean onPath(AppEnv appEnv, String command) {
                return true;
              }

              @Override
              public boolean isExecutable(Path executable) {
                return true;
              }

              @Override
              public boolean sandboxPreflightFails(String executable) {
                return !namespaceAvailable;
              }
            });
    return new BubblewrapSandboxProvider(availability);
  }
}
