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
        new AppEnv());
  }

  private Path appRoot() {
    return tempDir.resolve("installed").resolve("sample-app");
  }
}
