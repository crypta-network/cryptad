package network.crypta.apps.sitepublisher;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SitePublisherDraftBehaviorTest {
  @TempDir Path temporaryDirectory;

  @Test
  void drafts_whenConvertedImportedEditedAndRecovered_expectDurablePrivateGuardedBehavior()
      throws Exception {
    Path harness = temporaryDirectory.resolve("drafts-behavior.cjs");
    try (var input = getClass().getResourceAsStream("/drafts-behavior.cjs")) {
      if (input == null) {
        throw new IllegalStateException("Draft behavior harness missing");
      }
      Files.copy(input, harness);
    }
    Path script = Path.of(System.getProperty("sitePublisher.stageDir"), "static", "drafts.js");
    Process process = new ProcessBuilder("node", harness.toString(), script.toString()).start();
    boolean finished = process.waitFor(20, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
    }
    String output =
        new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
            + new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(finished, output);
    assertEquals(0, process.exitValue(), output);
  }
}
