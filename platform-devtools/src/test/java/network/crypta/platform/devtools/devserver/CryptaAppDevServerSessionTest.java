package network.crypta.platform.devtools.devserver;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaAppDevServerSessionTest {
  private static final Pattern BOOTSTRAP_SESSION_PATTERN =
      Pattern.compile("\"browserSessionToken\"\\s*:\\s*\"([^\"]+)\"");
  private static final Instant START = Instant.parse("2026-05-14T00:00:00Z");
  private static final String EXPIRING_APP_ID = "expiring-app";

  @TempDir private Path tempDir;

  @Test
  void devServer_whenSessionExpires_expectApiRejectsOldTokenAndBootstrapRefreshes()
      throws IOException, InterruptedException {
    Path appDir = scaffoldExpiringApp();
    MutableClock clock = new MutableClock(START);

    try (CryptaAppDevServer server =
            CryptaAppDevServer.start(
                new DevServerConfig(appDir, "127.0.0.1", 0, null, false, Duration.ofMinutes(10)),
                clock,
                new SecureRandom());
        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HttpClient.Version.HTTP_1_1)
                .build()) {
      URI bootstrapUri =
          URI.create(server.apiRoot().replace("/api/v1/", "/.well-known/cryptad-bootstrap.json"));
      URI queueUri = URI.create(server.apiRoot() + "queue");
      String firstToken = sessionToken(get(client, bootstrapUri).body());

      assertEquals(200, getWithSession(client, queueUri, firstToken).statusCode());

      clock.advance(Duration.ofMinutes(10).plusSeconds(1));
      HttpResponse<String> expired = getWithSession(client, queueUri, firstToken);
      String refreshedToken = sessionToken(get(client, bootstrapUri).body());

      assertEquals(401, expired.statusCode());
      assertTrue(expired.body().contains("invalid_app_browser_session"));
      assertNotEquals(firstToken, refreshedToken);
      assertEquals(200, getWithSession(client, queueUri, refreshedToken).statusCode());
    }
  }

  private Path scaffoldExpiringApp() {
    Path appDir = tempDir.resolve(EXPIRING_APP_ID);
    try {
      Files.createDirectories(appDir.resolve("bin"));
      Files.createDirectories(appDir.resolve("static"));
      Files.writeString(
          appDir.resolve("cryptad-app.properties"),
          """
          manifest.version=1
          app.id=%s
          app.name=Expiring App
          app.version=0.1.0
          api.minimumVersion=1
          api.maximumTestedVersion=1
          api.targetStability=stable
          api.experimentalCapabilitiesAccepted=false
          app.exec=bin/start.sh
          app.ui.mode=static
          app.ui.entry=static/index.html
          sandbox.mode=none
          sandbox.required=false
          quota.data.bytes=0
          quota.cache.bytes=0
          app.restart.policy=never
          app.restart.maxAttempts=0
          app.restart.backoff.ms=0
          """
              .formatted(EXPIRING_APP_ID),
          StandardCharsets.UTF_8);
      Files.writeString(appDir.resolve("bin").resolve("start.sh"), "#!/bin/sh\nexit 0\n");
      Files.writeString(
          appDir.resolve("static").resolve("index.html"),
          "<!doctype html><title>Expiring App</title>",
          StandardCharsets.UTF_8);
      return appDir;
    } catch (IOException exception) {
      throw new AssertionError("failed to create test app " + EXPIRING_APP_ID, exception);
    }
  }

  private static HttpResponse<String> get(HttpClient client, URI uri)
      throws IOException, InterruptedException {
    return client.send(
        HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
  }

  private static HttpResponse<String> getWithSession(HttpClient client, URI uri, String session)
      throws IOException, InterruptedException {
    return client.send(
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(5))
            .header("X-Crypta-App-Session", session)
            .GET()
            .build(),
        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
  }

  private static String sessionToken(String bootstrapJson) {
    Matcher matcher = BOOTSTRAP_SESSION_PATTERN.matcher(bootstrapJson);
    if (!matcher.find()) {
      throw new AssertionError("bootstrap did not include a browser session token");
    }
    return matcher.group(1);
  }

  private static final class MutableClock extends Clock {
    private Instant current;

    private MutableClock(Instant current) {
      this.current = current;
    }

    private void advance(Duration duration) {
      current = current.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneId.of("UTC");
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return current;
    }

    @Override
    public boolean equals(Object other) {
      return this == other;
    }

    @Override
    public int hashCode() {
      return System.identityHashCode(this);
    }
  }
}
