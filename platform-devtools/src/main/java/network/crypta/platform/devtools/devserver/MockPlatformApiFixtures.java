package network.crypta.platform.devtools.devserver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Map;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Loads deterministic mock Platform API JSON fixtures.
 *
 * <p>The dev server can serve built-in fixture JSON or developer-provided JSON files from a single
 * fixture directory. Built-ins keep scaffolded apps useful without setup, while file fixtures let
 * tests and local demos exercise specific queue, vault, node, and current-app states. Fixture
 * values remain static for the life of the request; mutation routes return acknowledgements rather
 * than modifying fixture files.
 *
 * <p>When reading developer fixtures, this class refuses symlink fixture directories, symlink
 * files, non-regular files, path traversal outside the fixture directory, and JSON strings that
 * contain obvious absolute local paths. That keeps mock output from leaking workstation paths into
 * browser-visible responses or app test reports.
 */
final class MockPlatformApiFixtures {
  /** Built-in JSON fixtures keyed by the optional fixture file names accepted by the CLI. */
  private static final Map<String, String> DEFAULTS =
      Map.ofEntries(
          Map.entry(
              "node.json",
              """
              {"nodeName":"Crypta local dev","status":"mock","apiVersion":"v1"}
              """),
          Map.entry(
              "queue.json",
              """
              {"page":"downloads","requests":[{"id":"mock-download-1","name":"Example download","state":"running","priority":"normal"},{"id":"mock-insert-1","name":"Example insert","state":"queued","priority":"low"}],"contentHtml":"<p>Mock queue data</p>"}
              """),
          Map.entry(
              "vault-identities.json",
              """
              {"identities":[{"identityId":"local-profile","id":"local-profile","label":"Local Profile","displayName":"Local Profile","kind":"mock","status":"available","fingerprint":"mock-profile-fingerprint","usageScopes":["metadata.read","sign.domain-separated"]}]}
              """),
          Map.entry(
              "vault-grants.json",
              """
              {"grants":[{"id":"grant-local-profile","identityId":"local-profile","scopes":["metadata.read"],"status":"mock-granted"}]}
              """),
          Map.entry(
              "apps-current.json",
              """
              {"appId":"${APP_ID}","name":"${APP_NAME}","version":"${APP_VERSION}","mode":"mock-dev"}
              """),
          Map.entry(
              "trust-graph-status.json",
              """
              {"trustGraph":{"available":true,"service":"trust-graph-preview","documentType":"crypta.trust.statement.v1","contentType":"application/vnd.crypta.trust+json","statementCount":1,"anchorCount":1,"scoring":"mock-direct-local-anchor","completeWot":false,"mock":true}}
              """),
          Map.entry(
              "trust-graph-anchors.json",
              """
              {"anchors":[{"issuerFingerprint":"mock-profile-fingerprint","label":"Local Profile","source":"manual","addedAt":"2026-05-17T00:00:00Z"}]}
              """),
          Map.entry(
              "trust-graph-score.json",
              """
              {"score":{"subject":{"kind":"profile","uri":"USK@mock/profile.json"},"context":"profile","status":"trusted","score":50,"confidence":80,"evidenceCount":1,"contributingEvidenceCount":1,"evidence":[{"issuerFingerprint":"mock-profile-fingerprint","score":50,"confidence":80,"issuedAt":"2026-05-16T00:00:00Z","contributing":true,"source":"mock-fixture"}],"mock":true}}
              """));

  /** Deterministic app-owned identity creation response. */
  static final String CREATED_IDENTITY_RESPONSE =
      """
      {"identity":{"identityId":"mock-created-profile","id":"mock-created-profile","label":"Mock Created Profile","displayName":"Mock Created Profile","kind":"mock","status":"available","usageScopes":["metadata.read","sign.domain-separated"]},"mock":true,"action":"app-vault.identities.create"}
      """;

  /** Deterministic acknowledgement for an app JSON document insert request. */
  static final String APP_DOCUMENT_INSERT_RESPONSE =
      """
      {"status":"ok","mock":true,"action":"queue.inserts.app-document","identifier":"mock-app-document","uri":"CHK@mock-app-document"}
      """;

  /** Deterministic bounded content-fetch response containing a mock trust statement document. */
  static final String CONTENT_FETCH_TRUST_STATEMENT_RESPONSE =
      """
      {"requestedUri":"CHK@mock-trust-statement","resolvedUri":"CHK@mock-trust-statement","format":"text","bytesLength":445,"contentText":"{\\"type\\":\\"crypta.trust.statement.v1\\",\\"payload\\":{\\"issuer\\":{\\"identityId\\":\\"local-profile\\",\\"publicKeyFingerprint\\":\\"mock-profile-fingerprint\\"},\\"subject\\":{\\"kind\\":\\"profile\\",\\"uri\\":\\"USK@mock/profile.json\\"},\\"context\\":\\"profile\\",\\"score\\":50,\\"confidence\\":80,\\"issuedAt\\":\\"2026-05-16T00:00:00Z\\"},\\"signature\\":{\\"algorithm\\":\\"app-vault-ed25519-preview\\",\\"domain\\":\\"crypta.trust.statement.v1\\",\\"value\\":\\"mock-preview-signature\\"}}","mock":true}
      """;

  /** Optional normalized directory containing user-supplied JSON fixture files. */
  private final Path fixtureDir;

  /** App id used to fill placeholders in the current-app fixture. */
  private final String appId;

  /** App display name used to fill placeholders in the current-app fixture. */
  private final String appName;

  /** App version used to fill placeholders in the current-app fixture. */
  private final String appVersion;

  /**
   * Creates a fixture provider for one staged app.
   *
   * @param fixtureDir optional fixture directory supplied by the developer
   * @param appId app id used by default current-app responses
   * @param appName app display name used by default current-app responses
   * @param appVersion app version used by default current-app responses
   */
  MockPlatformApiFixtures(Path fixtureDir, String appId, String appName, String appVersion) {
    this.fixtureDir = fixtureDir == null ? null : fixtureDir.toAbsolutePath().normalize();
    this.appId = appId;
    this.appName = appName;
    this.appVersion = appVersion;
  }

  /**
   * Returns node metadata fixture JSON.
   *
   * @return fixture-backed or built-in node JSON
   * @throws IOException if fixture loading fails
   */
  String node() throws IOException {
    return fixture("node.json");
  }

  /**
   * Returns queue listing fixture JSON.
   *
   * @return fixture-backed or built-in queue JSON
   * @throws IOException if fixture loading fails
   */
  String queue() throws IOException {
    return fixture("queue.json");
  }

  /**
   * Returns app-vault identity listing fixture JSON.
   *
   * @return fixture-backed or built-in identity JSON with safe mock data
   * @throws IOException if fixture loading fails
   */
  String vaultIdentities() throws IOException {
    return fixture("vault-identities.json");
  }

  /**
   * Returns app-vault grant listing fixture JSON.
   *
   * @return fixture-backed or built-in grant JSON with safe mock data
   * @throws IOException if fixture loading fails
   */
  String vaultGrants() throws IOException {
    return fixture("vault-grants.json");
  }

  /**
   * Returns current-app metadata fixture JSON.
   *
   * @return fixture-backed or built-in current-app JSON after placeholder replacement
   * @throws IOException if fixture loading fails
   */
  String appsCurrent() throws IOException {
    return fixture("apps-current.json");
  }

  /**
   * Returns Trust Graph Preview status fixture JSON.
   *
   * @return fixture-backed or built-in trust graph status JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphStatus() throws IOException {
    return fixture("trust-graph-status.json");
  }

  /**
   * Returns local trust-anchor fixture JSON.
   *
   * @return fixture-backed or built-in anchor list JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphAnchors() throws IOException {
    return fixture("trust-graph-anchors.json");
  }

  /**
   * Returns deterministic Trust Graph Preview score JSON.
   *
   * @return fixture-backed or built-in score JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphScore() throws IOException {
    return fixture("trust-graph-score.json");
  }

  /**
   * Builds a deterministic profile document preview response for a mock identity.
   *
   * @param identityId identity id segment supplied in the route
   * @return compact JSON response with path-free, token-free profile document metadata
   */
  String profileDocument(String identityId) {
    String escapedIdentityId = Json.escape(identityId);
    return "{\"profileDocument\":{\"schema\":\"crypta.profile.v1\",\"identityId\":\""
        + escapedIdentityId
        + "\",\"profile\":{\"displayName\":\"Local Profile\",\"bio\":\"Mock profile"
        + " document\",\"tags\":[\"local\",\"mock\"]},\"identity\":{\"identityId\":\""
        + escapedIdentityId
        + "\",\"fingerprint\":\"mock-profile-fingerprint\",\"algorithm\":\"Ed25519\"}},\"mock\":true,\"action\":\"app-vault.identities.profile-document\"}";
  }

  /**
   * Builds a deterministic trust-statement preview response for a mock identity.
   *
   * @param identityId identity id segment supplied in the route
   * @return compact JSON response with public trust statement metadata only
   */
  String trustStatement(String identityId) {
    String escapedIdentityId = Json.escape(identityId);
    return "{\"trustStatement\":{\"identity\":{\"identityId\":\""
        + escapedIdentityId
        + "\",\"publicKeyFingerprint\":\"mock-profile-fingerprint\",\"publicKeyBase64\":\"mock-public-key-base64\",\"appId\":\""
        + Json.escape(appId)
        + "\"},\"payloadHash\":\"5e1ec6f9a9a04cb4738f711bd49a9b25f6f0d5565d3c0845eb55b443f086c53a"
        + "\",\"domain\":\"crypta.trust.statement.v1\",\"trustStatement\":{\"type\":\"crypta.trust.statement.v1\","
        + "\"payload\":{\"issuer\":{\"identityId\":\""
        + escapedIdentityId
        + "\",\"publicKeyFingerprint\":\"mock-profile-fingerprint\",\"publicKeyBase64\":\"mock-public-key-base64\"},\"subject\":{\"kind\":\"profile\","
        + "\"uri\":\"USK@mock/profile.json\"},\"context\":\"profile\",\"score\":50,\"confidence\":80,"
        + "\"issuedAt\":\"2026-05-16T00:00:00Z\"},\"signature\":{\"algorithm\":\"app-vault-ed25519-preview\","
        + "\"domain\":\"crypta.trust.statement.v1\",\"value\":\"mock-preview-signature\"}},\"mock\":true,"
        + "\"action\":\"app-vault.identities.trust-statement\"}}";
  }

  /**
   * Builds a deterministic mutation acknowledgement.
   *
   * @param action stable action label for the route that accepted the mutation
   * @return compact JSON acknowledgement with no persistent state change
   */
  String mutation(String action) {
    return "{\"status\":\"ok\",\"mock\":true,\"action\":\"" + Json.escape(action) + "\"}";
  }

  /**
   * Loads a named fixture from disk when present, otherwise uses the built-in default.
   *
   * @param name fixture file name such as {@code queue.json}
   * @return fixture JSON after placeholder replacement and whitespace trimming
   * @throws IOException if a present fixture is unsafe or cannot be read
   */
  private String fixture(String name) throws IOException {
    String json = fixtureDir == null ? null : readFixture(name);
    if (json == null) {
      json = DEFAULTS.get(name);
    }
    return applyAppPlaceholders(json.strip());
  }

  /**
   * Reads one user fixture file from the configured fixture directory.
   *
   * @param name file name selected from the supported fixture list
   * @return fixture text, or {@code null} when the file is absent
   * @throws IOException if the directory or file is unsafe or unreadable
   */
  private String readFixture(String name) throws IOException {
    if (!Files.isDirectory(fixtureDir, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(fixtureDir)) {
      throw new AppDistributionException("fixture directory must be a real directory");
    }
    Path file = fixtureDir.resolve(name).normalize();
    if (!file.startsWith(fixtureDir) || !Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return null;
    }
    if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("fixture file must be a regular file: " + name);
    }
    String text = Files.readString(file, StandardCharsets.UTF_8);
    rejectLocalPathLeaks(text, name);
    return text;
  }

  /**
   * Rejects fixture JSON that appears to expose absolute local filesystem paths.
   *
   * @param text fixture text read from disk
   * @param name fixture file name used in diagnostics
   * @throws AppDistributionException if a quoted Unix or Windows absolute path is detected
   */
  private static void rejectLocalPathLeaks(String text, String name)
      throws AppDistributionException {
    if (text.matches("(?s).*\"/[^\"]*\".*")
        || text.matches("(?s).*\"[A-Za-z]:\\\\\\\\[^\"]*\".*")) {
      throw new AppDistributionException("fixture output contains an absolute local path: " + name);
    }
  }

  /**
   * Replaces app metadata placeholders in fixture JSON.
   *
   * @param json fixture JSON that may contain {@code ${APP_ID}}, {@code ${APP_NAME}}, or {@code
   *     ${APP_VERSION}}
   * @return fixture JSON with placeholders replaced by escaped app metadata
   */
  private String applyAppPlaceholders(String json) {
    return json.replace("${APP_ID}", Json.escape(appId))
        .replace("${APP_NAME}", Json.escape(appName))
        .replace("${APP_VERSION}", Json.escape(appVersion));
  }

  /** Small JSON string escaper for mock response values. */
  static final class Json {
    /** Prevents construction of this stateless JSON helper. */
    private Json() {}

    /**
     * Escapes one string for inclusion in mock JSON responses.
     *
     * @param value raw value to escape
     * @return escaped JSON string content without surrounding quote characters
     */
    static String escape(String value) {
      StringBuilder out = new StringBuilder(value.length());
      for (int index = 0; index < value.length(); index++) {
        char c = value.charAt(index);
        switch (c) {
          case '"' -> out.append("\\\"");
          case '\\' -> out.append("\\\\");
          case '\b' -> out.append("\\b");
          case '\f' -> out.append("\\f");
          case '\n' -> out.append("\\n");
          case '\r' -> out.append("\\r");
          case '\t' -> out.append("\\t");
          default -> {
            if (c < 0x20) {
              out.append(String.format("\\u%04x", (int) c));
            } else {
              out.append(c);
            }
          }
        }
      }
      return out.toString();
    }
  }
}
