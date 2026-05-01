package network.crypta.clients.http;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.l10n.TranslationPaths;
import network.crypta.platform.appui.AppUiPaths;
import network.crypta.platform.webshell.routes.WebShellPaths;

import static network.crypta.runtime.updater.UpdaterPaths.CORE_UPDATE_PATH;

/**
 * Authoritative retirement metadata for legacy admin HTTP surfaces.
 *
 * <p>The registry covers the admin/control-plane pages that are candidates for later retirement.
 * Concrete FProxy browse routes remain outside this registry except where an admin-owned helper
 * route directly supports a retained browse workflow. Matching is route-prefix based and uses the
 * longest known prefix, which keeps configurable config and queue subpaths attributed to their
 * parent surface without storing request parameters.
 *
 * <p>The list is intentionally static for PR-200. It gives notices, Web Shell fallback links, and
 * usage diagnostics one shared source of truth while legacy pages continue to exist. Callers should
 * treat the returned entries as policy metadata, not route registrations. The actual toadlet
 * registration still lives in the legacy HTTP container, and app/UI replacements remain owned by
 * their platform modules.
 *
 * <p>The registry is immutable after class initialization and is safe to read from request-handling
 * threads. Any future change to a route's state should update this registry, the retirement-plan
 * documentation, and the focused tests together so deletion decisions continue to be explainable.
 *
 * <ul>
 *   <li>{@link #surfaces()} exposes the full administrative map.
 *   <li>{@link #diagnosticSurfaces()} limits usage telemetry to user-facing tracked surfaces.
 *   <li>{@link #webShellFallbackSurfaces()} feeds retained and pending links back to the shell.
 *   <li>{@link #findByLegacyPath(String)} resolves request paths without storing query details.
 * </ul>
 */
public final class LegacyAdminRetirementRegistry {
  private static final String SHELL_PEERS_URL = WebShellPaths.SHELL_ROOT + "#peers";
  private static final String SHELL_CONNECTIVITY_URL = WebShellPaths.SHELL_ROOT + "#connectivity";
  private static final String SHELL_CONFIG_URL = WebShellPaths.SHELL_ROOT + "#config";
  private static final String SHELL_SECURITY_URL = WebShellPaths.SHELL_ROOT + "#security";
  private static final String SHELL_UPDATES_URL = WebShellPaths.SHELL_ROOT + "#updates";
  private static final String SHELL_ALERTS_URL = WebShellPaths.SHELL_ROOT + "#alerts";
  private static final String SHELL_DIAGNOSTICS_URL = WebShellPaths.SHELL_ROOT + "#diagnostics";
  private static final String SHELL_WIZARD_URL = WebShellPaths.SHELL_ROOT + "#wizard";
  private static final String WEB_SHELL_PEER_CONTROL_LABEL = "Web Shell peer control";
  private static final String QUEUE_MANAGER_URL = AppUiPaths.APPS_ROOT + "queue-manager/";
  private static final String PUBLISHER_URL = AppUiPaths.APPS_ROOT + "publisher/";
  private static final String SEND_N2NTM_PATH = localPath("send_n2ntm");
  private static final String CHAT_PATH = localPath("chat");
  private static final String HELP_PATH = localPath("help");

  private static final List<LegacyAdminSurface> SURFACES =
      List.of(
          infrastructure(
              "web-shell",
              "Web Shell bridge",
              WebShellPaths.SHELL_ROOT,
              "Hosts the replacement node-management shell."),
          infrastructure(
              "platform-api",
              "Platform API bridge",
              PlatformApiToadlet.MOUNT_PATH,
              "Hosts the JSON control plane used by Web Shell and first-party apps."),
          infrastructure(
              "app-ui",
              "App-owned static UI bridge",
              AppUiPaths.APPS_ROOT,
              "Hosts installed app-owned static UI routes."),
          infrastructure(
              "static-assets",
              "Legacy static assets",
              StaticToadlet.ROOT_URL,
              "Serves shared legacy page assets while fallback pages remain."),
          replaced(
              "alerts",
              "Alerts",
              "/alerts/",
              SHELL_ALERTS_URL,
              "Web Shell alerts",
              "Web Shell lists and dismisses alerts through Platform API v1."),
          replaced(
              "queue-downloads",
              "Download queue",
              QueueToadlet.PATH_DOWNLOADS,
              QUEUE_MANAGER_URL,
              "Queue Manager app",
              "Queue Manager and the Web Shell queue panel are the primary transfer views."),
          replaced(
              "queue-uploads",
              "Upload queue",
              QueueToadlet.PATH_UPLOADS,
              QUEUE_MANAGER_URL,
              "Queue Manager app",
              "Queue Manager and Publisher cover upload-queue monitoring and insert creation."),
          replaced(
              "file-insert",
              "File insert wizard",
              FileInsertWizardToadlet.PATH,
              PUBLISHER_URL,
              "Publisher app",
              "Publisher is the primary first-party UI for local file and directory inserts."),
          replaced(
              "local-file-insert",
              "Local upload file browser",
              LocalFileInsertToadlet.INSERT_BROWSE_PATH,
              PUBLISHER_URL,
              "Publisher app",
              "The route remains for legacy upload forms and operator fallback."),
          replaced(
              "friends",
              "Friends",
              LegacyHttpPaths.FRIENDS_PATH,
              SHELL_PEERS_URL,
              WEB_SHELL_PEER_CONTROL_LABEL,
              "Web Shell peer control covers darknet peer roster and mutations."),
          replaced(
              "add-friend",
              "Add friend",
              DarknetAddRefToadlet.PATH,
              SHELL_PEERS_URL,
              WEB_SHELL_PEER_CONTROL_LABEL,
              "Web Shell peer add handles the primary noderef import flow."),
          replaced(
              "strangers",
              "Strangers",
              "/strangers/",
              SHELL_PEERS_URL,
              WEB_SHELL_PEER_CONTROL_LABEL,
              "Opennet peer visibility belongs with the shell peer control plane."),
          replaced(
              "connectivity",
              "Connectivity",
              ConnectivityToadlet.CONNECTIVITY_PATH,
              SHELL_CONNECTIVITY_URL,
              "Web Shell connectivity",
              "Web Shell shows connectivity snapshots through Platform API v1."),
          replaced(
              "config",
              "Configuration",
              LegacyHttpPaths.CONFIG_PATH,
              SHELL_CONFIG_URL,
              "Web Shell config",
              "Web Shell owns the operator config subset and persistence actions."),
          replaced(
              "security-levels",
              "Security levels",
              SecurityLevelsToadlet.PATH,
              SHELL_SECURITY_URL,
              "Web Shell security",
              "Web Shell owns the primary security-level view and common mutations."),
          replaced(
              "core-update",
              "Core update actions",
              CORE_UPDATE_PATH,
              SHELL_UPDATES_URL,
              "Web Shell updates",
              "Web Shell owns the primary updater state and download trigger."),
          replaced(
              "statistics",
              "Statistics",
              StatisticsToadlet.TOADLET_URL,
              SHELL_DIAGNOSTICS_URL,
              "Web Shell diagnostics",
              "Diagnostics is the primary shell-native operator status surface."),
          replaced(
              "diagnostic",
              "Diagnostic report",
              DiagnosticToadlet.TOADLET_URL,
              SHELL_DIAGNOSTICS_URL,
              "Web Shell diagnostics",
              "The plain-text export remains useful as fallback and debug output."),
          pendingWizard(
              "first-time-wizard",
              "First-time wizard",
              FirstTimeWizardToadlet.TOADLET_URL,
              "The shell wizard exists, but startup routing still relies on the legacy wizard"
                  + " gate."),
          pendingWizard(
              "first-time-wizard-js",
              "JavaScript first-time wizard",
              FirstTimeWizardNewToadlet.TOADLET_URL,
              "The JavaScript wizard remains part of first-run fallback behavior."),
          pending(
              "node-to-node-message",
              "Node-to-node messages",
              SEND_N2NTM_PATH,
              null,
              null,
              "No complete Web Shell or app replacement is established yet.",
              true),
          retained(
              "chat",
              "Chat and forums",
              CHAT_PATH,
              "On-network chat/forum discovery remains a retained legacy browse-adjacent page."),
          retained(
              "translation",
              "Translation",
              TranslationPaths.TOADLET_URL,
              "Translation management has no shell-native replacement in this PR."),
          retained(
              "help",
              "Help",
              HELP_PATH,
              "The simple help page remains a retained legacy support page."),
          retained(
              "content-filter",
              "Content filter",
              LegacyContentFilterSupport.CONTENT_FILTER_PATH,
              "FProxy content filtering remains part of retained browse safety tooling."),
          infrastructure(
              "directory-browser",
              "Local directory browser",
              LocalDirectoryToadlet.basePath(),
              "Supports legacy config, download, and insert forms."),
          infrastructure(
              "symlink-resolver",
              "Toadlet symlink resolver",
              "/sl/",
              "Maintains legacy alias compatibility."));

  private static final Map<String, LegacyAdminSurface> SURFACES_BY_ID = surfacesById();
  private static final List<LegacyAdminSurface> MATCH_SURFACES =
      SURFACES.stream()
          .sorted(
              Comparator.comparingInt((LegacyAdminSurface surface) -> surface.legacyPath().length())
                  .reversed())
          .toList();

  private LegacyAdminRetirementRegistry() {}

  /**
   * Returns all known admin-surface retirement metadata in stable encounter order.
   *
   * <p>The returned list includes primary-replaced pages, retained pages, pending migration gaps,
   * and infrastructure routes. Encounter order is the documentation order used by diagnostics and
   * shell fallback views. Consumers must filter by state or inclusion flags rather than assuming
   * every entry is user-facing.
   *
   * @return immutable list of registry entries in the maintained retirement-map order
   */
  public static List<LegacyAdminSurface> surfaces() {
    return SURFACES;
  }

  /**
   * Returns surfaces included in process-local usage diagnostics.
   *
   * <p>The diagnostics list excludes infrastructure bridges and helpers such as static assets,
   * Platform API, Web Shell, and app UI mounts. It does include replaced, retained, and pending
   * user-facing surfaces so later retirement PRs can see which fallback pages are still used after
   * process start.
   *
   * @return immutable list of surfaces that should appear in diagnostics output
   */
  public static List<LegacyAdminSurface> diagnosticSurfaces() {
    return SURFACES.stream().filter(LegacyAdminSurface::includeInUsageDiagnostics).toList();
  }

  /**
   * Returns retained or pending legacy pages that the Web Shell may show as fallback links.
   *
   * <p>Primary-replaced pages are deliberately excluded because their normal entry points should be
   * Web Shell panels or first-party apps. This list is for routes that remain retained or whose
   * replacement is not complete enough to hide the legacy entry point.
   *
   * @return immutable list of Web Shell fallback-link surfaces in display order
   */
  public static List<LegacyAdminSurface> webShellFallbackSurfaces() {
    return SURFACES.stream().filter(LegacyAdminSurface::includeInWebShellFallbackLinks).toList();
  }

  /**
   * Indicates whether a legacy route should still be promoted in the legacy navigation menus.
   *
   * <p>Primary-replaced routes remain registered as direct fallback and debug URLs, but normal
   * navigation should lead operators to the Web Shell or first-party app replacement. Unknown
   * routes are treated as visible because they are outside this retirement map and may belong to
   * retained browse-owned surfaces.
   *
   * @param legacyPath legacy HTTP route prefix that would be used for a menu entry
   * @return {@code false} for known {@link LegacyAdminRetirementState#PRIMARY_REPLACED} surfaces;
   *     {@code true} for retained, pending, infrastructure, and unknown routes
   */
  public static boolean shouldPromoteInLegacyNavigation(String legacyPath) {
    return findByLegacyPath(legacyPath)
        .map(surface -> surface.state() != LegacyAdminRetirementState.PRIMARY_REPLACED)
        .orElse(true);
  }

  /**
   * Resolves one surface by stable id.
   *
   * <p>Ids are stable machine-readable names used by diagnostics and tests. This method does not
   * normalize input; callers should pass the exact registry id and handle an empty result for
   * unknown or {@code null} values.
   *
   * @param id registry id to look up, usually a stable diagnostics surface id
   * @return matching surface when present, otherwise an empty optional
   */
  public static Optional<LegacyAdminSurface> findById(String id) {
    return Optional.ofNullable(SURFACES_BY_ID.get(id));
  }

  /**
   * Resolves one surface by stable id and fails if the id is missing.
   *
   * <p>This is intended for tests and wiring code that must fail fast when a registry entry was
   * renamed or removed. Request-handling paths should normally use {@link #findById(String)} or
   * {@link #findByLegacyPath(String)} so unknown input can be ignored safely.
   *
   * @param id registry id to look up, using the exact value declared in the map
   * @return matching surface for the supplied registry id
   * @throws IllegalArgumentException if the id is unknown or not present in the map
   */
  public static LegacyAdminSurface require(String id) {
    return findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown surface: " + id));
  }

  /**
   * Resolves the best matching surface for a request path using longest-prefix matching.
   *
   * <p>The matcher expects a local path with no query string, for example {@code /downloads/} or
   * {@code /config/node}. Longest-prefix ordering prevents broad helper routes from masking more
   * specific surfaces. The method returns empty for blank, {@code null}, unregistered, or
   * browse-only paths, which lets usage diagnostics ignore traffic outside the retirement map.
   *
   * @param requestPath local same-origin request path without query string or fragment
   * @return matching surface when the path belongs to a registered legacy-admin surface
   */
  public static Optional<LegacyAdminSurface> findByLegacyPath(String requestPath) {
    if (requestPath == null || requestPath.isBlank()) {
      return Optional.empty();
    }
    for (LegacyAdminSurface surface : MATCH_SURFACES) {
      String legacyPath = surface.legacyPath();
      if (requestPath.equals(legacyPath) || requestPath.startsWith(legacyPath)) {
        return Optional.of(surface);
      }
    }
    return Optional.empty();
  }

  private static Map<String, LegacyAdminSurface> surfacesById() {
    LinkedHashMap<String, LegacyAdminSurface> byId =
        LinkedHashMap.newLinkedHashMap(SURFACES.size());
    for (LegacyAdminSurface surface : SURFACES) {
      LegacyAdminSurface previous = byId.put(surface.id(), surface);
      if (previous != null) {
        throw new IllegalStateException("Duplicate legacy-admin surface id: " + surface.id());
      }
    }
    return Map.copyOf(byId);
  }

  private static String localPath(String segment) {
    return "/" + segment + "/";
  }

  private static LegacyAdminSurface replaced(
      String id,
      String title,
      String legacyPath,
      String replacementUrl,
      String replacementLabel,
      String notes) {
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        LegacyAdminRetirementState.PRIMARY_REPLACED,
        replacementUrl,
        replacementLabel,
        notes,
        true,
        false);
  }

  private static LegacyAdminSurface pendingWizard(
      String id, String title, String legacyPath, String notes) {
    return pending(
        id, title, legacyPath, SHELL_WIZARD_URL, "Web Shell first-time setup", notes, false);
  }

  private static LegacyAdminSurface pending(
      String id,
      String title,
      String legacyPath,
      String replacementUrl,
      String replacementLabel,
      String notes,
      boolean includeInWebShellFallbackLinks) {
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        LegacyAdminRetirementState.PENDING,
        replacementUrl,
        replacementLabel,
        notes,
        true,
        includeInWebShellFallbackLinks);
  }

  private static LegacyAdminSurface retained(
      String id, String title, String legacyPath, String notes) {
    return new LegacyAdminSurface(
        id, title, legacyPath, LegacyAdminRetirementState.RETAINED, null, null, notes, true, true);
  }

  private static LegacyAdminSurface infrastructure(
      String id, String title, String legacyPath, String notes) {
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        LegacyAdminRetirementState.INFRASTRUCTURE,
        null,
        null,
        notes,
        false,
        false);
  }
}
