package network.crypta.clients.http;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
 * <p>The list gives notices, Web Shell fallback links, removal decisions, and usage diagnostics one
 * shared source of truth. Callers should treat the returned entries as policy metadata, not route
 * registrations. The actual toadlet registration still lives in the legacy HTTP container, and
 * app/UI replacements remain owned by their platform modules.
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
  private static final int NO_REMOVAL_WAVE = 0;
  private static final int REMOVAL_WAVE_1 = 1;
  private static final int REMOVAL_WAVE_2 = 2;
  private static final int REMOVAL_WAVE_3 = 3;
  private static final int REMOVAL_WAVE_4 = 4;
  static final int REMOVAL_WAVE_5 = 5;
  private static final String REMOVED_BY_DEFAULT_SINCE_WAVE_1 = "phase-6-pr-8";
  private static final String REMOVED_BY_DEFAULT_SINCE_WAVE_2 = "phase-7-pr-230";
  private static final String REMOVED_BY_DEFAULT_SINCE_WAVE_3 = "phase-8-pr-244";
  private static final String REMOVED_BY_DEFAULT_SINCE_WAVE_4 = "phase-9-pr-254";
  static final String REMOVED_BY_DEFAULT_SINCE_WAVE_5 = "phase-10-pr-265";
  private static final String FALLBACK_POLICY_NONE = "none";
  private static final String FALLBACK_POLICY_MUTATING_LEGACY = "mutating-legacy-fallback";
  private static final String FALLBACK_POLICY_SUPPORT_EMERGENCY = "support-emergency-fallback";
  private static final String FALLBACK_POLICY_RETAINED = "retained";
  private static final String FALLBACK_POLICY_PENDING = "pending";
  private static final String FALLBACK_POLICY_INFRASTRUCTURE = "infrastructure";

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
          wave2Redirect(
              "alerts",
              "Alerts",
              "/alerts/",
              SHELL_ALERTS_URL,
              "Web Shell alerts",
              "Web Shell lists and dismisses individual alerts through Platform API v1; bulk"
                  + " legacy alert actions remain fallback until API coverage is complete.",
              canonicalMutationFallback()),
          wave1Redirect(
              "queue-downloads",
              "Download queue",
              QueueToadlet.PATH_DOWNLOADS,
              QUEUE_MANAGER_URL,
              "Queue Manager app",
              "Queue Manager and the Web Shell queue panel are the primary transfer views.",
              scopedCoveredRemoval(
                  LegacyAdminRemovalScope.EXPLICIT_CHILDREN,
                  queueHelperPaths(QueueToadlet.PATH_DOWNLOADS),
                  REMOVAL_WAVE_2)),
          wave1Redirect(
              "queue-uploads",
              "Upload queue",
              QueueToadlet.PATH_UPLOADS,
              QUEUE_MANAGER_URL,
              "Queue Manager app",
              "Queue Manager and Publisher cover upload-queue monitoring and insert creation.",
              scopedCoveredRemoval(
                  LegacyAdminRemovalScope.EXPLICIT_CHILDREN,
                  queueHelperPaths(QueueToadlet.PATH_UPLOADS),
                  REMOVAL_WAVE_2)),
          wave1Redirect(
              "file-insert",
              "File insert wizard",
              FileInsertWizardToadlet.PATH,
              PUBLISHER_URL,
              "Publisher app",
              "Publisher is the primary first-party UI for local file and directory inserts."),
          wave1Redirect(
              "local-file-insert",
              "Local upload file browser",
              LocalFileInsertToadlet.INSERT_BROWSE_PATH,
              PUBLISHER_URL,
              "Publisher app",
              "Publisher owns the primary local insert flow; helper subpaths remain untouched."),
          wave1Redirect(
              "friends",
              "Friends",
              LegacyHttpPaths.FRIENDS_PATH,
              SHELL_PEERS_URL,
              WEB_SHELL_PEER_CONTROL_LABEL,
              "Web Shell peer control covers darknet peer roster and mutations."),
          wave1Redirect(
              "add-friend",
              "Add friend",
              DarknetAddRefToadlet.PATH,
              SHELL_PEERS_URL,
              WEB_SHELL_PEER_CONTROL_LABEL,
              "Web Shell peer add handles the primary noderef import flow."),
          wave1Redirect(
              "strangers",
              "Strangers",
              "/strangers/",
              SHELL_PEERS_URL,
              WEB_SHELL_PEER_CONTROL_LABEL,
              "Opennet peer visibility belongs with the shell peer control plane."),
          wave1Redirect(
              "connectivity",
              "Connectivity",
              ConnectivityToadlet.CONNECTIVITY_PATH,
              SHELL_CONNECTIVITY_URL,
              "Web Shell connectivity",
              "Web Shell shows connectivity snapshots through Platform API v1."),
          wave2Redirect(
              "config",
              "Configuration",
              LegacyHttpPaths.CONFIG_PATH,
              SHELL_CONFIG_URL,
              "Web Shell config",
              "Web Shell config and Platform API v1 own config reads, override writes, and"
                  + " persistence actions.",
              scopedCoveredRemoval(
                  LegacyAdminRemovalScope.PREFIX_FAMILY, List.of(), REMOVAL_WAVE_2)),
          securityLevelsWave3Redirect(),
          wave2Redirect(
              "core-update",
              "Core update actions",
              CORE_UPDATE_PATH,
              SHELL_UPDATES_URL,
              "Web Shell updates",
              "Web Shell owns updater status and the manual download trigger; installer and"
                  + " package-store handoff actions remain legacy fallback.",
              canonicalMutationFallback()),
          wave2Redirect(
              "statistics",
              "Statistics",
              StatisticsToadlet.TOADLET_URL,
              SHELL_DIAGNOSTICS_URL,
              "Web Shell diagnostics",
              "Diagnostics is the primary shell-native operator status surface.",
              scopedMutationFallback(
                  LegacyAdminRemovalScope.EXPLICIT_CHILDREN,
                  List.of(StatisticsToadlet.TOADLET_URL + "requesters.html"),
                  REMOVAL_WAVE_2)),
          diagnosticWave4Redirect(),
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
  private static final FinalSurfacePolicy FINAL_SURFACE_POLICY = buildFinalSurfacePolicy();

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
   * user-facing surfaces so later retirement PRs can see which legacy renders, replacement
   * responses, and blocked mutations are still observed after process start.
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
   * Returns the surfaces removed by default in a specific execution wave.
   *
   * <p>Removal waves are an execution policy and must not be inferred from retirement state alone.
   * This method is primarily used by tests and release-certification evidence so future waves can
   * prove the active route set without duplicating path lists outside the registry.
   *
   * @param removalWave removal wave number to select
   * @return immutable list of surfaces whose current removal metadata belongs to the wave
   */
  public static List<LegacyAdminSurface> removalWaveSurfaces(int removalWave) {
    return SURFACES.stream().filter(surface -> surface.removalWave() == removalWave).toList();
  }

  /**
   * Returns surfaces whose path-matching scope was expanded in a specific wave.
   *
   * <p>Some later waves can safely expand helper paths for a surface that was already removed by an
   * earlier canonical-route wave. Keeping that metadata separate preserves the original {@link
   * #removalWaveSurfaces(int)} evidence while making helper-route expansion reviewable.
   *
   * @param removalWave removal wave number to select
   * @return immutable list of surfaces whose scope expansion metadata belongs to the wave
   */
  public static List<LegacyAdminSurface> scopeExpandedInWaveSurfaces(int removalWave) {
    return SURFACES.stream()
        .filter(surface -> surface.scopeExpandedInWave() == removalWave)
        .toList();
  }

  /**
   * Returns the production-beta final legacy-admin surface policy.
   *
   * <p>Wave 5 is a readiness and classification wave. It does not promote additional routes into
   * removal-by-default unless a route has a proven complete replacement. The policy therefore
   * records the final maintenance-only shape: previous removal waves, explicit fallback surfaces,
   * retained browse and browse-safety routes, pending gaps, and infrastructure entries.
   *
   * @return immutable final-surface policy snapshot for release certification and tests
   */
  static FinalSurfacePolicy finalSurfacePolicy() {
    return FINAL_SURFACE_POLICY;
  }

  /**
   * Indicates whether a legacy route should still be promoted in the legacy navigation menus.
   *
   * <p>Primary-replaced routes are not promoted as normal navigation targets. Some still render as
   * later-wave legacy fallback pages, while wave-1 routes return replacement responses. Unknown
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

  enum FinalSurfaceCategory {
    REMOVED_BY_DEFAULT_ADMIN,
    SUPPORT_EMERGENCY_FALLBACK,
    STARTUP_RECOVERY_FALLBACK,
    RETAINED_BROWSE_SURFACE,
    RETAINED_BROWSE_SAFETY,
    RETAINED_NON_ADMIN_SUPPORT,
    PENDING_MIGRATION_GAP,
    INFRASTRUCTURE
  }

  record FinalSurfaceEntry(
      String id,
      String title,
      String routePattern,
      List<FinalSurfaceCategory> categories,
      LegacyAdminRemovalMode removalMode,
      int removalWave,
      String replacementUrl,
      String fallbackPolicy,
      String rationale) {
    FinalSurfaceEntry {
      requireText(id, "id");
      requireText(title, "title");
      requireText(routePattern, "routePattern");
      categories = List.copyOf(categories);
      if (categories.isEmpty()) {
        throw new IllegalArgumentException("categories must not be empty");
      }
      categories.forEach(category -> Objects.requireNonNull(category, "category"));
      Objects.requireNonNull(removalMode, "removalMode");
      if (removalWave < 0) {
        throw new IllegalArgumentException("removalWave must not be negative");
      }
      if (replacementUrl != null) {
        requireSameOriginPath(replacementUrl);
      }
      requireText(fallbackPolicy, "fallbackPolicy");
      requireText(rationale, "rationale");
    }

    boolean belongsTo(FinalSurfaceCategory category) {
      return categories.contains(category);
    }
  }

  record FinalSurfacePolicy(
      String evidenceId, int readinessWave, String since, List<FinalSurfaceEntry> entries) {
    FinalSurfacePolicy {
      requireText(evidenceId, "evidenceId");
      if (readinessWave <= NO_REMOVAL_WAVE) {
        throw new IllegalArgumentException("readinessWave must be positive");
      }
      requireText(since, "since");
      entries = List.copyOf(entries);
      if (entries.isEmpty()) {
        throw new IllegalArgumentException("entries must not be empty");
      }
    }

    List<FinalSurfaceEntry> entriesInCategory(FinalSurfaceCategory category) {
      return entries.stream().filter(entry -> entry.belongsTo(category)).toList();
    }

    List<FinalSurfaceEntry> waveFivePromotedEntries() {
      return entries.stream().filter(entry -> entry.removalWave() == readinessWave).toList();
    }
  }

  private static FinalSurfacePolicy buildFinalSurfacePolicy() {
    return new FinalSurfacePolicy(
        "legacy-admin.final-admin-surface",
        REMOVAL_WAVE_5,
        REMOVED_BY_DEFAULT_SINCE_WAVE_5,
        List.of(
            surfaceFinalSurface(
                "queue-downloads",
                "Daily transfer monitoring is app-first through Queue Manager.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "queue-uploads",
                "Daily upload monitoring is app-first through Queue Manager and Publisher.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "file-insert",
                "Daily file insertion is app-first through Publisher.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "local-file-insert",
                "Daily local insert selection is app-first through Publisher.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "friends",
                "Daily peer roster work is Web Shell peer control first.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "add-friend",
                "Daily peer-add work is Web Shell peer control first.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "strangers",
                "Daily opennet peer visibility is Web Shell peer control first.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "connectivity",
                "Daily connectivity inspection is Web Shell first.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "alerts",
                "Safe reads are Web Shell first; bulk legacy mutations remain a pending gap.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN,
                FinalSurfaceCategory.PENDING_MIGRATION_GAP),
            surfaceFinalSurface(
                "config",
                "Daily configuration reads and covered writes are Web Shell first.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "security-levels",
                "Safe reads are Web Shell first while recovery and high-security forms remain"
                    + " explicit fallback.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN,
                FinalSurfaceCategory.STARTUP_RECOVERY_FALLBACK),
            surfaceFinalSurface(
                "core-update",
                "Safe reads are Web Shell first; installer handoff remains a pending support gap.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN,
                FinalSurfaceCategory.PENDING_MIGRATION_GAP),
            surfaceFinalSurface(
                "statistics",
                "Daily status inspection is Web Shell diagnostics first.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN),
            surfaceFinalSurface(
                "diagnostic",
                "Safe reads are Web Shell first while the exact plaintext export marker remains"
                    + " support fallback.",
                FinalSurfaceCategory.REMOVED_BY_DEFAULT_ADMIN,
                FinalSurfaceCategory.SUPPORT_EMERGENCY_FALLBACK),
            surfaceFinalSurface(
                "first-time-wizard",
                "Startup routing still uses the legacy wizard gate until a complete replacement is"
                    + " proven.",
                FinalSurfaceCategory.STARTUP_RECOVERY_FALLBACK,
                FinalSurfaceCategory.PENDING_MIGRATION_GAP),
            surfaceFinalSurface(
                "first-time-wizard-js",
                "The JavaScript wizard remains part of first-run fallback behavior.",
                FinalSurfaceCategory.STARTUP_RECOVERY_FALLBACK,
                FinalSurfaceCategory.PENDING_MIGRATION_GAP),
            surfaceFinalSurface(
                "node-to-node-message",
                "Node-to-node messages have no complete Web Shell or app replacement yet.",
                FinalSurfaceCategory.PENDING_MIGRATION_GAP),
            surfaceFinalSurface(
                "chat",
                "Chat/forum discovery remains retained as browse-adjacent functionality.",
                FinalSurfaceCategory.RETAINED_BROWSE_SURFACE),
            surfaceFinalSurface(
                "translation",
                "Translation remains retained as a non-admin support page.",
                FinalSurfaceCategory.RETAINED_NON_ADMIN_SUPPORT),
            surfaceFinalSurface(
                "help",
                "Help remains retained as a non-admin support page.",
                FinalSurfaceCategory.RETAINED_NON_ADMIN_SUPPORT),
            surfaceFinalSurface(
                "content-filter",
                "The content filter remains retained browse safety tooling.",
                FinalSurfaceCategory.RETAINED_BROWSE_SAFETY),
            retainedBrowseFinalSurface(
                "fproxy-browse-root",
                "FProxy browse root",
                "/",
                "Browse root remains owned by the browse registrar and is outside admin"
                    + " retirement matching."),
            retainedBrowseFinalSurface(
                "fproxy-key-content-rendering",
                "FProxy key and content rendering",
                "/{CHK,SSK,USK,KSK}@...",
                "Key/content rendering remains retained FProxy behavior and is not an admin"
                    + " removal target."),
            surfaceFinalSurface(
                "web-shell",
                "Web Shell bridge is replacement infrastructure, not retired legacy admin.",
                FinalSurfaceCategory.INFRASTRUCTURE),
            surfaceFinalSurface(
                "platform-api",
                "Platform API bridge is replacement infrastructure, not retired legacy admin.",
                FinalSurfaceCategory.INFRASTRUCTURE),
            surfaceFinalSurface(
                "app-ui",
                "App-owned UI bridge is replacement infrastructure, not retired legacy admin.",
                FinalSurfaceCategory.INFRASTRUCTURE),
            surfaceFinalSurface(
                "static-assets",
                "Static assets support retained fallback pages.",
                FinalSurfaceCategory.INFRASTRUCTURE),
            surfaceFinalSurface(
                "directory-browser",
                "Directory browser remains helper infrastructure for retained fallback pages.",
                FinalSurfaceCategory.INFRASTRUCTURE),
            surfaceFinalSurface(
                "symlink-resolver",
                "Symlink resolver remains helper infrastructure for legacy aliases.",
                FinalSurfaceCategory.INFRASTRUCTURE)));
  }

  private static FinalSurfaceEntry surfaceFinalSurface(
      String id, String rationale, FinalSurfaceCategory... categories) {
    LegacyAdminSurface surface = require(id);
    return new FinalSurfaceEntry(
        surface.id(),
        surface.title(),
        surface.legacyPath(),
        List.of(categories),
        surface.removalMode(),
        surface.removalWave(),
        surface.replacementUrl(),
        surface.fallbackPolicy(),
        rationale);
  }

  private static FinalSurfaceEntry retainedBrowseFinalSurface(
      String id, String title, String routePattern, String rationale) {
    return new FinalSurfaceEntry(
        id,
        title,
        routePattern,
        List.of(FinalSurfaceCategory.RETAINED_BROWSE_SURFACE),
        LegacyAdminRemovalMode.RETAINED,
        NO_REMOVAL_WAVE,
        null,
        FALLBACK_POLICY_RETAINED,
        rationale);
  }

  private static String localPath(String segment) {
    return "/" + segment + "/";
  }

  private static void requireText(String value, String label) {
    Objects.requireNonNull(value, label);
    if (value.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
  }

  private static void requireSameOriginPath(String value) {
    requireText(value, "replacementUrl");
    if (!value.startsWith("/") || value.startsWith("//")) {
      throw new IllegalArgumentException("replacementUrl must be a same-origin absolute path");
    }
  }

  private static List<String> queueHelperPaths(String queuePath) {
    return List.of(queuePath + "countRequests.html", queuePath + "listKeys.txt");
  }

  private enum MutatingRequestReplacement {
    COVERED(true, FALLBACK_POLICY_NONE),
    PARTIAL_LEGACY_FALLBACK(false, FALLBACK_POLICY_MUTATING_LEGACY);

    private final boolean blockLegacyRequests;
    private final String fallbackPolicy;

    MutatingRequestReplacement(boolean blockLegacyRequests, String fallbackPolicy) {
      this.blockLegacyRequests = blockLegacyRequests;
      this.fallbackPolicy = fallbackPolicy;
    }
  }

  private record RemovalExecution(
      LegacyAdminRemovalScope scope,
      List<String> explicitChildPaths,
      int scopeExpandedInWave,
      MutatingRequestReplacement mutatingRequestReplacement) {}

  private static RemovalExecution canonicalCoveredRemoval() {
    return scopedCoveredRemoval(
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS, List.of(), NO_REMOVAL_WAVE);
  }

  private static RemovalExecution canonicalMutationFallback() {
    return scopedMutationFallback(
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS, List.of(), NO_REMOVAL_WAVE);
  }

  private static RemovalExecution scopedCoveredRemoval(
      LegacyAdminRemovalScope scope, List<String> explicitChildPaths, int scopeExpandedInWave) {
    return new RemovalExecution(
        scope, explicitChildPaths, scopeExpandedInWave, MutatingRequestReplacement.COVERED);
  }

  private static RemovalExecution scopedMutationFallback(
      LegacyAdminRemovalScope scope, List<String> explicitChildPaths, int scopeExpandedInWave) {
    return new RemovalExecution(
        scope,
        explicitChildPaths,
        scopeExpandedInWave,
        MutatingRequestReplacement.PARTIAL_LEGACY_FALLBACK);
  }

  private static LegacyAdminSurface diagnosticWave4Redirect() {
    return new LegacyAdminSurface(
        "diagnostic",
        "Diagnostic report",
        DiagnosticToadlet.TOADLET_URL,
        LegacyAdminRetirementState.PRIMARY_REPLACED,
        SHELL_DIAGNOSTICS_URL,
        "Web Shell diagnostics",
        "Web Shell diagnostics is the primary status surface; the legacy plain-text export remains"
            + " available only through explicit support or emergency fallback.",
        LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT,
        REMOVAL_WAVE_4,
        REMOVED_BY_DEFAULT_SINCE_WAVE_4,
        FALLBACK_POLICY_SUPPORT_EMERGENCY,
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
        NO_REMOVAL_WAVE,
        List.of(),
        true,
        true,
        false);
  }

  private static LegacyAdminSurface wave1Redirect(
      String id,
      String title,
      String legacyPath,
      String replacementUrl,
      String replacementLabel,
      String notes) {
    return wave1Redirect(
        id, title, legacyPath, replacementUrl, replacementLabel, notes, canonicalCoveredRemoval());
  }

  private static LegacyAdminSurface wave1Redirect(
      String id,
      String title,
      String legacyPath,
      String replacementUrl,
      String replacementLabel,
      String notes,
      RemovalExecution removalExecution) {
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        LegacyAdminRetirementState.PRIMARY_REPLACED,
        replacementUrl,
        replacementLabel,
        notes,
        LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT,
        REMOVAL_WAVE_1,
        REMOVED_BY_DEFAULT_SINCE_WAVE_1,
        FALLBACK_POLICY_NONE,
        removalExecution.scope(),
        removalExecution.scopeExpandedInWave(),
        removalExecution.explicitChildPaths(),
        true,
        true,
        false);
  }

  private static LegacyAdminSurface wave2Redirect(
      String id,
      String title,
      String legacyPath,
      String replacementUrl,
      String replacementLabel,
      String notes,
      RemovalExecution removalExecution) {
    MutatingRequestReplacement mutatingReplacement = removalExecution.mutatingRequestReplacement();
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        LegacyAdminRetirementState.PRIMARY_REPLACED,
        replacementUrl,
        replacementLabel,
        notes,
        LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT,
        REMOVAL_WAVE_2,
        REMOVED_BY_DEFAULT_SINCE_WAVE_2,
        mutatingReplacement.fallbackPolicy,
        removalExecution.scope(),
        removalExecution.scopeExpandedInWave(),
        removalExecution.explicitChildPaths(),
        mutatingReplacement.blockLegacyRequests,
        true,
        false);
  }

  private static LegacyAdminSurface securityLevelsWave3Redirect() {
    RemovalExecution removalExecution = canonicalMutationFallback();
    MutatingRequestReplacement mutatingReplacement = removalExecution.mutatingRequestReplacement();
    return new LegacyAdminSurface(
        "security-levels",
        "Security levels",
        SecurityLevelsToadlet.PATH,
        LegacyAdminRetirementState.PRIMARY_REPLACED,
        SHELL_SECURITY_URL,
        "Web Shell security",
        "Web Shell owns the primary security-level view and common mutations; master-password"
            + " and high-physical-security flows remain legacy fallback.",
        LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT,
        REMOVAL_WAVE_3,
        REMOVED_BY_DEFAULT_SINCE_WAVE_3,
        mutatingReplacement.fallbackPolicy,
        removalExecution.scope(),
        removalExecution.scopeExpandedInWave(),
        removalExecution.explicitChildPaths(),
        mutatingReplacement.blockLegacyRequests,
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
        LegacyAdminRemovalMode.PENDING,
        NO_REMOVAL_WAVE,
        null,
        FALLBACK_POLICY_PENDING,
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
        NO_REMOVAL_WAVE,
        List.of(),
        true,
        true,
        includeInWebShellFallbackLinks);
  }

  private static LegacyAdminSurface retained(
      String id, String title, String legacyPath, String notes) {
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        LegacyAdminRetirementState.RETAINED,
        null,
        null,
        notes,
        LegacyAdminRemovalMode.RETAINED,
        NO_REMOVAL_WAVE,
        null,
        FALLBACK_POLICY_RETAINED,
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
        NO_REMOVAL_WAVE,
        List.of(),
        true,
        true,
        true);
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
        LegacyAdminRemovalMode.INFRASTRUCTURE,
        NO_REMOVAL_WAVE,
        null,
        FALLBACK_POLICY_INFRASTRUCTURE,
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
        NO_REMOVAL_WAVE,
        List.of(),
        true,
        false,
        false);
  }
}
