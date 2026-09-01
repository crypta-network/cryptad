package network.crypta.platform.api.appupdates;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.api.appdata.AppDataNamespaceMetadata;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.appdist.AppDataMigrationStep;
import network.crypta.platform.appdist.AppDataNamespaceSchema;
import network.crypta.platform.appdist.AppDataSchemaContract;
import network.crypta.platform.appdist.AppSandboxMode;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Builds deterministic durable app-data migration plans for catalog updates.
 *
 * <p>This planner owns schema comparison and migration-path selection. It deliberately does not
 * stage bundles, execute app-owned migration commands, mutate durable data, or manage rollback;
 * those lifecycle responsibilities remain in {@link AppUpdateService}. Keeping path construction
 * separate lets the update service coordinate policy and host mutations without depending directly
 * on every app-data schema representation.
 *
 * <p>Paths prefer fewer rollback-incompatible steps, then fewer stop-required steps, then fewer
 * total steps, and finally stable step identifiers. A missing or downgrade path fails closed with
 * the same public blocker used by the update lifecycle.
 */
final class AppUpdateMigrationPlanner {
  /** Stable failure code used when no valid schema migration path exists. */
  static final String ERROR_MISSING_MIGRATION = "app_data_migration_missing";

  /** Stable failure code used when durable app-data metadata cannot be inspected. */
  private static final String ERROR_DATA_STORE_UNAVAILABLE = "app_data_store_unavailable";

  /** Durable app-data authority consulted while planning namespace migrations. */
  private final AppDataService appDataService;

  /**
   * Creates a planner backed by the node's durable app-data service.
   *
   * @param appDataService app-scoped metadata service, or {@code null} when unavailable
   */
  AppUpdateMigrationPlanner(AppDataService appDataService) {
    this.appDataService = appDataService;
  }

  /**
   * Builds a migration plan without retaining a planner instance.
   *
   * @param appDataService app-scoped metadata service, or {@code null} when unavailable
   * @param appId installed application whose namespaces are evaluated
   * @param installedManifest verified currently installed manifest
   * @param targetManifest verified retained target manifest
   * @return deterministic migration plan for the exact manifest pair
   */
  static AppDataMigrationPlan buildPlan(
      AppDataService appDataService,
      String appId,
      AppManifest installedManifest,
      AppManifest targetManifest) {
    return new AppUpdateMigrationPlanner(appDataService)
        .buildPlan(appId, installedManifest, targetManifest);
  }

  /**
   * Builds the deterministic schema migration plan for one verified app update.
   *
   * @param appId installed app whose durable namespaces are being evaluated
   * @param installedManifest verified manifest for the currently installed bundle
   * @param targetManifest verified manifest for the retained target bundle
   * @return ready, unnecessary, or blocked migration plan for the exact manifests
   */
  AppDataMigrationPlan buildPlan(
      String appId, AppManifest installedManifest, AppManifest targetManifest) {
    Objects.requireNonNull(appId, "appId");
    AppDataSchemaContract installedContract =
        Objects.requireNonNull(installedManifest, "installedManifest").dataSchemaContract();
    AppDataSchemaContract targetContract =
        Objects.requireNonNull(targetManifest, "targetManifest").dataSchemaContract();
    if (!targetContract.declared()) {
      return AppDataMigrationPlan.notRequired(
          installedContract.currentSchemaVersion(), targetContract.currentSchemaVersion());
    }
    if (appDataService == null) {
      return AppDataMigrationPlan.blocked(
          AppDataMigrationPlan.STATUS_FAILED,
          installedContract.currentSchemaVersion(),
          targetContract.currentSchemaVersion(),
          List.of(),
          false,
          ERROR_DATA_STORE_UNAVAILABLE);
    }
    List<AppDataNamespaceMetadata> currentNamespaces =
        appDataService.listNamespaceMetadataForUpdate(appId);
    if (currentNamespaces.isEmpty()) {
      return AppDataMigrationPlan.notRequired(
          installedContract.currentSchemaVersion(), targetContract.currentSchemaVersion());
    }
    Map<String, AppDataNamespaceMetadata> currentMetadata = namespaceMetadataMap(currentNamespaces);
    List<String> migrationNamespaces = migrationNamespaces(targetContract, currentMetadata);
    ArrayList<AppDataMigrationPlan.NamespaceStep> steps = new ArrayList<>();
    for (String namespace : migrationNamespaces) {
      if (currentMetadata.containsKey(namespace)) {
        Optional<AppDataMigrationPlan> blocker =
            appendNamespaceMigrationSteps(
                namespace, installedContract, targetContract, currentMetadata, steps);
        if (blocker.isPresent()) {
          return blocker.orElseThrow();
        }
      }
    }
    if (steps.isEmpty()) {
      return AppDataMigrationPlan.notRequired(
          installedContract.currentSchemaVersion(), targetContract.currentSchemaVersion());
    }
    return AppDataMigrationPlan.ready(
        installedContract.currentSchemaVersion(), targetContract.currentSchemaVersion(), steps);
  }

  /**
   * Determines whether the migration runner can execute a plan under the target app sandbox.
   *
   * <p>A plan that performs no migration needs no runner. A target that does not require sandbox
   * enforcement also remains eligible. When sandbox enforcement is required, the explicit
   * development-compatible {@link AppSandboxMode#NONE} mode is the only mode that does not require
   * an external sandbox provider at this planning boundary.
   *
   * @param migrationPlan deterministic migration plan selected for the target bundle
   * @param targetManifest verified manifest copied from the retained target bundle
   * @return {@code true} when the migration may execute with the target sandbox contract
   */
  static boolean migrationExecutionAllowed(
      AppDataMigrationPlan migrationPlan, AppManifest targetManifest) {
    return !migrationPlan.required()
        || !targetManifest.sandboxPolicy().required()
        || targetManifest.sandboxPolicy().mode() == AppSandboxMode.NONE;
  }

  /**
   * Appends the best migration path for one namespace or returns its blocking plan.
   *
   * @param namespace durable namespace being advanced
   * @param installedContract installed bundle's schema contract
   * @param targetContract retained target bundle's schema contract
   * @param currentMetadata current host-owned namespace metadata
   * @param steps ordered output list receiving selected migration steps
   * @return blocking plan when no valid forward path exists; otherwise empty
   */
  private static Optional<AppDataMigrationPlan> appendNamespaceMigrationSteps(
      String namespace,
      AppDataSchemaContract installedContract,
      AppDataSchemaContract targetContract,
      Map<String, AppDataNamespaceMetadata> currentMetadata,
      List<AppDataMigrationPlan.NamespaceStep> steps) {
    int currentVersion = currentSchemaVersion(namespace, installedContract, currentMetadata);
    int targetVersion = targetSchemaVersion(namespace, targetContract, currentVersion);
    if (targetVersion < currentVersion) {
      return Optional.of(
          AppDataMigrationPlan.blocked(
              AppDataMigrationPlan.STATUS_MISSING_MIGRATION,
              installedContract.currentSchemaVersion(),
              targetContract.currentSchemaVersion(),
              steps,
              false,
              ERROR_MISSING_MIGRATION));
    }
    if (targetVersion == currentVersion) {
      return Optional.empty();
    }
    List<AppDataMigrationPlan.NamespaceStep> path =
        migrationPath(namespace, currentVersion, targetVersion, targetContract.migrations());
    if (path.isEmpty()) {
      return Optional.of(
          AppDataMigrationPlan.blocked(
              AppDataMigrationPlan.STATUS_MISSING_MIGRATION,
              currentVersion,
              targetVersion,
              steps,
              false,
              ERROR_MISSING_MIGRATION));
    }
    steps.addAll(path);
    return Optional.empty();
  }

  /**
   * Indexes current namespace metadata by its normalized namespace identifier.
   *
   * @param namespaces current host-owned namespace metadata
   * @return insertion-ordered metadata index
   */
  private static Map<String, AppDataNamespaceMetadata> namespaceMetadataMap(
      List<AppDataNamespaceMetadata> namespaces) {
    LinkedHashMap<String, AppDataNamespaceMetadata> byNamespace = new LinkedHashMap<>();
    for (AppDataNamespaceMetadata namespace : namespaces) {
      byNamespace.put(namespace.namespace(), namespace);
    }
    return byNamespace;
  }

  /**
   * Selects the namespaces covered by the target schema contract.
   *
   * @param targetContract target bundle's schema contract
   * @param currentMetadata current host-owned namespace metadata
   * @return deterministic namespaces that require comparison
   */
  private static List<String> migrationNamespaces(
      AppDataSchemaContract targetContract, Map<String, AppDataNamespaceMetadata> currentMetadata) {
    if (!targetContract.namespaces().isEmpty()) {
      return targetContract.namespaces().stream().map(AppDataNamespaceSchema::namespace).toList();
    }
    if (targetContract.currentSchemaVersion() != null) {
      return List.copyOf(currentMetadata.keySet());
    }
    return List.of();
  }

  /**
   * Resolves the effective installed schema version for one namespace.
   *
   * @param namespace durable namespace being inspected
   * @param installedContract installed bundle's schema contract
   * @param currentMetadata current host-owned namespace metadata
   * @return effective current schema version
   */
  private static int currentSchemaVersion(
      String namespace,
      AppDataSchemaContract installedContract,
      Map<String, AppDataNamespaceMetadata> currentMetadata) {
    AppDataNamespaceMetadata metadata = currentMetadata.get(namespace);
    if (metadata != null) {
      return metadata.schemaVersion();
    }
    AppDataNamespaceSchema installedNamespace = installedContract.namespace(namespace);
    if (installedNamespace != null) {
      return installedNamespace.currentSchemaVersion();
    }
    Integer globalCurrent = installedContract.currentSchemaVersion();
    return globalCurrent == null ? 1 : globalCurrent;
  }

  /**
   * Resolves the effective target schema version for one namespace.
   *
   * @param namespace durable namespace being inspected
   * @param targetContract retained target bundle's schema contract
   * @param currentVersion fallback when the target declares no version
   * @return effective target schema version
   */
  private static int targetSchemaVersion(
      String namespace, AppDataSchemaContract targetContract, int currentVersion) {
    AppDataNamespaceSchema targetNamespace = targetContract.namespace(namespace);
    if (targetNamespace != null) {
      return targetNamespace.currentSchemaVersion();
    }
    Integer globalTarget = targetContract.currentSchemaVersion();
    return globalTarget == null ? currentVersion : globalTarget;
  }

  /**
   * Converts the best signed migration-step path into lifecycle plan steps.
   *
   * @param namespace durable namespace being advanced
   * @param currentVersion installed schema version
   * @param targetVersion requested target schema version
   * @param migrations signed migration steps declared by the target bundle
   * @return ordered lifecycle steps, or an empty list when no path exists
   */
  private static List<AppDataMigrationPlan.NamespaceStep> migrationPath(
      String namespace,
      int currentVersion,
      int targetVersion,
      List<AppDataMigrationStep> migrations) {
    Optional<List<AppDataMigrationStep>> path =
        bestMigrationPath(
            namespace, currentVersion, targetVersion, migrations, new LinkedHashMap<>());
    return path.map(steps -> steps.stream().map(AppUpdateMigrationPlanner::namespaceStep).toList())
        .orElseGet(List::of);
  }

  /**
   * Finds the preferred acyclic forward path using memoized suffix decisions.
   *
   * @param namespace durable namespace being advanced
   * @param currentVersion schema version at this search node
   * @param targetVersion requested target schema version
   * @param migrations signed migration steps declared by the target bundle
   * @param memoizedPaths previously evaluated paths keyed by starting version
   * @return preferred path when the target version is reachable
   */
  private static Optional<List<AppDataMigrationStep>> bestMigrationPath(
      String namespace,
      int currentVersion,
      int targetVersion,
      List<AppDataMigrationStep> migrations,
      Map<Integer, Optional<List<AppDataMigrationStep>>> memoizedPaths) {
    if (currentVersion == targetVersion) {
      return Optional.of(List.of());
    }
    if (memoizedPaths.containsKey(currentVersion)) {
      return memoizedPaths.get(currentVersion);
    }
    Optional<List<AppDataMigrationStep>> best = Optional.empty();
    List<AppDataMigrationStep> candidates =
        migrations.stream()
            .filter(step -> step.namespace().equals(namespace))
            .filter(step -> step.fromSchemaVersion() == currentVersion)
            .filter(step -> step.toSchemaVersion() <= targetVersion)
            .sorted(
                Comparator.comparingInt(AppDataMigrationStep::toSchemaVersion)
                    .thenComparing(AppDataMigrationStep::stepId))
            .toList();
    for (AppDataMigrationStep candidate : candidates) {
      Optional<List<AppDataMigrationStep>> suffix =
          bestMigrationPath(
              namespace, candidate.toSchemaVersion(), targetVersion, migrations, memoizedPaths);
      if (suffix.isPresent()) {
        ArrayList<AppDataMigrationStep> candidatePath = new ArrayList<>();
        candidatePath.add(candidate);
        candidatePath.addAll(suffix.orElseThrow());
        if (best.isEmpty() || compareMigrationPaths(candidatePath, best.orElseThrow()) < 0) {
          best = Optional.of(List.copyOf(candidatePath));
        }
      }
    }
    memoizedPaths.put(currentVersion, best);
    return best;
  }

  /**
   * Orders two valid paths by rollback safety, stop requirements, length, and stable step id.
   *
   * @param left first candidate path
   * @param right second candidate path
   * @return negative, zero, or positive comparison result
   */
  private static int compareMigrationPaths(
      List<AppDataMigrationStep> left, List<AppDataMigrationStep> right) {
    int comparison =
        Integer.compare(rollbackIncompatibleSteps(left), rollbackIncompatibleSteps(right));
    if (comparison != 0) {
      return comparison;
    }
    comparison = Integer.compare(requiresStoppedSteps(left), requiresStoppedSteps(right));
    if (comparison != 0) {
      return comparison;
    }
    comparison = Integer.compare(left.size(), right.size());
    if (comparison != 0) {
      return comparison;
    }
    for (int index = 0; index < left.size(); index++) {
      comparison = left.get(index).stepId().compareTo(right.get(index).stepId());
      if (comparison != 0) {
        return comparison;
      }
    }
    return 0;
  }

  /**
   * Counts steps that cannot participate in automatic data rollback.
   *
   * @param steps candidate migration path
   * @return number of rollback-incompatible steps
   */
  private static int rollbackIncompatibleSteps(List<AppDataMigrationStep> steps) {
    return (int) steps.stream().filter(step -> !step.rollbackCompatible()).count();
  }

  /**
   * Counts steps that require the app process to remain stopped.
   *
   * @param steps candidate migration path
   * @return number of stop-required steps
   */
  private static int requiresStoppedSteps(List<AppDataMigrationStep> steps) {
    return (int) steps.stream().filter(AppDataMigrationStep::requiresStopped).count();
  }

  /**
   * Projects one signed manifest step into the lifecycle plan representation.
   *
   * @param step signed migration step from the target manifest
   * @return immutable lifecycle namespace step
   */
  private static AppDataMigrationPlan.NamespaceStep namespaceStep(AppDataMigrationStep step) {
    return new AppDataMigrationPlan.NamespaceStep(
        step.namespace(),
        step.fromSchemaVersion(),
        step.toSchemaVersion(),
        step.stepId(),
        step.rollbackCompatible(),
        step.requiresStopped(),
        step.description(),
        step.command());
  }
}
