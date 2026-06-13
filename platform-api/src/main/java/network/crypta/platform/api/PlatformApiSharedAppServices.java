package network.crypta.platform.api;

import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Optional app-platform services shared between Platform API routing and background schedulers.
 *
 * <p>Most router embeddings can omit these services and let request routes create their local
 * coordinators when enough AppHost support is present. The HTTP runtime passes shared instances so
 * request handlers, app-update scheduling, and content-subscription scheduling observe the same
 * policy state, staged plans, subscription metadata, and vault service. All components are optional
 * because reduced test and embedded configurations expose only selected Platform API route
 * families.
 *
 * @param vaultService optional app-vault service for app and identity vault routes
 * @param updateService optional shared app-update lifecycle service
 * @param contentSubscriptionService optional shared content-subscription service
 * @param appDataService optional shared durable app-data service
 * @param trustGraphApiHandler optional shared durable trust graph preview handler
 * @param appServiceCoordinator optional shared app-service discovery and grant coordinator
 * @param networkBudgetService optional shared app-network budget service
 */
public record PlatformApiSharedAppServices(
    AppVaultService vaultService,
    AppUpdateService updateService,
    ContentSubscriptionService contentSubscriptionService,
    AppDataService appDataService,
    TrustGraphApiHandler trustGraphApiHandler,
    AppServiceCoordinator appServiceCoordinator,
    AppNetworkBudgetService networkBudgetService) {

  /**
   * Returns an empty shared-service group.
   *
   * @return service group with every optional app-platform service absent
   */
  public static PlatformApiSharedAppServices none() {
    return new PlatformApiSharedAppServices(null, null, null, null, null, null, null);
  }

  /**
   * Returns a service group containing only an app-vault service.
   *
   * @param vaultService optional app-vault service
   * @return service group with vault routing enabled when {@code vaultService} is non-null
   */
  public static PlatformApiSharedAppServices withVault(AppVaultService vaultService) {
    return new PlatformApiSharedAppServices(vaultService, null, null, null, null, null, null);
  }

  /**
   * Returns a service group containing all currently shared app-platform service types.
   *
   * @param vaultService optional app-vault service
   * @param appUpdateService optional shared app-update lifecycle service
   * @param contentSubscriptionService optional shared content-subscription service
   * @return service group for runtime-managed app-platform route families
   */
  public static PlatformApiSharedAppServices of(
      AppVaultService vaultService,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService) {
    return of(vaultService, appUpdateService, contentSubscriptionService, null, null);
  }

  /**
   * Returns a service group containing all currently shared app-platform service types.
   *
   * @param vaultService optional app-vault service
   * @param appUpdateService optional shared app-update lifecycle service
   * @param contentSubscriptionService optional shared content-subscription service
   * @param appDataService optional durable app-data service
   * @return service group for runtime-managed app-platform route families
   */
  public static PlatformApiSharedAppServices of(
      AppVaultService vaultService,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService) {
    return of(vaultService, appUpdateService, contentSubscriptionService, appDataService, null);
  }

  /**
   * Returns a service group containing all currently shared app-platform service types.
   *
   * @param vaultService optional app-vault service
   * @param appUpdateService optional shared app-update lifecycle service
   * @param contentSubscriptionService optional shared content-subscription service
   * @param appDataService optional durable app-data service
   * @param trustGraphApiHandler optional shared durable trust graph preview handler
   * @return service group for runtime-managed app-platform route families
   */
  public static PlatformApiSharedAppServices of(
      AppVaultService vaultService,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler) {
    return of(
        vaultService,
        appUpdateService,
        contentSubscriptionService,
        appDataService,
        trustGraphApiHandler,
        null);
  }

  /**
   * Returns a service group containing all currently shared app-platform service types.
   *
   * @param vaultService optional app-vault service
   * @param appUpdateService optional shared app-update lifecycle service
   * @param contentSubscriptionService optional shared content-subscription service
   * @param appDataService optional durable app-data service
   * @param trustGraphApiHandler optional shared durable trust graph preview handler
   * @param appServiceCoordinator optional shared app-service discovery and grant coordinator
   * @return service group for runtime-managed app-platform route families
   */
  public static PlatformApiSharedAppServices of(
      AppVaultService vaultService,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppServiceCoordinator appServiceCoordinator) {
    return new PlatformApiSharedAppServices(
        vaultService,
        appUpdateService,
        contentSubscriptionService,
        appDataService,
        trustGraphApiHandler,
        appServiceCoordinator,
        null);
  }

  /**
   * Returns a service group with all shared app-platform service types and network budget service.
   *
   * @param vaultService optional app-vault service
   * @param appUpdateService optional shared app-update lifecycle service
   * @param contentSubscriptionService optional shared content-subscription service
   * @param appDataService optional durable app-data service
   * @param trustGraphApiHandler optional shared durable trust graph preview handler
   * @param appServiceCoordinator optional shared app-service coordinator
   * @param networkBudgetService optional shared app-network budget service
   * @return service group for runtime-managed app-platform route families
   */
  public static PlatformApiSharedAppServices of(
      AppVaultService vaultService,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppServiceCoordinator appServiceCoordinator,
      AppNetworkBudgetService networkBudgetService) {
    return new PlatformApiSharedAppServices(
        vaultService,
        appUpdateService,
        contentSubscriptionService,
        appDataService,
        trustGraphApiHandler,
        appServiceCoordinator,
        networkBudgetService);
  }
}
