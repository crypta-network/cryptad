package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appvault.AppVaultApiHandler;
import network.crypta.platform.api.identityvault.IdentityVaultApiHandler;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Routes the app-vault and identity-vault Platform API endpoint families.
 *
 * <p>The main {@link PlatformApiRouter} owns global authentication, authorization, audit wrapping,
 * and broad endpoint-family dispatch. This helper keeps the vault-specific collection/resource
 * routing with the vault handlers, which avoids adding vault endpoint details to the already broad
 * top-level router while preserving the same request and response shapes.
 */
final class PlatformApiVaultRouter {
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";
  private static final String METHODS_GET_POST = "GET, POST";
  private static final String GET_POST_ONLY_MESSAGE =
      "Platform API v1 supports GET and POST requests only.";
  private static final String METHODS_GET_DELETE = "GET, DELETE";
  private static final String GET_DELETE_ONLY_MESSAGE =
      "Platform API v1 supports GET and DELETE requests only.";
  private static final String METHODS_GET_PUT_DELETE = "GET, PUT, DELETE";
  private static final String GET_PUT_DELETE_ONLY_MESSAGE =
      "Platform API v1 supports GET, PUT, and DELETE requests only.";
  private static final String METHODS_PATCH_DELETE = "PATCH, DELETE";
  private static final String PATCH_DELETE_ONLY_MESSAGE =
      "Platform API v1 supports PATCH and DELETE requests only.";
  private static final String METHOD_DELETE = "DELETE";
  private static final String METHOD_GET = "GET";
  private static final String METHOD_PATCH = "PATCH";
  private static final String METHOD_POST = "POST";
  private static final String METHOD_PUT = "PUT";
  private static final String ROUTE_NOT_FOUND_MESSAGE = "Platform API route not found.";
  private static final String VAULT_GRANT_KEY = "grant";
  private static final String VAULT_GRANT_REQUEST_KEY = "grantRequest";
  private static final String VAULT_GRANTS_KEY = "grants";
  private static final String VAULT_IDENTITIES_KEY = "identities";
  private static final String VAULT_IDENTITY_KEY = "identity";
  private static final String VAULT_SECRET_KEY = "secret";
  private static final String VAULT_SECRETS_KEY = "secrets";
  private static final String VAULT_USAGE_KEY = "usage";

  private final AppVaultApiHandler appVaultApiHandler;
  private final IdentityVaultApiHandler identityVaultApiHandler;

  PlatformApiVaultRouter(AppVaultService appVaultService) {
    appVaultApiHandler = new AppVaultApiHandler(appVaultService);
    identityVaultApiHandler = new IdentityVaultApiHandler(appVaultService);
  }

  PlatformApiResponse routeAppVaultRequest(
      List<String> segments, PlatformApiRequest request, String appId) {
    return switch (segments.size()) {
      case 2 -> routeAppVaultCollection(appId, segments.get(1), request);
      case 3 -> routeAppVaultResource(appId, segments.get(1), segments.get(2), request);
      case 4 ->
          routeAppVaultNestedResource(
              appId, segments.get(1), segments.get(2), segments.get(3), request);
      default -> throw notFound();
    };
  }

  PlatformApiResponse routeIdentityVaultRequest(List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 2 -> routeIdentityVaultCollection(segments.get(1), request);
      case 3 -> routeIdentityVaultResource(segments.get(1), segments.get(2), request);
      default -> throw notFound();
    };
  }

  static boolean isVaultException(RuntimeException exception) {
    return exception instanceof AppVaultException;
  }

  static int statusCode(RuntimeException exception) {
    return asVaultException(exception).statusCode();
  }

  static String errorCode(RuntimeException exception) {
    return asVaultException(exception).errorCode();
  }

  private PlatformApiResponse routeAppVaultCollection(
      String appId, String collection, PlatformApiRequest request) {
    return switch (collection) {
      case VAULT_SECRETS_KEY -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(VAULT_SECRETS_KEY, appVaultApiHandler.listSecrets(appId)));
      }
      case VAULT_IDENTITIES_KEY -> {
        if (METHOD_GET.equals(request.method())) {
          yield PlatformApiResponse.ok(
              envelope(VAULT_IDENTITIES_KEY, appVaultApiHandler.listIdentities(appId)));
        }
        if (METHOD_POST.equals(request.method())) {
          yield PlatformApiResponse.created(
              envelope(
                  VAULT_IDENTITY_KEY,
                  appVaultApiHandler.createIdentity(appId, request.queryParameters())));
        }
        yield methodNotAllowed(METHODS_GET_POST, GET_POST_ONLY_MESSAGE);
      }
      case VAULT_GRANTS_KEY -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(VAULT_GRANTS_KEY, appVaultApiHandler.listGrants(appId)));
      }
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAppVaultResource(
      String appId, String collection, String resource, PlatformApiRequest request) {
    return switch (collection) {
      case VAULT_SECRETS_KEY -> routeAppVaultSecret(appId, resource, request);
      case VAULT_IDENTITIES_KEY -> routeAppVaultIdentity(appId, resource, request);
      case VAULT_GRANTS_KEY -> routeAppVaultGrantAction(appId, resource, request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAppVaultSecret(
      String appId, String secretName, PlatformApiRequest request) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(appVaultApiHandler.readSecret(appId, secretName));
    }
    if (METHOD_PUT.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(
              VAULT_SECRET_KEY,
              appVaultApiHandler.putSecret(appId, secretName, request.queryParameters())));
    }
    if (METHOD_DELETE.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(VAULT_SECRET_KEY, appVaultApiHandler.deleteSecret(appId, secretName)));
    }
    return methodNotAllowed(METHODS_GET_PUT_DELETE, GET_PUT_DELETE_ONLY_MESSAGE);
  }

  private PlatformApiResponse routeAppVaultIdentity(
      String appId, String identityId, PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(VAULT_IDENTITY_KEY, appVaultApiHandler.getIdentity(appId, identityId)));
  }

  private PlatformApiResponse routeAppVaultGrantAction(
      String appId, String action, PlatformApiRequest request) {
    if (!"request".equals(action)) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(
            VAULT_GRANT_REQUEST_KEY,
            appVaultApiHandler.requestGrant(appId, request.queryParameters())));
  }

  private PlatformApiResponse routeAppVaultNestedResource(
      String appId, String collection, String resource, String action, PlatformApiRequest request) {
    if (!VAULT_IDENTITIES_KEY.equals(collection) || !"use".equals(action)) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(
            VAULT_USAGE_KEY,
            appVaultApiHandler.useIdentity(appId, resource, request.queryParameters())));
  }

  private PlatformApiResponse routeIdentityVaultCollection(
      String collection, PlatformApiRequest request) {
    return switch (collection) {
      case VAULT_IDENTITIES_KEY -> {
        if (METHOD_GET.equals(request.method())) {
          yield PlatformApiResponse.ok(
              envelope(VAULT_IDENTITIES_KEY, identityVaultApiHandler.listIdentities()));
        }
        if (METHOD_POST.equals(request.method())) {
          yield PlatformApiResponse.created(
              envelope(
                  VAULT_IDENTITY_KEY,
                  identityVaultApiHandler.createIdentity(request.queryParameters())));
        }
        yield methodNotAllowed(METHODS_GET_POST, GET_POST_ONLY_MESSAGE);
      }
      case VAULT_GRANTS_KEY -> {
        if (METHOD_GET.equals(request.method())) {
          yield PlatformApiResponse.ok(
              envelope(VAULT_GRANTS_KEY, identityVaultApiHandler.listGrants()));
        }
        if (METHOD_POST.equals(request.method())) {
          yield PlatformApiResponse.created(
              envelope(
                  VAULT_GRANT_KEY, identityVaultApiHandler.createGrant(request.queryParameters())));
        }
        yield methodNotAllowed(METHODS_GET_POST, GET_POST_ONLY_MESSAGE);
      }
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeIdentityVaultResource(
      String collection, String resource, PlatformApiRequest request) {
    return switch (collection) {
      case VAULT_IDENTITIES_KEY -> routeIdentityVaultIdentity(resource, request);
      case VAULT_GRANTS_KEY -> routeIdentityVaultGrant(resource, request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeIdentityVaultIdentity(
      String identityId, PlatformApiRequest request) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(VAULT_IDENTITY_KEY, identityVaultApiHandler.getIdentity(identityId)));
    }
    if (METHOD_DELETE.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(VAULT_IDENTITY_KEY, identityVaultApiHandler.deleteIdentity(identityId)));
    }
    return methodNotAllowed(METHODS_GET_DELETE, GET_DELETE_ONLY_MESSAGE);
  }

  private PlatformApiResponse routeIdentityVaultGrant(String grantId, PlatformApiRequest request) {
    if (METHOD_PATCH.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(
              VAULT_GRANT_KEY,
              identityVaultApiHandler.updateGrantStatus(grantId, request.queryParameters())));
    }
    if (METHOD_DELETE.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(VAULT_GRANT_KEY, identityVaultApiHandler.revokeGrant(grantId)));
    }
    return methodNotAllowed(METHODS_PATCH_DELETE, PATCH_DELETE_ONLY_MESSAGE);
  }

  private static AppVaultException asVaultException(RuntimeException exception) {
    return (AppVaultException) exception;
  }

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", ROUTE_NOT_FOUND_MESSAGE);
  }

  private static Map<String, Object> envelope(String key, Object value) {
    java.util.LinkedHashMap<String, Object> envelope = java.util.LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }

  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }
}
