package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiRequestTest {
  @Test
  void constructor_whenPrincipalOmitted_expectHostOperatorPrincipal() {
    PlatformApiRequest request =
        new PlatformApiRequest("get", List.of("node", "greeting"), Map.of());

    assertEquals("GET", request.method());
    assertEquals(PlatformApiPrincipalType.HOST_OPERATOR, request.principal().type());
    assertEquals(PlatformApiAuthSource.HOST_LOCAL, request.principal().authSource());
    assertTrue(request.principal().permissions().isEmpty());
  }

  @Test
  void constructor_whenAppPrincipalProvided_expectSortedImmutablePermissions() {
    PlatformApiRequest request =
        new PlatformApiRequest(
            "GET",
            List.of("queue"),
            Map.of(),
            PlatformApiPrincipal.appToken("demo-app", List.of("queue.write", "queue.read")));

    assertEquals(PlatformApiPrincipalType.APP, request.principal().type());
    assertEquals(PlatformApiAuthSource.APP_TOKEN, request.principal().authSource());
    assertEquals("demo-app", request.principal().appId());
    assertEquals(List.of("queue.read", "queue.write"), request.principal().permissions());
  }

  @Test
  void constructor_whenMutableInputsChange_expectRequestKeepsImmutableCopies() {
    ArrayList<String> segments = new ArrayList<>(List.of("queue"));
    ArrayList<String> values = new ArrayList<>(List.of("downloads"));
    LinkedHashMap<String, List<String>> query = LinkedHashMap.newLinkedHashMap(1);
    query.put("view", values);

    PlatformApiRequest request = new PlatformApiRequest("get", segments, query);
    segments.add("mutated");
    values.add("mutated");
    query.put("later", List.of("value"));

    assertEquals(List.of("queue"), request.pathSegments());
    assertEquals(Map.of("view", List.of("downloads")), request.queryParameters());
    Map<String, List<String>> copiedQuery = request.queryParameters();
    List<String> newValue = List.of("value");
    assertThrows(UnsupportedOperationException.class, () -> copiedQuery.put("new", newValue));
  }

  @Test
  void constructor_whenAppPrincipalHasInvalidShape_expectIllegalArgumentException() {
    List<String> permissions = List.of("queue.read");

    assertThrows(
        IllegalArgumentException.class,
        () ->
            new PlatformApiPrincipal(
                PlatformApiPrincipalType.APP,
                PlatformApiAuthSource.HOST_LOCAL,
                "demo-app",
                permissions));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new PlatformApiPrincipal(
                PlatformApiPrincipalType.APP, PlatformApiAuthSource.APP_TOKEN, " ", permissions));
  }

  @Test
  void constructor_whenHostPrincipalCarriesAppFields_expectIllegalArgumentException() {
    List<String> noPermissions = List.of();
    List<String> permissions = List.of("queue.read");

    assertThrows(
        IllegalArgumentException.class,
        () ->
            new PlatformApiPrincipal(
                PlatformApiPrincipalType.HOST_OPERATOR,
                PlatformApiAuthSource.HOST_LOCAL,
                "demo-app",
                noPermissions));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new PlatformApiPrincipal(
                PlatformApiPrincipalType.HOST_OPERATOR,
                PlatformApiAuthSource.HOST_LOCAL,
                null,
                permissions));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new PlatformApiPrincipal(
                PlatformApiPrincipalType.HOST_OPERATOR,
                PlatformApiAuthSource.APP_TOKEN,
                null,
                noPermissions));
  }

  @Test
  void appToken_whenPermissionIsBlank_expectIllegalArgumentException() {
    List<String> permissions = List.of("queue.read", " ");

    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiPrincipal.appToken("demo-app", permissions));
  }
}
