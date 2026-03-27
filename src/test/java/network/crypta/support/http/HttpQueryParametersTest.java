package network.crypta.support.http;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class HttpQueryParametersTest {

  @Test
  void parseUriParameters_whenNullOrEmpty_expectEmptyMap() {
    // Act
    Map<String, List<String>> nullResult = HttpQueryParameters.parseUriParameters(null, true);
    Map<String, List<String>> emptyResult = HttpQueryParameters.parseUriParameters("", true);

    // Assert
    assertTrue(nullResult.isEmpty());
    assertTrue(emptyResult.isEmpty());
  }

  @Test
  void parseUriParameters_whenDecodingEnabled_expectDecodedAndGroupedValues() {
    // Arrange
    String query = "a=one&b=two+three&b=abc%40def.de&lonely&empty=";

    // Act
    Map<String, List<String>> result = HttpQueryParameters.parseUriParameters(query, true);

    // Assert
    assertEquals(List.of("one"), result.get("a"));
    assertEquals(List.of("two three", "abc@def.de"), result.get("b"));
    assertEquals(List.of(""), result.get("lonely"));
    assertEquals(List.of(""), result.get("empty"));
  }

  @Test
  void parseUriParameters_whenDecodingDisabled_expectEncodedCharactersPreserved() {
    // Arrange
    String query = "a=one+two&b=abc%40def.de&b=three%2Bfour&lonely&empty=";

    // Act
    Map<String, List<String>> result = HttpQueryParameters.parseUriParameters(query, false);

    // Assert
    assertEquals(List.of("one+two"), result.get("a"));
    assertEquals(List.of("abc%40def.de", "three%2Bfour"), result.get("b"));
    assertEquals(List.of(""), result.get("lonely"));
    assertEquals(List.of(""), result.get("empty"));
  }
}
