package network.crypta.support.http;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class ExternalLinkSupportTest {

  @Test
  void escape_whenUsingDefaultPath_expectUsesConfiguredConstant() {
    // Arrange
    String uri = "http://example.com/resource?q=a%20b";

    // Act
    String escaped = ExternalLinkSupport.escape(uri);

    // Assert
    assertEquals(
        ExternalLinkSupport.EXTERNAL_LINK_PATH
            + "?"
            + ExternalLinkSupport.MAGIC_HTTP_ESCAPE_STRING
            + "="
            + uri,
        escaped);
  }

  @Test
  void escape_whenUsingCustomPath_expectPrependsProvidedPath() {
    // Arrange
    String customPath = "/custom-external-link/";
    String uri = "https://example.org/file";

    // Act
    String escaped = ExternalLinkSupport.escape(customPath, uri);

    // Assert
    assertEquals(
        customPath + "?" + ExternalLinkSupport.MAGIC_HTTP_ESCAPE_STRING + "=" + uri, escaped);
  }

  @Test
  void normalizePath_whenPathNeedsSeparators_expectLeadingAndTrailingSlashesAdded()
      throws Exception {
    // Arrange / Act / Assert
    assertEquals("/external-link/", invokeNormalizePath("external-link"));
    assertEquals("/external-link/", invokeNormalizePath("/external-link"));
    assertEquals("/external-link/", invokeNormalizePath("external-link/"));
  }

  @Test
  void normalizePath_whenPathNullOrEmpty_expectRootPath() throws Exception {
    // Arrange / Act / Assert
    assertEquals("/", invokeNormalizePath(null));
    assertEquals("/", invokeNormalizePath(""));
  }

  private static String invokeNormalizePath(String input) throws Exception {
    Method normalizePath =
        ExternalLinkSupport.class.getDeclaredMethod("normalizePath", String.class);
    normalizePath.setAccessible(true);
    return (String) normalizePath.invoke(null, input);
  }
}
