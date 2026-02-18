package network.crypta.clients.http.utils;

import java.util.Objects;
import network.crypta.config.Option;
import network.crypta.support.MultiValueTable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class UriFilterProxyHeaderParserTest {
  private static final String DEFAULT_BIND_TO = "127.0.0.1";
  private static final String DEFAULT_PORT = "8888";
  private static final String DEFAULT_HOST_WITH_PORT = "127.0.0.1:8888";
  private static final String DEFAULT_URL = "http://127.0.0.1:8888";
  private static final String BIND_TO_LOCAL_AND_FOO = "127.0.0.1,foo";
  private static final String HTTP_FOO = "http://foo";

  private static final String HEADER_HOST = "host";
  private static final String HEADER_X_FORWARDED_HOST = "x-forwarded-host";
  private static final String HEADER_X_FORWARDED_PROTO = "x-forwarded-proto";

  @Test
  void parse_whenNoHeadersAndNullUriSchemeAndNullUriHost_expectDefaults() {
    // Arrange
    MultiValueTable<String, String> headers = new MultiValueTable<>();

    // Act
    String result = parseToString(mockOption(""), mockOption(""), null, null, headers);

    // Assert
    assertEquals(DEFAULT_URL, result);
  }

  @Test
  void parse_whenHostHeaderPresentAndAllowed_expectUsesHostHeader() {
    // Arrange
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_HOST, "foo");

    // Act
    String result =
        parseToString(mockOption(DEFAULT_PORT), mockOption(BIND_TO_LOCAL_AND_FOO), "", "", headers);

    // Assert
    assertEquals(HTTP_FOO, result);
  }

  @Test
  void parse_whenUriHostProvidedAndAllowed_expectUsesUriHostOverHostHeader() {
    // Arrange
    MultiValueTable<String, String> headers =
        MultiValueTable.from(HEADER_HOST, DEFAULT_HOST_WITH_PORT);

    // Act
    String result =
        parseToString(
            mockOption(DEFAULT_PORT), mockOption(BIND_TO_LOCAL_AND_FOO), "", "foo", headers);

    // Assert
    assertEquals(HTTP_FOO, result);
  }

  @Test
  void parse_whenForwardedHostPresentAndAllowed_expectUsesForwardedHostOverUriAndHostHeader() {
    // Arrange
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put(HEADER_HOST, DEFAULT_HOST_WITH_PORT);
    headers.put(HEADER_X_FORWARDED_HOST, "foo:" + DEFAULT_PORT);

    // Act
    String result =
        parseToString(
            mockOption(DEFAULT_PORT),
            mockOption(BIND_TO_LOCAL_AND_FOO),
            "",
            DEFAULT_BIND_TO,
            headers);

    // Assert
    assertEquals("http://foo:8888", result);
  }

  @Test
  void
      parse_whenForwardedHostPresentButDisallowed_expectFallsBackToFirstBindToWithPortEvenIfUriHostAllowed() {
    // Arrange
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_X_FORWARDED_HOST, "evil");

    // Act
    String result =
        parseToString(
            mockOption(DEFAULT_PORT), mockOption(BIND_TO_LOCAL_AND_FOO), "", "foo", headers);

    // Assert
    assertEquals(DEFAULT_URL, result);
  }

  @Test
  void parse_whenForwardedProtoPresentAndAllowed_expectUsesForwardedProto() {
    // Arrange
    MultiValueTable<String, String> headers =
        MultiValueTable.from(HEADER_X_FORWARDED_PROTO, "https");

    // Act
    String result =
        parseToString(mockOption(DEFAULT_PORT), mockOption(DEFAULT_BIND_TO), "", "", headers);

    // Assert
    assertEquals("https://127.0.0.1:8888", result);
  }

  @Test
  void parse_whenForwardedProtoPresentButInvalid_expectFallsBackToHttpEvenIfUriSchemeHttps() {
    // Arrange
    MultiValueTable<String, String> headers =
        MultiValueTable.from(HEADER_X_FORWARDED_PROTO, "gopher");

    // Act
    String result =
        parseToString(mockOption(DEFAULT_PORT), mockOption(DEFAULT_BIND_TO), "https", "", headers);

    // Assert
    assertEquals(DEFAULT_URL, result);
  }

  @Test
  void parse_whenUriSchemeInvalid_expectFallsBackToHttp() {
    // Arrange
    MultiValueTable<String, String> headers = new MultiValueTable<>();

    // Act
    String result =
        parseToString(mockOption(DEFAULT_PORT), mockOption(DEFAULT_BIND_TO), "ftp", "", headers);

    // Assert
    assertEquals(DEFAULT_URL, result);
  }

  @Test
  void parse_whenPortConfigEmpty_expectDefaultPortUsedInFallbackHost() {
    // Arrange
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_X_FORWARDED_HOST, "evil");

    // Act
    String result = parseToString(mockOption(""), mockOption(DEFAULT_BIND_TO), "", "", headers);

    // Assert
    assertEquals(DEFAULT_URL, result);
  }

  @Test
  void parse_whenBindToIpv6Literal_expectAllowsBracketedHostAndPort() {
    // Arrange
    MultiValueTable<String, String> headers =
        MultiValueTable.from(HEADER_X_FORWARDED_HOST, "[2001:db8::1]:" + DEFAULT_PORT);

    // Act
    String result =
        parseToString(mockOption(DEFAULT_PORT), mockOption("2001:db8::1"), "", "", headers);

    // Assert
    assertEquals("http://[2001:db8::1]:8888", result);
  }

  @Test
  void parse_whenBindToIpv6LiteralAndHostDisallowed_expectFallsBackToFirstBindToWithPort() {
    // Arrange
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_X_FORWARDED_HOST, "evil");

    // Act
    String result =
        parseToString(mockOption(DEFAULT_PORT), mockOption("2001:db8::1"), "", "", headers);

    // Assert
    assertEquals("http://[2001:db8::1]:8888", result);
  }

  @Test
  void parse_whenPortNonStandardAndForwardedHostHasNoPort_expectAllowsHostWithoutPort() {
    // Arrange
    MultiValueTable<String, String> headers = MultiValueTable.from(HEADER_X_FORWARDED_HOST, "foo");

    // Act
    String result =
        parseToString(mockOption("8889"), mockOption(BIND_TO_LOCAL_AND_FOO), "", "", headers);

    // Assert
    assertEquals(HTTP_FOO, result);
  }

  @Test
  void parse_whenHeadersNull_expectThrowsNullPointerException() {
    // Arrange
    Option<?> port = mockOption(DEFAULT_PORT);
    Option<?> bindTo = mockOption(DEFAULT_BIND_TO);

    // Act / Assert
    assertThrows(
        NullPointerException.class,
        () -> UriFilterProxyHeaderParser.parse(port, bindTo, "", "", null));
  }

  @Test
  void parse_whenBindToOptionNull_expectThrowsNullPointerException() {
    // Arrange
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    Option<?> port = mock(Option.class);

    // Act / Assert
    //noinspection DataFlowIssue
    assertThrows(
        NullPointerException.class,
        () -> UriFilterProxyHeaderParser.parse(port, null, "", "", headers));
  }

  private static String parseToString(
      Option<?> fProxyPortConfig,
      Option<?> fProxyBindToConfig,
      String uriScheme,
      String uriHost,
      MultiValueTable<String, String> headers) {
    UriFilterProxyHeaderParser.SchemeAndHostWithPort result =
        UriFilterProxyHeaderParser.parse(
            Objects.requireNonNull(fProxyPortConfig),
            Objects.requireNonNull(fProxyBindToConfig),
            uriScheme,
            uriHost,
            Objects.requireNonNull(headers));
    return result.toString();
  }

  private static Option<?> mockOption(String value) {
    Option<?> option = mock(Option.class);
    when(option.getValueString()).thenReturn(value);
    return option;
  }
}
