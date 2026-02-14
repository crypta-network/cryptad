package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Instant;
import network.crypta.support.TimeUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class CookieTest {

  private static final URI VALID_PATH = URI.create("/Freetalk");
  private static final String VALID_NAME = "SessionID";
  private static final String VALID_VALUE = "abCd12345";
  private static final Instant FUTURE_DATE = Instant.parse("2099-01-01T00:00:00Z");

  private Cookie cookie;

  @BeforeEach
  void setUp() {
    cookie = new Cookie(VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);
  }

  @Test
  void validatePath_withAbsoluteUri_expectException() {
    URI absolute = URI.create("http://example.com");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validatePath(absolute));
  }

  @Test
  void validatePath_withoutLeadingSlash_expectException() {
    URI relative = URI.create("relative");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validatePath(relative));
  }

  @Test
  void validatePath_withLeadingSlashRelative_expectSamePath() {
    URI result = Cookie.validatePath(URI.create("/some/Path"));

    assertEquals("/some/Path", result.toString());
  }

  @Test
  void validateDomain_withInvalidScheme_expectException() {
    URI invalidScheme = URI.create("ftp://example.com");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validateDomain(invalidScheme));
  }

  @Test
  void validateDomain_withPathComponent_expectException() {
    URI withPath = URI.create("http://example.com/path");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validateDomain(withPath));
  }

  @Test
  void validateDomain_withQuery_expectException() {
    URI withQuery = URI.create("http://example.com?x=1");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validateDomain(withQuery));
  }

  @Test
  void validateDomain_withFragment_expectException() {
    URI withFragment = URI.create("http://example.com#frag");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validateDomain(withFragment));
  }

  @Test
  void validateDomain_withUserInfo_expectException() {
    URI withUserInfo = URI.create("http://user@example.com");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validateDomain(withUserInfo));
  }

  @Test
  void validateDomain_withHttpAndHttps_expectReturnedUri() {
    URI http = Cookie.validateDomain(URI.create("http://example.com"));
    URI https = Cookie.validateDomain(URI.create("https://example.com"));

    assertEquals("http://example.com", http.toString());
    assertEquals("https://example.com", https.toString());
  }

  @Test
  void validateDomain_withMixedCaseUri_expectLowercasedUri() {
    URI validated = Cookie.validateDomain(URI.create("http://EXAMPLE.com"));

    assertEquals("http://example.com", validated.toString());
  }

  @Test
  void validateName_withUppercaseAndWhitespace_expectLowercaseTrimmed() {
    String validated = Cookie.validateName("  SessionID  ");

    assertEquals("sessionid", validated);
  }

  @Test
  void validateName_withSeparatorCharacter_expectException() {
    assertThrows(IllegalArgumentException.class, () -> Cookie.validateName("invalid;name"));
  }

  @Test
  void validateName_withReservedToken_expectException() {
    assertThrows(IllegalArgumentException.class, () -> Cookie.validateName("domain"));
  }

  @Test
  void validateName_withNonAscii_expectException() {
    assertThrows(IllegalArgumentException.class, () -> Cookie.validateName("näm"));
  }

  @Test
  void validateValue_withTrimmedWhitespace_expectTrimmedResult() {
    String validated = Cookie.validateValue("  value  ");

    assertEquals("value", validated);
  }

  @Test
  void validateValue_withControlCharacter_expectException() {
    assertThrows(IllegalArgumentException.class, () -> Cookie.validateValue("abc\u0001def"));
  }

  @Test
  void validateValue_withInvalidCharacter_expectException() {
    assertThrows(IllegalArgumentException.class, () -> Cookie.validateValue("has(parenthesis"));
  }

  @Test
  void validateValue_withNonAscii_expectException() {
    assertThrows(IllegalArgumentException.class, () -> Cookie.validateValue("väl"));
  }

  @Test
  void validateExpirationDate_withFutureDate_expectSameInstance() {
    Instant validated = Cookie.validateExpirationDate(FUTURE_DATE);

    assertEquals(FUTURE_DATE, validated);
  }

  @Test
  void validateExpirationDate_withPastDate_expectException() {
    Instant past = Instant.parse("2020-01-01T00:00:00Z");

    assertThrows(IllegalArgumentException.class, () -> Cookie.validateExpirationDate(past));
  }

  @Test
  void constructor_withNullPath_expectNullPointer() {
    assertThrows(
        NullPointerException.class, () -> new Cookie(null, VALID_NAME, VALID_VALUE, FUTURE_DATE));
  }

  @Test
  void constructor_withNullName_expectNullPointer() {
    assertThrows(
        NullPointerException.class, () -> new Cookie(VALID_PATH, null, VALID_VALUE, FUTURE_DATE));
  }

  @Test
  void constructor_withNullValue_expectEmptyString() {
    Cookie created = new Cookie(VALID_PATH, VALID_NAME, null, FUTURE_DATE);

    assertEquals("", created.getValue());
  }

  @Test
  void constructor_normalizesNameToLowercase() {
    Cookie created = new Cookie(VALID_PATH, "MiXeD", VALID_VALUE, FUTURE_DATE);

    assertEquals("mixed", created.getName());
  }

  @Test
  void constructor_withDomainContainingQuery_expectException() {
    URI withQuery = URI.create("http://example.com?x=1");

    assertThrows(
        IllegalArgumentException.class,
        () -> new Cookie(withQuery, VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE));
  }

  @Test
  void equals_whenPathDiffers_expectFalse() {
    Cookie other = new Cookie(URI.create("/Other"), VALID_NAME, VALID_VALUE, FUTURE_DATE);

    assertNotEquals(cookie, other);
  }

  @Test
  void equals_whenDomainDiffers_expectFalse() {
    Cookie withDomain =
        new Cookie(
            URI.create("http://example.com"), VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);
    Cookie otherDomain =
        new Cookie(
            URI.create("http://other.com"), VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);

    assertNotEquals(withDomain, otherDomain);
  }

  @Test
  void equals_whenDomainCaseDiffers_expectTrue() {
    Cookie uppercaseDomain =
        new Cookie(
            URI.create("http://EXAMPLE.com"), VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);
    Cookie lowercaseDomain =
        new Cookie(
            URI.create("http://example.com"), VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);

    assertEquals(uppercaseDomain, lowercaseDomain);
    assertEquals(uppercaseDomain.hashCode(), lowercaseDomain.hashCode());
  }

  @Test
  void equals_whenOnlyValueDiffers_expectTrue() {
    Cookie other = new Cookie(VALID_PATH, VALID_NAME, "different", FUTURE_DATE);

    assertEquals(cookie, other);
  }

  @Test
  void hashCode_whenFieldsSet_matchesEqualsContract() {
    Cookie first =
        new Cookie(
            URI.create("http://example.com"), VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);
    Cookie second =
        new Cookie(
            URI.create("http://example.com"), VALID_PATH, VALID_NAME, "ignored", FUTURE_DATE);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void hashCode_withoutDomain_matchesEqualsContract() {
    Cookie first = new Cookie(VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);
    Cookie second = new Cookie(VALID_PATH, VALID_NAME, "ignored", FUTURE_DATE);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void encodeToHeaderValue_withDomain_includesDomainAttribute() {
    Cookie withDomain =
        new Cookie(
            URI.create("http://example.com"), VALID_PATH, VALID_NAME, VALID_VALUE, FUTURE_DATE);

    String encoded = withDomain.encodeToHeaderValue();

    assertTrue(encoded.contains("domain=http://example.com;"));
  }

  @Test
  void encodeToHeaderValue_includesAllAttributesInOrder() {
    String encoded = cookie.encodeToHeaderValue();
    String expectedExpires = TimeUtil.makeHTTPDate(FUTURE_DATE.toEpochMilli());

    assertTrue(encoded.startsWith("sessionid=" + VALID_VALUE + ";version=1;"));
    assertTrue(encoded.contains("path=" + VALID_PATH + ";"));
    assertTrue(encoded.contains("expires=" + expectedExpires + ";"));
    assertTrue(encoded.endsWith("discard=true;"));
  }
}
