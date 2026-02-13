package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"java:S100", "ResultOfMethodCallIgnored"})
class ReceivedCookieTest {

  private static final String VALID_NAME = "SessionID";
  private static final String VALID_VALUE = "abCd12345";
  private static final String VALID_PATH = "/Freetalk";

  private ReceivedCookie cookie;

  @BeforeEach
  void setUp() throws Exception {
    cookie = ReceivedCookie.parseHeader(validHeaderWithAttributes()).getFirst();
  }

  @Test
  void parseHeader_singleCookieLowercasesNameAndKeepsValue() throws ParseException {
    ReceivedCookie parsed = ReceivedCookie.parseHeader("SessionID=abCd12345;$path=/").getFirst();

    assertEquals(VALID_NAME.toLowerCase(Locale.ROOT), parsed.getName());
    assertEquals(VALID_VALUE, parsed.getValue());
  }

  @Test
  void parseHeader_multipleCookies_parsesSequentially() throws ParseException {
    List<ReceivedCookie> cookies =
        ReceivedCookie.parseHeader("SessionID=abCd12345;$path=/;key2=valUe2;$path=/");

    assertEquals(2, cookies.size());
    assertEquals(VALID_NAME.toLowerCase(Locale.ROOT), cookies.get(0).getName());
    assertEquals(VALID_VALUE, cookies.get(0).getValue());
    assertEquals("key2", cookies.get(1).getName());
    assertEquals("valUe2", cookies.get(1).getValue());
  }

  @Test
  void parseHeader_attributesBeforeName_stillExtractsCookieName() throws ParseException {
    ReceivedCookie parsed =
        ReceivedCookie.parseHeader("$version=1; SessionID=abCd12345;$path=/").getFirst();

    assertEquals(VALID_NAME.toLowerCase(Locale.ROOT), parsed.getName());
    assertEquals(VALID_VALUE, parsed.getValue());
  }

  @Test
  void parseHeader_emptyKey_throwsParseException() {
    assertThrows(ParseException.class, () -> ReceivedCookie.parseHeader(" =value"));
  }

  @Test
  void parseHeader_missingSemicolonAfterQuotedValue_throwsParseException() {
    assertThrows(ParseException.class, () -> ReceivedCookie.parseHeader("sid=\"abc\"x"));
  }

  @Test
  void getDomain_withValidHttpDomain_returnsUri() {
    URI domain = cookie.getDomain();

    assertNotNull(domain);
    assertEquals("http://example.com", domain.toString());
  }

  @Test
  void getDomain_withInvalidScheme_throwsIllegalArgument() throws ParseException {
    ReceivedCookie parsed =
        ReceivedCookie.parseHeader("sid=value;$domain=ftp://example.com;$path=/").getFirst();

    assertThrows(IllegalArgumentException.class, parsed::getDomain);
  }

  @Test
  void getDomain_withoutDomainAttribute_returnsNull() throws ParseException {
    ReceivedCookie parsed = ReceivedCookie.parseHeader("sid=value;$path=/").getFirst();

    assertNull(parsed.getDomain());
  }

  @Test
  void getPath_withRelativePath_returnsUri() {
    URI path = cookie.getPath();

    assertNotNull(path);
    assertEquals(VALID_PATH, path.toString());
  }

  @Test
  void getPath_withAbsoluteUri_throwsIllegalArgument() throws ParseException {
    ReceivedCookie parsed =
        ReceivedCookie.parseHeader("sid=value;$path=http://example.com").getFirst();

    assertThrows(IllegalArgumentException.class, parsed::getPath);
  }

  @Test
  void getName_reservedToken_throwsIllegalArgument() throws ParseException {
    ReceivedCookie parsed = ReceivedCookie.parseHeader("path=value;$path=/").getFirst();

    assertThrows(IllegalArgumentException.class, parsed::getName);
  }

  @Test
  void getValue_withInvalidCharacter_throwsIllegalArgument() throws ParseException {
    ReceivedCookie parsed = ReceivedCookie.parseHeader("sid=a,b;$path=/").getFirst();

    assertThrows(IllegalArgumentException.class, parsed::getValue);
  }

  @Test
  void encodeToHeaderValue_throwsUnsupportedOperation() {
    assertThrows(UnsupportedOperationException.class, () -> cookie.encodeToHeaderValue());
  }

  private static String validHeaderWithAttributes() {
    return " SessionID = \"abCd12345\" ;"
        + " $Version = 1 ;"
        + " $Path = \"/Freetalk\";"
        + " $Domain = http://example.com;"
        + " $Discard; "
        + " $Expires = \"Sun, 25 Oct 2030 15:09:37 GMT\"; "
        + " $blah;";
  }
}
