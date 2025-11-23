package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;
import java.util.ArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReceivedCookieTest {

  private static final String VALID_NAME = "SessionID";
  private static final String VALID_VALUE = "abCd12345";

  private static final String validEncodedCookie =
      " SessionID = \"abCd12345\" ;"
          + " $Version = 1 ;"
          + " $Path = \"/Freetalk\";"
          + " $Discard; "
          + " $Expires = \"Sun, 25 Oct 2030 15:09:37 GMT\"; "
          + " $blah;";

  private Cookie cookie;

  @BeforeEach
  void setUp() throws Exception {
    cookie = ReceivedCookie.parseHeader(validEncodedCookie).getFirst();
  }

  @Test
  void parseHeader_handlesVariousCookieFormats() throws ParseException {
    ArrayList<ReceivedCookie> cookies;
    Cookie parsedCookie;

    parsedCookie = ReceivedCookie.parseHeader("SessionID=abCd12345").getFirst();
    assertEquals(VALID_NAME.toLowerCase(), parsedCookie.getName());
    assertEquals(VALID_VALUE, parsedCookie.getValue());

    cookies = ReceivedCookie.parseHeader("SessionID=abCd12345;key2=valUe2");
    parsedCookie = cookies.getFirst();
    assertEquals(VALID_NAME.toLowerCase(), parsedCookie.getName());
    assertEquals(VALID_VALUE, parsedCookie.getValue());
    parsedCookie = cookies.get(1);
    assertEquals("key2", parsedCookie.getName());
    assertEquals("valUe2", parsedCookie.getValue());

    parsedCookie =
        ReceivedCookie.parseHeader(" SessionID = \"abCd12345\" ;" + " $blah;").getFirst();
    assertEquals(VALID_NAME.toLowerCase(), parsedCookie.getName());
    assertEquals(VALID_VALUE, parsedCookie.getValue());

    parsedCookie = ReceivedCookie.parseHeader(" SessionID = \"abCd12345\" ;" + " $blah").getFirst();
    assertEquals(VALID_NAME.toLowerCase(), parsedCookie.getName());
    assertEquals(VALID_VALUE, parsedCookie.getValue());
  }

  @Test
  void encodeToHeaderValue_throwsUnsupportedOperation() {
    assertThrows(UnsupportedOperationException.class, () -> cookie.encodeToHeaderValue());
  }
}
