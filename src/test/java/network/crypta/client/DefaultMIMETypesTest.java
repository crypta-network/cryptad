package network.crypta.client;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class DefaultMIMETypesTest {

  @Test
  public void testFullList() {
    for (String mimeType : DefaultMIMETypes.getMIMETypes()) {
      assertTrue(DefaultMIMETypes.isPlausibleMIMEType(mimeType), "Failed: \"" + mimeType + "\"");
    }
  }

  @Test
  public void testParams() {
    assertTrue(
        DefaultMIMETypes.isPlausibleMIMEType("text/xhtml+xml; charset=ISO-8859-1; blah=blah"));
    assertTrue(
        DefaultMIMETypes.isPlausibleMIMEType(
            "multipart/mixed; boundary=\"---this is a silly boundary---\""));
  }
}
