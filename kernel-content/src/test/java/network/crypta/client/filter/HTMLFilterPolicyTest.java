package network.crypta.client.filter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HTMLFilterPolicyTest {

  @Test
  void htmlFilterPolicy_defaults_expectDocumentedValues() {
    assertTrue(HTMLFilterPolicy.isEmbedM3uPlayerEnabled());
    assertEquals(1, HTMLFilterPolicy.getMetaRefreshSamePageMinInterval());
    assertEquals(30, HTMLFilterPolicy.getMetaRefreshRedirectMinInterval());
  }

  @Test
  void htmlFilterPolicy_whenUpdated_expectValuesStoredGlobally() {
    boolean originalEmbed = HTMLFilterPolicy.isEmbedM3uPlayerEnabled();
    int originalSamePage = HTMLFilterPolicy.getMetaRefreshSamePageMinInterval();
    int originalRedirect = HTMLFilterPolicy.getMetaRefreshRedirectMinInterval();

    try {
      HTMLFilterPolicy.setEmbedM3uPlayerEnabled(false);
      HTMLFilterPolicy.setMetaRefreshSamePageMinInterval(7);
      HTMLFilterPolicy.setMetaRefreshRedirectMinInterval(13);

      assertFalse(HTMLFilterPolicy.isEmbedM3uPlayerEnabled());
      assertEquals(7, HTMLFilterPolicy.getMetaRefreshSamePageMinInterval());
      assertEquals(13, HTMLFilterPolicy.getMetaRefreshRedirectMinInterval());
    } finally {
      HTMLFilterPolicy.setEmbedM3uPlayerEnabled(originalEmbed);
      HTMLFilterPolicy.setMetaRefreshSamePageMinInterval(originalSamePage);
      HTMLFilterPolicy.setMetaRefreshRedirectMinInterval(originalRedirect);
    }
  }
}
