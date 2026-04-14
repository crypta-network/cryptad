package network.crypta.client.filter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HTMLFilterPolicyTest {

  @Test
  void htmlFilterPolicy_whenUpdatedThroughEitherFacade_expectSharedState() {
    boolean originalEmbed = HTMLFilterPolicy.isEmbedM3uPlayerEnabled();
    int originalSamePage = HTMLFilterPolicy.getMetaRefreshSamePageMinInterval();
    int originalRedirect = HTMLFilterPolicy.getMetaRefreshRedirectMinInterval();

    try {
      HTMLFilterPolicy.setEmbedM3uPlayerEnabled(false);
      HTMLFilterPolicy.setMetaRefreshSamePageMinInterval(4);
      HTMLFilterPolicy.setMetaRefreshRedirectMinInterval(9);

      assertFalse(HTMLFilter.isEmbedM3uPlayerEnabled());
      assertEquals(4, HTMLFilter.getMetaRefreshSamePageMinInterval());
      assertEquals(9, HTMLFilter.getMetaRefreshRedirectMinInterval());

      HTMLFilter.setEmbedM3uPlayerEnabled(true);
      HTMLFilter.setMetaRefreshSamePageMinInterval(6);
      HTMLFilter.setMetaRefreshRedirectMinInterval(11);

      assertTrue(HTMLFilterPolicy.isEmbedM3uPlayerEnabled());
      assertEquals(6, HTMLFilterPolicy.getMetaRefreshSamePageMinInterval());
      assertEquals(11, HTMLFilterPolicy.getMetaRefreshRedirectMinInterval());
    } finally {
      HTMLFilterPolicy.setEmbedM3uPlayerEnabled(originalEmbed);
      HTMLFilterPolicy.setMetaRefreshSamePageMinInterval(originalSamePage);
      HTMLFilterPolicy.setMetaRefreshRedirectMinInterval(originalRedirect);
    }
  }
}
