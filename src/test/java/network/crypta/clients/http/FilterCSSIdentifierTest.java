package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Tests that valid CSS identifiers without non-ASCII characters or escaped characters are
 * unchanged, and that invalid ones are changed as expected.
 */
class FilterCSSIdentifierTest {
  @Test
  void testKnownValid() {
    String[] identifiers = {"sample_key-1", "-_", "-k_d", "_testing-key"};

    for (String identifier : identifiers) {
      assertEquals(identifier, PageMaker.filterCSSIdentifier(identifier));
    }
  }

  @Test
  void testInvalidFirstDash() {
    assertEquals("-_things", PageMaker.filterCSSIdentifier("-9things"));
    assertEquals("-_", PageMaker.filterCSSIdentifier("--"));
  }

  @Test
  void testInvalidChar() {
    assertEquals("__thing", PageMaker.filterCSSIdentifier("#$thing"));
  }
}
