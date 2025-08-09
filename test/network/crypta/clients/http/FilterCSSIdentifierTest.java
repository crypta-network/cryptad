package network.crypta.clients.http;

import static org.junit.Assert.*;

import network.crypta.clients.http.PageMaker;
import org.junit.Test;

/**
 * Tests that valid CSS identifiers without non-ASCII characters or escaped characters are unchanged, and that invalid
 * ones are changed as expected.
 */
public class FilterCSSIdentifierTest {
	@Test
	public void testKnownValid() {
		String[] identifiers = { "sample_key-1", "-_", "-k_d", "_testing-key" };

		for (String identifier : identifiers) {
			assertEquals(identifier, PageMaker.filterCSSIdentifier(identifier));
		}
	}

	@Test
	public void testInvalidFirstDash() {
		assertEquals("-_things", PageMaker.filterCSSIdentifier("-9things"));
		assertEquals("-_", PageMaker.filterCSSIdentifier("--"));
	}

	@Test
	public void testInvalidChar() {
		assertEquals("__thing", PageMaker.filterCSSIdentifier("#$thing"));
	}
}
