package network.crypta.clients.http.utils;

import network.crypta.l10n.BaseL10nTest;
import network.crypta.support.HTMLNode;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static network.crypta.l10n.BaseL10n.LANGUAGE.ENGLISH;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class PebbleUtilsTest {

    static {
        PebbleUtils.setBaseL10n(BaseL10nTest.createTestL10n(ENGLISH));
    }

    @Test
    public void addChildAddsCorrectlyEvaluatedSimpleTemplateToHtmlNode() throws IOException {
        PebbleUtils.addChild(emptyParentNode, "pebble-utils-test-simple", model, null);
        assertThat(emptyParentNode.generate(), equalTo("Test!\n"));
    }

    @Test
    public void addChildAddsCorrectlyEvaluatedTemplateWithL10nFunctionToHtmlNode() throws IOException {
        PebbleUtils.addChild(emptyParentNode, "pebble-utils-test-l10n", model, "pebble-utils-tests.");
        assertThat(emptyParentNode.generate(), equalTo("Test Value"));
    }
    private final HTMLNode emptyParentNode = new HTMLNode("#");
    private final Map<String, Object> model = new HashMap<>();

}
