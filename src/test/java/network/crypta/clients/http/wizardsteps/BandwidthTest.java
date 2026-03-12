package network.crypta.clients.http.wizardsteps;

import java.util.regex.Pattern;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BandwidthTest {

  @Mock HTTPRequest request;
  @Mock PageHelper helper;

  @ParameterizedTest
  @CsvSource({
    "true,false,BANDWIDTH_MONTHLY",
    "true,true,BANDWIDTH_MONTHLY",
    "false,true,BANDWIDTH_RATE",
    "false,false,BANDWIDTH_RATE"
  })
  void postStep_whenPartsSubmitted_expectCorrectNextStep(
      boolean yesPartSet, boolean noPartSet, String expectedStepName) {
    Bandwidth step = new Bandwidth();

    when(request.isPartSet(anyString()))
        .thenAnswer(
            invocation -> {
              String name = invocation.getArgument(0, String.class);
              if ("yes".equals(name)) {
                return yesPartSet;
              }
              if ("no".equals(name)) {
                return noPartSet;
              }
              return false;
            });

    String next = step.postStep(request);

    assertEquals(expectedStepName, next);
  }

  @Test
  void getStep_whenInvoked_buildsPromptAndSubmitButtons() {
    Bandwidth step = new Bandwidth();

    String expectedTitle = WizardL10n.l10n("step3Title");
    String expectedHeader = WizardL10n.l10n("bandwidthLimit");
    String expectedPrompt = WizardL10n.l10n("bandwidthCapPrompt");

    HTMLNode pageContent = new HTMLNode("div");
    when(helper.getPageContent(expectedTitle)).thenReturn(pageContent);

    HTMLNode infoboxContent = new HTMLNode("div");
    when(helper.getInfobox("infobox-normal", expectedHeader, pageContent, null, false))
        .thenAnswer(
            invocation -> {
              // Ensure mutations made by the step are visible in the generated HTML.
              pageContent.addChild(infoboxContent);
              return infoboxContent;
            });

    HTMLNode formNode = new HTMLNode("form");
    when(helper.addFormChild(infoboxContent, ".", "bwForm"))
        .thenAnswer(
            invocation -> {
              infoboxContent.addChild(formNode);
              return formNode;
            });

    step.getStep(request, helper);

    verify(helper).getPageContent(expectedTitle);
    verify(helper).getInfobox("infobox-normal", expectedHeader, pageContent, null, false);
    verify(helper).addFormChild(infoboxContent, ".", "bwForm");

    String html = pageContent.generate();

    assertTrue(html.contains(HTMLEncoder.encode(expectedPrompt)));

    assertHtmlHasSubmitInput(html, "yes", NodeL10n.getBase().getString("Toadlet.yes"));
    assertHtmlHasSubmitInput(html, "no", NodeL10n.getBase().getString("Toadlet.no"));
    assertHtmlHasSubmitInput(html, "back", NodeL10n.getBase().getString("Toadlet.back"));
  }

  private static void assertHtmlHasSubmitInput(String html, String name, String value) {
    String encodedValue = HTMLEncoder.encode(value);
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"submit\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(name)
                + "\")"
                + "(?=[^>]*\\bvalue=\""
                + Pattern.quote(encodedValue)
                + "\")"
                + "[^>]*>");
    assertTrue(pattern.matcher(html).find(), "Missing submit input name=" + name);
  }
}
