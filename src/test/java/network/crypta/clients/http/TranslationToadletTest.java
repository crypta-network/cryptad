package network.crypta.clients.http;

import java.lang.reflect.Field;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TranslationToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private BaseL10n baseL10n;
  private BaseL10n originalBase;
  private TranslationToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    originalBase = getNodeL10nBase();
    baseL10n = mock(BaseL10n.class);
    setNodeL10nBase(baseL10n);

    when(baseL10n.getSelectedLanguage()).thenReturn(BaseL10n.LANGUAGE.ENGLISH);
    when(baseL10n.getString(anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0, String.class));
    when(baseL10n.getString(anyString(), any(String[].class), any(String[].class)))
        .thenAnswer(invocation -> invocation.getArgument(0, String.class));

    toadlet = new TranslationToadlet(client);
  }

  @AfterEach
  void tearDown() throws Exception {
    setNodeL10nBase(originalBase);
  }

  @Test
  void path_returnsTranslationUrl() {
    assertEquals(TranslationToadlet.TOADLET_URL, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_doesNothing() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(URI.create(TranslationToadlet.TOADLET_URL), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenOverrideFileAvailable_streamsFile() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isParameterSet("toTranslateOnly")).thenReturn(false);
    when(request.isParameterSet("getOverrideTranslationFile")).thenReturn(true);

    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("hello", "world");
    when(baseL10n.getOverrideForCurrentLanguageTranslation()).thenReturn(sfs);
    when(baseL10n.getL10nOverrideFileName(BaseL10n.LANGUAGE.ENGLISH)).thenReturn("override.txt");

    toadlet.handleMethodGET(URI.create(TranslationToadlet.TOADLET_URL), request, ctx);

    byte[] expected = sfs.toOrderedString().getBytes(UTF_8);

    ArgumentCaptor<Integer> codeCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> descCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor = captureHeaders();
    ArgumentCaptor<String> mimeCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> lengthCaptor = ArgumentCaptor.forClass(Long.class);

    verify(ctx)
        .sendReplyHeaders(
            codeCaptor.capture(),
            descCaptor.capture(),
            headersCaptor.capture(),
            mimeCaptor.capture(),
            lengthCaptor.capture());

    assertEquals(200, codeCaptor.getValue());
    assertEquals("Found", descCaptor.getValue());
    assertEquals("text/plain; charset=utf-8", mimeCaptor.getValue());
    assertEquals(expected.length, lengthCaptor.getValue());
    assertEquals(
        "attachment; filename=\"override.txt\"",
        headersCaptor.getValue().getFirst("Content-Disposition"));
    verify(ctx).writeData(expected);
  }

  @Test
  void handleMethodGET_whenOverrideMissing_sendsErrorPage() throws Exception {
    TranslationToadlet spyToadlet = spy(toadlet);
    when(ctx.checkFullAccess(spyToadlet)).thenReturn(true);
    when(request.isParameterSet("toTranslateOnly")).thenReturn(false);
    when(request.isParameterSet("getOverrideTranslationFile")).thenReturn(true);
    when(baseL10n.getOverrideForCurrentLanguageTranslation()).thenReturn(null);
    doNothing()
        .when(spyToadlet)
        .sendErrorPage(ctx, 503, "Service Unavailable", "TranslationToadlet.noCustomTranslations");

    spyToadlet.handleMethodGET(URI.create(TranslationToadlet.TOADLET_URL), request, ctx);

    verify(spyToadlet)
        .sendErrorPage(ctx, 503, "Service Unavailable", "TranslationToadlet.noCustomTranslations");
  }

  @Test
  void handleMethodPOST_whenGotoNext_redirectsToNextKey() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("translating_for")).thenReturn(false);
    when(request.isPartSet("toTranslateOnly")).thenReturn(false);
    when(request.getPartAsStringFailsafe("translation_update", 32)).thenReturn("update");
    when(request.getPartAsStringFailsafe("key", 256)).thenReturn("currentKey");
    when(request.getPart("trans")).thenReturn(new ArrayBucket(" new value ".getBytes(UTF_8)));
    when(request.getPartAsStringFailsafe("gotoNext", 7)).thenReturn("on");

    SimpleFieldSet translationSet = mock(SimpleFieldSet.class);
    SimpleFieldSet.KeyIterator keyIterator = mock(SimpleFieldSet.KeyIterator.class);
    when(keyIterator.hasNext()).thenReturn(true, true, false);
    when(keyIterator.nextKey()).thenReturn("alreadyTranslated", "nextKey");
    when(translationSet.keyIterator("")).thenReturn(keyIterator);
    when(baseL10n.getDefaultLanguageTranslation()).thenReturn(translationSet);
    when(baseL10n.isOverridden("alreadyTranslated")).thenReturn(false);
    when(baseL10n.getString("alreadyTranslated", true)).thenReturn("present");
    when(baseL10n.isOverridden("nextKey")).thenReturn(false);
    when(baseL10n.getString("nextKey", true)).thenReturn(null);

    toadlet.handleMethodPOST(URI.create(TranslationToadlet.TOADLET_URL), request, ctx);

    verify(baseL10n).setOverride("currentKey", "new value");

    ArgumentCaptor<Integer> codeCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> descCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor = captureHeaders();
    ArgumentCaptor<String> mimeCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> lengthCaptor = ArgumentCaptor.forClass(Long.class);

    verify(ctx)
        .sendReplyHeaders(
            codeCaptor.capture(),
            descCaptor.capture(),
            headersCaptor.capture(),
            mimeCaptor.capture(),
            lengthCaptor.capture());

    assertEquals(302, codeCaptor.getValue());
    assertEquals("Found", descCaptor.getValue());
    assertEquals(0L, lengthCaptor.getValue());
    assertEquals(
        TranslationToadlet.TOADLET_URL + "?gotoNext&translate=nextKey",
        headersCaptor.getValue().getFirst("Location"));
    assertEquals(
        TranslationToadlet.TOADLET_URL + "?gotoNext&translate=nextKey",
        headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodPOST_whenRemoveConfirmed_clearsOverrideAndRedirects() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("translating_for")).thenReturn(false);
    when(request.isPartSet("toTranslateOnly")).thenReturn(false);
    when(request.getPartAsStringFailsafe("translation_update", 32)).thenReturn("");
    when(request.getPartAsStringFailsafe("remove_confirmed", 32)).thenReturn("yes");
    when(request.getPartAsStringFailsafe("remove_confirm", 256)).thenReturn("killkey ");

    toadlet.handleMethodPOST(URI.create(TranslationToadlet.TOADLET_URL), request, ctx);

    verify(baseL10n).setOverride("killkey", "");

    ArgumentCaptor<Integer> codeCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> descCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor = captureHeaders();
    ArgumentCaptor<String> mimeCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> lengthCaptor = ArgumentCaptor.forClass(Long.class);

    verify(ctx)
        .sendReplyHeaders(
            codeCaptor.capture(),
            descCaptor.capture(),
            headersCaptor.capture(),
            mimeCaptor.capture(),
            lengthCaptor.capture());

    assertEquals(302, codeCaptor.getValue());
    assertEquals("Found", descCaptor.getValue());
    assertEquals(0L, lengthCaptor.getValue());
    assertEquals(
        TranslationToadlet.TOADLET_URL + "?translation_updated=killkey",
        headersCaptor.getValue().getFirst("Location"));
  }

  private static BaseL10n getNodeL10nBase() throws Exception {
    Field field = NodeL10n.class.getDeclaredField("b");
    field.setAccessible(true);
    return (BaseL10n) field.get(null);
  }

  private static void setNodeL10nBase(BaseL10n base) throws Exception {
    Field field = NodeL10n.class.getDeclaredField("b");
    field.setAccessible(true);
    field.set(null, base);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static ArgumentCaptor<MultiValueTable<String, String>> captureHeaders() {
    return ArgumentCaptor.forClass(
        (Class<MultiValueTable<String, String>>) (Class) MultiValueTable.class);
  }
}
