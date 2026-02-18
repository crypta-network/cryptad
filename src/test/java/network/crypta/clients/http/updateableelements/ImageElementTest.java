package network.crypta.clients.http.updateableelements;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.List;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.clients.http.FProxyFetchCriteria;
import network.crypta.clients.http.FProxyFetchInProgress;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.FProxyFetchProgressCounts;
import network.crypta.clients.http.FProxyFetchResult;
import network.crypta.clients.http.FProxyFetchSnapshotInfo;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyFetchWaiter;
import network.crypta.clients.http.ToadletContext;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S3011"})
class ImageElementTest {

  private static final String TAG_INPUT = "input";
  private static final String TAG_NOSCRIPT = "noscript";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_SRC = "src";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_VALUE = "value";

  private static final Constructor<FProxyFetchResult> RESULT_CTOR_FINISHED_WITH_DATA =
      getResultConstructorFinishedWithData();
  private static final Constructor<FProxyFetchResult> RESULT_CTOR_PROGRESS_OR_FAILURE =
      getResultConstructorProgressOrFailure();

  @Mock private FProxyFetchTracker tracker;
  @Mock private ToadletContext ctx;

  private FreenetURI key;

  @BeforeEach
  void setUp() throws Exception {
    NodeL10n.getBase().getDefaultLanguageTranslation();
    key = new FreenetURI("KSK@test-image");

    when(ctx.getUniqueId()).thenReturn("req-123");
    when(tracker.makeRandomElementID()).thenReturn(42);
  }

  @Test
  void getUpdaterType_returnsExpectedUpdaterConstant() {
    // Arrange
    ImageElement element = ImageElement.createImageElement(tracker, key, 123L, ctx, false);

    // Act
    String updaterType = element.getUpdaterType();

    // Assert
    assertEquals(UpdaterConstants.IMAGE_ELEMENT_UPDATER, updaterType);
  }

  @Test
  void getId_whenGivenUri_decodesToExpectedPlaintext() throws Exception {
    // Arrange
    int random = 123;

    // Act
    String id = ImageElement.getId(key, random);

    // Assert
    String decoded = new String(Base64.decodeStandard(id), StandardCharsets.UTF_8);
    assertEquals("image[URI:" + key + ",random:" + random + "]", decoded);
  }

  @Test
  void getId_whenUriIsNull_throwsNullPointerException() {
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> ImageElement.getId(null, 1));
  }

  @Test
  void getUpdaterId_whenCalledWithDifferentRequestIds_isStable() {
    // Arrange
    ImageElement element = ImageElement.createImageElement(tracker, key, 123L, ctx, false);

    // Act
    String updaterIdA = element.getUpdaterId("req-a");
    String updaterIdB = element.getUpdaterId("req-b");

    // Assert
    assertEquals(updaterIdA, updaterIdB);
    assertEquals(ImageElement.getId(key, 42), updaterIdA);
  }

  @ParameterizedTest
  @CsvSource({
    "-1, -1, false, false",
    "80, -1, true, false",
    "-1, 60, false, true",
    "80, 60, true, true"
  })
  void createImageElement_whenDimensionsProvided_appliesAttributesToOriginalImg(
      int width, int height, boolean expectWidth, boolean expectHeight) {
    // Arrange
    long maxSize = 456L;

    // Act
    ImageElement element =
        ImageElement.createImageElement(
            tracker, key, maxSize, ctx, new ImageElementAttributes(width, height, null), false);

    // Assert
    HTMLNode noscript = requireChildByName(element, TAG_NOSCRIPT);
    HTMLNode img = requireChildByName(noscript, "img");
    assertEquals(key.toString(), img.getAttribute(ATTR_SRC));
    if (expectWidth) {
      assertEquals(String.valueOf(width), img.getAttribute("width"));
    } else {
      assertNull(img.getAttribute("width"));
    }
    if (expectHeight) {
      assertEquals(String.valueOf(height), img.getAttribute("height"));
    } else {
      assertNull(img.getAttribute("height"));
    }
  }

  @Test
  void createImageElement_whenNameProvided_setsAltAndTitle() {
    // Arrange
    String name = "My image";

    // Act
    ImageElement element =
        ImageElement.createImageElement(
            tracker, key, 1L, ctx, new ImageElementAttributes(-1, -1, name), false);

    // Assert
    HTMLNode img = requireChildByName(requireChildByName(element, TAG_NOSCRIPT), "img");
    assertEquals(name, img.getAttribute("alt"));
    assertEquals(name, img.getAttribute("title"));
  }

  @Test
  void updateState_whenInitialAndNotError_rendersInitializingImageAndHiddenInputs() {
    // Arrange
    ImageElement element =
        ImageElement.createImageElement(
            tracker, key, 999L, ctx, new ImageElementAttributes(12, 34, "name"), false);
    setWasError(element, false);

    // Act
    // Initial render already happened in BaseUpdatableElement.init().
    HTMLNode jsSpan = requireChildByName(element, "span");

    // Assert
    assertEquals("jsonly ImageElement", jsSpan.getAttribute(ATTR_CLASS));
    HTMLNode img = requireChildByName(jsSpan, "img");
    String src = img.getAttribute(ATTR_SRC);
    assertNotNull(src);
    assertTrue(
        src.startsWith("/imagecreator/?text=+"), "initial src uses imagecreator placeholder");
    assertTrue(src.contains("&width=12&height=34"), "initial placeholder includes size parameters");

    HTMLNode fetched = requireInputByName(jsSpan, "fetchedBlocks");
    assertEquals("hidden", fetched.getAttribute(ATTR_TYPE));
    assertEquals("0", fetched.getAttribute(ATTR_VALUE));

    HTMLNode required = requireInputByName(jsSpan, "requiredBlocks");
    assertEquals("hidden", required.getAttribute(ATTR_TYPE));
    assertEquals("1", required.getAttribute(ATTR_VALUE));

    HTMLNode noscript = requireChildByName(element, TAG_NOSCRIPT);
    HTMLNode originalImg = requireChildByName(noscript, "img");
    assertEquals(key.toString(), originalImg.getAttribute(ATTR_SRC));
  }

  @Test
  void updateState_whenInitialAndWasError_rendersOriginalImageForJsEnabled() {
    // Arrange
    ImageElement element = ImageElement.createImageElement(tracker, key, 999L, ctx, false);
    setWasError(element, true);

    // Act
    element.updateState(true);
    HTMLNode jsSpan = requireChildByName(element, "span");

    // Assert
    HTMLNode img = requireChildByName(jsSpan, "img");
    assertEquals(key.toString(), img.getAttribute(ATTR_SRC));
    assertNull(
        findFirstChildByName(jsSpan, TAG_INPUT), "no hidden inputs when showing original image");
  }

  @Test
  void updateState_whenNotInitialAndFetcherThrows_addsErrorAndNoFetcherFound()
      throws FetchException {
    // Arrange
    ImageElement element = ImageElement.createImageElement(tracker, key, 123L, ctx, false);
    when(tracker.makeFetcher(new FProxyFetchCriteria(key, 123L, null), REFILTER_POLICY.RE_FILTER))
        .thenThrow(new FetchException(FetchExceptionMode.DATA_NOT_FOUND));

    // Act
    element.updateState(false);

    // Assert
    String html = element.generate();
    assertTrue(html.contains("No fetcher found"), "renders fallback text when no fetcher exists");
    assertTrue(html.contains("error"), "renders error indicator when FetchException occurs");
  }

  @Test
  void updateState_whenNotInitialAndFinishedWithData_rendersOriginalImageAndClosesHandles()
      throws FetchException {
    // Arrange
    long maxSize = 321L;
    ImageElement element = ImageElement.createImageElement(tracker, key, maxSize, ctx, false);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.size()).thenReturn(123L);
    FProxyFetchResult result = newFinishedResultWithData(progress, bucket);

    when(tracker.makeFetcher(
            new FProxyFetchCriteria(key, maxSize, null), REFILTER_POLICY.RE_FILTER))
        .thenReturn(waiter);
    when(waiter.getResultFast()).thenReturn(result);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, null)))
        .thenReturn(progress);

    // Act
    element.updateState(false);
    HTMLNode jsSpan = requireChildByName(element, "span");

    // Assert
    HTMLNode img = requireChildByName(jsSpan, "img");
    assertEquals(key.toString(), img.getAttribute(ATTR_SRC));
    assertNull(findFirstChildByName(jsSpan, TAG_INPUT), "no progress inputs when finished");
    verify(progress, times(1)).close(waiter);
    verify(progress, times(1)).close(result);
  }

  @Test
  void updateState_whenNotInitialAndFailed_rendersOriginalImageAndClosesHandles()
      throws FetchException {
    // Arrange
    long maxSize = 321L;
    ImageElement element = ImageElement.createImageElement(tracker, key, maxSize, ctx, false);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    FetchException failure = new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
    FProxyFetchResult result = newProgressOrFailureResult(progress, 10, 1, failure);

    when(tracker.makeFetcher(
            new FProxyFetchCriteria(key, maxSize, null), REFILTER_POLICY.RE_FILTER))
        .thenReturn(waiter);
    when(waiter.getResultFast()).thenReturn(result);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, null)))
        .thenReturn(progress);

    // Act
    element.updateState(false);

    // Assert
    HTMLNode jsSpan = requireChildByName(element, "span");
    HTMLNode img = requireChildByName(jsSpan, "img");
    assertEquals(key.toString(), img.getAttribute(ATTR_SRC));
    assertNull(findFirstChildByName(jsSpan, TAG_INPUT), "no progress inputs when failed");
    verify(progress, times(1)).close(waiter);
    verify(progress, times(1)).close(result);
  }

  @Test
  void updateState_whenNotInitialAndInProgress_rendersPercentAndHiddenInputsAndClosesHandles()
      throws FetchException {
    // Arrange
    long maxSize = 321L;
    ImageElement element =
        ImageElement.createImageElement(
            tracker, key, maxSize, ctx, new ImageElementAttributes(12, 34, null), false);

    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    FProxyFetchResult result = newProgressOrFailureResult(progress, 20, 5, null);

    when(tracker.makeFetcher(
            new FProxyFetchCriteria(key, maxSize, null), REFILTER_POLICY.RE_FILTER))
        .thenReturn(waiter);
    when(waiter.getResultFast()).thenReturn(result);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, null)))
        .thenReturn(progress);

    // Act
    element.updateState(false);

    // Assert
    HTMLNode jsSpan = requireChildByName(element, "span");
    HTMLNode img = requireChildByName(jsSpan, "img");
    String src = img.getAttribute(ATTR_SRC);
    assertNotNull(src);
    assertTrue(src.contains("/imagecreator/?text=25%25"), "progress src contains percent");
    assertTrue(src.contains("&width=12&height=34"), "progress src includes size parameters");

    HTMLNode fetched = requireInputByName(jsSpan, "fetchedBlocks");
    assertEquals("5", fetched.getAttribute(ATTR_VALUE));
    HTMLNode required = requireInputByName(jsSpan, "requiredBlocks");
    assertEquals("20", required.getAttribute(ATTR_VALUE));

    verify(progress, times(1)).close(waiter);
    verify(progress, times(1)).close(result);
  }

  @Test
  void dispose_whenNoFetchInProgress_doesNothing() {
    // Arrange
    ImageElement element = ImageElement.createImageElement(tracker, key, 123L, ctx, false);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, null))).thenReturn(null);

    // Act
    element.dispose();

    // Assert
    verify(tracker, never()).run();
  }

  @Test
  void dispose_whenCancelable_requestsCancelAndRunsTracker() {
    // Arrange
    long maxSize = 123L;
    ImageElement element = ImageElement.createImageElement(tracker, key, maxSize, ctx, false);
    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    when(tracker.getFetchInProgress(new FProxyFetchCriteria(key, maxSize, null)))
        .thenReturn(progress);
    when(progress.canCancel()).thenReturn(true);

    // Act
    element.dispose();

    // Assert
    verify(progress, times(1)).removeListener(null);
    verify(progress, times(1)).requestImmediateCancel();
    verify(tracker, times(1)).run();
  }

  @Test
  void toString_includesKeyMaxSizeAndUpdaterId() {
    // Arrange
    ImageElement element = ImageElement.createImageElement(tracker, key, 123L, ctx, false);

    // Act
    String out = element.toString();

    // Assert
    assertTrue(out.contains("ImageElement[key:" + key), "includes key");
    assertTrue(out.contains("maxSize:123"), "includes maxSize");
    assertTrue(out.contains("updaterId:" + element.getUpdaterId(null)), "includes updater id");
  }

  private static HTMLNode requireChildByName(HTMLNode parent, String name) {
    HTMLNode child = findFirstChildByName(parent, name);
    assertNotNull(child, "Expected child <" + name + "> under <" + parent.getName() + ">");
    return child;
  }

  private static HTMLNode findFirstChildByName(HTMLNode parent, String name) {
    List<HTMLNode> children = parent.getChildren();
    for (HTMLNode child : children) {
      if (name.equals(child.getName())) {
        return child;
      }
    }
    return null;
  }

  private static HTMLNode requireInputByName(HTMLNode parent, String inputName) {
    for (HTMLNode child : parent.getChildren()) {
      if (TAG_INPUT.equals(child.getName()) && inputName.equals(child.getAttribute(ATTR_NAME))) {
        return child;
      }
    }
    throw new AssertionError("Expected <input name=\"" + inputName + "\">");
  }

  private static void setWasError(ImageElement element, boolean value) {
    try {
      Field field = ImageElement.class.getDeclaredField("wasError");
      field.setAccessible(true);
      field.setBoolean(element, value);
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to set ImageElement.wasError via reflection", e);
    }
  }

  private static FProxyFetchResult newFinishedResultWithData(
      FProxyFetchInProgress parent, Bucket bucket) {
    try {
      return RESULT_CTOR_FINISHED_WITH_DATA.newInstance(
          parent, bucket, new FProxyFetchSnapshotInfo("image/png", 1000L, true, 0L, false));
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to construct FProxyFetchResult (finished-with-data)", e);
    }
  }

  private static FProxyFetchResult newProgressOrFailureResult(
      FProxyFetchInProgress parent, int requiredBlocks, int fetchedBlocks, FetchException failure) {
    try {
      return RESULT_CTOR_PROGRESS_OR_FAILURE.newInstance(
          parent,
          new FProxyFetchSnapshotInfo("image/png", 1000L, true, 0L, false),
          -1L,
          new FProxyFetchProgressCounts(requiredBlocks, requiredBlocks, fetchedBlocks, 0, 0, false),
          failure);
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to construct FProxyFetchResult (progress-or-failure)", e);
    }
  }

  private static Constructor<FProxyFetchResult> getResultConstructorFinishedWithData() {
    try {
      Constructor<FProxyFetchResult> ctor =
          FProxyFetchResult.class.getDeclaredConstructor(
              FProxyFetchInProgress.class, Bucket.class, FProxyFetchSnapshotInfo.class);
      ctor.setAccessible(true);
      return ctor;
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to resolve FProxyFetchResult constructor (finished-with-data)", e);
    }
  }

  private static Constructor<FProxyFetchResult> getResultConstructorProgressOrFailure() {
    try {
      Constructor<FProxyFetchResult> ctor =
          FProxyFetchResult.class.getDeclaredConstructor(
              FProxyFetchInProgress.class,
              FProxyFetchSnapshotInfo.class,
              long.class,
              FProxyFetchProgressCounts.class,
              FetchException.class);
      ctor.setAccessible(true);
      return ctor;
    } catch (ReflectiveOperationException e) {
      throw linkageError(
          "Failed to resolve FProxyFetchResult constructor (progress-or-failure)", e);
    }
  }

  private static LinkageError linkageError(String message, ReflectiveOperationException e) {
    LinkageError error = new LinkageError(message);
    error.initCause(e);
    return error;
  }
}
