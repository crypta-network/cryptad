package network.crypta.clients.http.updateableelements;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.IllegalBase64Exception;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming convention: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class TesterElementTest {

  private static final String REQUEST_ID = "request-123";
  private static final String ELEMENT_ID = "element-abc";

  @Mock private ToadletContext ctx;
  @Mock private SimpleToadletServer server;
  @Mock private PushDataManager pushDataManager;

  @Test
  void getId_whenGivenRequestAndElementId_expectDecodesToStableTokenWithComponents()
      throws IllegalBase64Exception {
    // Arrange
    String requestId = "req";
    String elementId = "el";

    // Act
    String encodedA = TesterElement.getId(requestId, elementId);
    String encodedB = TesterElement.getId(requestId, elementId);
    String decoded = new String(Base64.decodeStandard(encodedA), StandardCharsets.UTF_8);

    // Assert
    assertEquals(encodedA, encodedB);
    assertTrue(decoded.startsWith("test:" + requestId + "id:" + elementId));
  }

  @Test
  void
      constructor_whenCreated_expectSetsAttributesRendersInitialStateAndRegistersWithPushManager() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> timerConstruction = mockConstruction(Timer.class)) {
      // Act
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 2);

      // Assert (HTML attributes)
      assertEquals("div", element.getName());
      assertEquals("float:left;", element.getAttribute("style"));
      assertEquals(element.getUpdaterId(REQUEST_ID), element.getAttribute("id"));

      // Assert (initial children from updateState(true))
      List<HTMLNode> children = element.getChildren();
      assertEquals(1, children.size());
      HTMLNode img = children.getFirst();
      assertEquals("img", img.getName());
      assertEquals("/imagecreator/?text=0&width=30&height=30", img.getAttribute("src"));

      // Assert (push manager registration from BaseUpdatableElement.init(true))
      verify(pushDataManager).elementRendered(eq(REQUEST_ID), same(element));
      verifyNoMoreInteractions(pushDataManager);

      // Assert (timer wiring)
      assertEquals(1, timerConstruction.constructed().size());
      Timer timer = timerConstruction.constructed().getFirst();
      verify(timer).scheduleAtFixedRate(any(TimerTask.class), eq(0L), eq(1000L));
    }
  }

  @Test
  void constructor_whenTimerCreated_expectUsesDaemonTimer() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> timerConstruction =
        mockConstruction(
            Timer.class,
            (mock, context) -> assertEquals(List.of(true), List.copyOf(context.arguments())))) {
      // Act
      new TesterElement(ctx, ELEMENT_ID, 1);

      // Assert
      assertEquals(1, timerConstruction.constructed().size());
    }
  }

  @Test
  void getUpdaterId_whenCalled_expectDelegatesToStaticGetId() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> ignored = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 1);

      // Act
      String updaterId = element.getUpdaterId("rid");

      // Assert
      assertEquals(TesterElement.getId("rid", ELEMENT_ID), updaterId);
    }
  }

  @Test
  void getUpdaterType_whenCalled_expectReplacerUpdater() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> ignored = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 1);

      // Act
      String type = element.getUpdaterType();

      // Assert
      assertEquals(UpdaterConstants.REPLACER_UPDATER, type);
    }
  }

  @Test
  void update_whenBelowMaxStatus_expectNotifiesPushManagerAndDoesNotCancelTimer() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> timerConstruction = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 3);
      Timer timer = timerConstruction.constructed().getFirst();
      clearInvocations(timer, pushDataManager);

      // Act
      element.update();
      element.updateState(false);

      // Assert (state advanced)
      HTMLNode img = element.getChildren().getFirst();
      assertEquals("/imagecreator/?text=1&width=31&height=31", img.getAttribute("src"));

      // Assert (push notification)
      verify(pushDataManager).updateElement(element.getUpdaterId(REQUEST_ID));
      verifyNoMoreInteractions(pushDataManager);

      // Assert (timer not canceled yet)
      verifyNoMoreInteractions(timer);
    }
  }

  @Test
  void update_whenReachesMaxStatus_expectCancelsTimerAndNotifiesPushManager() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> timerConstruction = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 1);
      Timer timer = timerConstruction.constructed().getFirst();
      clearInvocations(timer, pushDataManager);

      // Act
      element.update();

      // Assert
      verify(timer).cancel();
      verify(pushDataManager).updateElement(element.getUpdaterId(REQUEST_ID));
      verifyNoMoreInteractions(timer, pushDataManager);
    }
  }

  @Test
  void dispose_whenCalled_expectCancelsTimer() {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> timerConstruction = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 1);
      Timer timer = timerConstruction.constructed().getFirst();
      clearInvocations(timer);

      // Act
      element.dispose();

      // Assert
      verify(timer).cancel();
      verifyNoMoreInteractions(timer);
    }
  }

  @Test
  void updateState_whenStatusLarge_expectCapsWidthAndHeightAndReplacesChildren()
      throws ReflectiveOperationException {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> ignored = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 999);
      element.addChild(new HTMLNode("span", "old"));
      setStatus(element, 500);

      // Act
      element.updateState(false);

      // Assert
      assertEquals(1, element.getChildren().size());
      HTMLNode img = element.getChildren().getFirst();
      assertEquals("/imagecreator/?text=500&width=300&height=300", img.getAttribute("src"));
    }
  }

  @Test
  void updateState_whenStatusBelowCap_expectUsesStatusPlus30ForWidthAndHeight()
      throws ReflectiveOperationException {
    // Arrange
    stubContext();

    try (MockedConstruction<Timer> ignored = mockConstruction(Timer.class)) {
      TesterElement element = new TesterElement(ctx, ELEMENT_ID, 999);
      setStatus(element, 250);

      // Act
      element.updateState(false);

      // Assert
      assertEquals(1, element.getChildren().size());
      HTMLNode img = element.getChildren().getFirst();
      assertEquals("/imagecreator/?text=250&width=280&height=280", img.getAttribute("src"));
    }
  }

  private void stubContext() {
    when(ctx.getUniqueId()).thenReturn(REQUEST_ID);
    when(ctx.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
  }

  @SuppressWarnings("java:S3011") // Test helper uses reflection to access private state.
  private static void setStatus(TesterElement element, int newStatus)
      throws ReflectiveOperationException {
    Field statusField = TesterElement.class.getDeclaredField("status");
    statusField.setAccessible(true);
    statusField.setInt(element, newStatus);
  }
}
