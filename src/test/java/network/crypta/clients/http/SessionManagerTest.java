package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import network.crypta.clients.http.SessionManager.Session;
import network.crypta.support.LRUMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SessionManagerTest {

  @Mock private ToadletContext context;

  @Test
  void constructor_withAbsolutePath_throwsIllegalArgumentException() {
    URI absolute = URI.create("http://example.com/path");

    assertThrows(IllegalArgumentException.class, () -> new SessionManager(absolute));
  }

  @Test
  void constructor_withPathWithoutLeadingSlash_throwsIllegalArgumentException() {
    URI relativeWithoutSlash = URI.create("relative");

    assertThrows(IllegalArgumentException.class, () -> new SessionManager(relativeWithoutSlash));
  }

  @Test
  void constructor_withInvalidNamespaceCharacters_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new SessionManager("name-with-dash"));
  }

  @Test
  void createSession_whenNewSession_setsCookieAndStoresSession() {
    SessionManager manager = new SessionManager("App");

    Session session = manager.createSession("user-1", context);

    ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
    verify(context).setCookie(cookieCaptor.capture());

    Cookie cookie = cookieCaptor.getValue();
    assertEquals(manager.getCookiePath(), cookie.getPath());
    assertEquals(expectedOutboundCookieName(manager), cookie.getName());
    assertEquals(session.getID().toString(), cookie.getValue());

    LRUMap<UUID, Session> sessionsById = sessionsById(manager);
    assertEquals(1, sessionsById.size());
    assertTrue(sessionsById.containsKey(session.getID()));
    assertEquals(session, sessionsById.get(session.getID()));
    assertEquals(session, sessionsByUser(manager).get(session.getUserID()));
  }

  @Test
  void createSession_whenSessionAlreadyExistsForUser_replacesOldSession() {
    SessionManager manager = new SessionManager("App");
    Session first = manager.createSession("dup-user", context);
    reset(context); // isolate second creation interactions

    Session second = manager.createSession("dup-user", context);

    LRUMap<UUID, Session> sessionsById = sessionsById(manager);
    assertEquals(1, sessionsById.size());
    assertFalse(sessionsById.containsKey(first.getID()));
    assertTrue(sessionsById.containsKey(second.getID()));
    assertEquals(second, sessionsByUser(manager).get("dup-user"));
  }

  @Test
  void sessionExists_whenInvalidUuidCookie_returnsFalse() throws Exception {
    SessionManager manager = new SessionManager("App");
    ReceivedCookie invalidCookie = mock(ReceivedCookie.class);
    when(invalidCookie.getValue()).thenReturn("not-a-uuid");
    lenient().when(context.getCookie(any(), any(), any())).thenReturn(invalidCookie);

    boolean exists = manager.sessionExists(context);

    assertFalse(exists);
    verify(context)
        .getCookie(isNull(), eq(manager.getCookiePath()), eq(expectedCookieName(manager)));
    verifyNoMoreInteractions(context);
  }

  @Test
  void sessionExists_whenExpiredSession_removesAndReturnsFalse() throws Exception {
    SessionManager manager = new SessionManager("App");
    Session session = manager.createSession("user-expire", context);
    long expiredTime = System.currentTimeMillis() - SessionManager.MAX_SESSION_IDLE_TIME - 1;
    setExpiration(session, expiredTime);
    ReceivedCookie cookie = mock(ReceivedCookie.class);
    when(cookie.getValue()).thenReturn(session.getID().toString());
    reset(context);
    lenient().when(context.getCookie(any(), any(), any())).thenReturn(cookie);

    boolean exists = manager.sessionExists(context);

    assertFalse(exists);
    assertEquals(0, sessionsById(manager).size());
    assertTrue(sessionsByUser(manager).isEmpty());
  }

  @Test
  void sessionExists_whenValidSession_returnsTrueWithoutRefreshingCookie() throws Exception {
    SessionManager manager = new SessionManager("App");
    Session session = manager.createSession("user-check", context);
    ReceivedCookie cookie = mock(ReceivedCookie.class);
    when(cookie.getValue()).thenReturn(session.getID().toString());
    reset(context);
    lenient().when(context.getCookie(any(), any(), any())).thenReturn(cookie);

    boolean exists = manager.sessionExists(context);

    assertTrue(exists);
    verify(context)
        .getCookie(isNull(), eq(manager.getCookiePath()), eq(expectedCookieName(manager)));
    verifyNoMoreInteractions(context);
  }

  @Test
  void useSession_whenValidSession_refreshesCookieAndReturnsSession() throws Exception {
    SessionManager manager = new SessionManager("App");
    Session session = manager.createSession("user-use", context);
    ReceivedCookie cookie = mock(ReceivedCookie.class);
    when(cookie.getValue()).thenReturn(session.getID().toString());
    reset(context);
    lenient().when(context.getCookie(any(), any(), any())).thenReturn(cookie);

    Session result = manager.useSession(context);

    assertNotNull(result);
    assertEquals(session.getID(), result.getID());
    verify(context)
        .getCookie(isNull(), eq(manager.getCookiePath()), eq(expectedCookieName(manager)));
    verify(context).setCookie(any(Cookie.class));
    verifyNoMoreInteractions(context);
  }

  @Test
  void deleteSession_whenCookieMatchesSession_removesSessionAndReturnsTrue() throws Exception {
    SessionManager manager = new SessionManager("App");
    Session session = manager.createSession("user-delete", context);
    ReceivedCookie cookie = mock(ReceivedCookie.class);
    when(cookie.getValue()).thenReturn(session.getID().toString());
    reset(context);
    lenient().when(context.getCookie(any(), any(), any())).thenReturn(cookie);

    boolean deleted = manager.deleteSession(context);

    assertTrue(deleted);
    assertEquals(0, sessionsById(manager).size());
    assertTrue(sessionsByUser(manager).isEmpty());
    verify(context)
        .getCookie(isNull(), eq(manager.getCookiePath()), eq(expectedCookieName(manager)));
    verifyNoMoreInteractions(context);
  }

  @Test
  void deleteSession_whenNoCookiePresent_returnsFalse() throws Exception {
    SessionManager manager = new SessionManager("App");
    boolean deleted = manager.deleteSession(context);

    assertFalse(deleted);
    verify(context)
        .getCookie(isNull(), eq(manager.getCookiePath()), eq(expectedCookieName(manager)));
    verifyNoMoreInteractions(context);
  }

  @Test
  void sessionAttributes_whenSetAndRemoved_behaveAsExpected() {
    SessionManager manager = new SessionManager("App");
    Session session = manager.createSession("user-attr", context);

    assertFalse(session.hasAttribute("k"));

    session.setAttribute("k", "v");
    assertTrue(session.hasAttribute("k"));
    assertEquals("v", session.getAttribute("k"));
    Set<String> names = session.getAttributeNames();
    assertEquals(Set.of("k"), names);

    session.removeAttribute("k");
    assertFalse(session.hasAttribute("k"));
    assertTrue(session.getAttributeNames().isEmpty());
  }

  private static String expectedCookieName(SessionManager manager) {
    return manager.getCookieNamespace().isEmpty()
        ? SessionManager.SESSION_COOKIE_NAME
        : manager.getCookieNamespace() + SessionManager.SESSION_COOKIE_NAME;
  }

  private static String expectedOutboundCookieName(SessionManager manager) {
    return expectedCookieName(manager).toLowerCase(Locale.ROOT);
  }

  @SuppressWarnings("unchecked")
  private static LRUMap<UUID, Session> sessionsById(SessionManager manager) {
    try {
      Field field = SessionManager.class.getDeclaredField("mSessionsByID");
      field.setAccessible(true);
      return (LRUMap<UUID, Session>) field.get(manager);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Session> sessionsByUser(SessionManager manager) {
    try {
      Field field = SessionManager.class.getDeclaredField("mSessionsByUserID");
      field.setAccessible(true);
      return (Map<String, Session>) field.get(manager);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void setExpiration(Session session, long timestampMillis) {
    try {
      Field field = Session.class.getDeclaredField("mExpiresAtTime");
      field.setAccessible(true);
      field.setLong(session, timestampMillis);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      throw new IllegalStateException(e);
    }
  }
}
