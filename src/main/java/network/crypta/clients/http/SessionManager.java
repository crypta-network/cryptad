package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.HOURS;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import network.crypta.support.LRUMap;
import network.crypta.support.StringValidityChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SessionManager coordinates cookie-backed HTTP sessions for the Crypta HTTP interface and its
 * plugins.
 *
 * <p>It maintains a strict 1:1 mapping between an opaque session ID and a user-provided user ID
 * while keeping lookups in both directions at constant time. A session ID is scoped by cookie path
 * and name, then backed by a random {@link UUID} stored in the browser. The manager enforces
 * exclusivity per user: creating a new session for the same user removes the previous one to
 * prevent concurrent logins. The time-to-idle policy expires sessions after {@link
 * #MAX_SESSION_IDLE_TIME} of inactivity and refreshes them on validated access. All public entry
 * points are synchronized to guard the internal LRU cache and ensure the eviction order matches
 * access time.
 *
 * <p>Use the path-based constructor when cookies should only be returned for a subtree of the HTTP
 * interface. Use the namespace-based constructor when multiple applications share the root path;
 * namespacing prefixes the cookie name to avoid collisions while still receiving cookies for all
 * requests under "/".
 *
 * <ul>
 *   <li>Responsibilities: issuing session IDs, validating cookies, expiring idle entries.
 *   <li>Thread-safety: all public methods synchronize on the instance; individual Session objects
 *       rely on caller synchronization via the enclosing manager.
 *   <li>Lifecycle: sessions are created on demand, refreshed on {@link
 *       #useSession(ToadletContext)}, and lazily purged when clients next interact.
 * </ul>
 *
 * @see SessionManager.Session
 * @see ToadletContext
 * @author xor (xor@freenetproject.org)
 */
public final class SessionManager {
  private static final Logger LOG = LoggerFactory.getLogger(SessionManager.class);

  /**
   * Maximum idle time in milliseconds before a session is considered expired and purged lazily; by
   * default this is one hour, enforcing short-lived browser sessions without persistent storage.
   */
  public static final long MAX_SESSION_IDLE_TIME = HOURS.toMillis(1);

  /**
   * Base cookie name used when no namespace is provided; combined with a namespace when present to
   * keep cookies distinct across co-hosted applications while preserving recognizable identifiers.
   */
  public static final String SESSION_COOKIE_NAME = "SessionID";

  private final URI mCookiePath;
  private final String mCookieNamespace;
  private final String mCookieName;

  /**
   * Constructs a new session manager that restricts cookies to the supplied path segment.
   *
   * <p>The path must be relative and start with {@code /}; absolute URIs are rejected to avoid
   * leaking cookies across hosts. Browsers will only present the issued session cookie when the
   * current request path is equal to or beneath the configured path, making this constructor
   * suitable for client interfaces that live in a dedicated subtree. The underlying cookie name is
   * {@link #SESSION_COOKIE_NAME}; no namespace prefix is added when this constructor is used.
   *
   * @param myCookiePath relative path beginning with {@code /} where the cookie remains valid
   */
  public SessionManager(URI myCookiePath) {
    if (myCookiePath.isAbsolute())
      throw new IllegalArgumentException("Illegal cookie path, must be relative: " + myCookiePath);

    if (!myCookiePath.toString().startsWith("/"))
      throw new IllegalArgumentException("Illegal cookie path, must start with /: " + myCookiePath);

    // Legacy global-path cookies are intentionally allowed for backward compatibility with plugins
    // that still rely on the root path.

    mCookiePath = myCookiePath;
    mCookieNamespace = "";
    mCookieName = SESSION_COOKIE_NAME;
  }

  /**
   * Constructs a new session manager that uses the root path and a namespace-prefixed cookie name.
   *
   * <p>Namespaces let multiple applications share the same HTTP origin while keeping sessions
   * isolated; the namespace is prepended to {@link #SESSION_COOKIE_NAME}. The parameter must be
   * non-empty and limited to Latin letters and digits to ensure it is safe for cookie names and
   * logging. Cookies issued by this manager are sent for all request paths because the cookie path
   * is fixed to {@code /}.
   *
   * @param myCookieNamespace non-empty ASCII alphanumeric token that prefixes the cookie name
   */
  public SessionManager(String myCookieNamespace) {
    if (myCookieNamespace.isEmpty())
      throw new IllegalArgumentException(
          "You must specify a cookie namespace or use the constructor "
              + "which allows specification of a cookie path.");

    if (!StringValidityChecker.isLatinLettersAndNumbersOnly(myCookieNamespace))
      throw new IllegalArgumentException(
          "The cookie namespace must be latin letters and numbers only.");

    try {
      mCookiePath = new URI("/");
    } catch (URISyntaxException e) {
      throw new IllegalStateException("Unexpected failure creating root URI", e);
    }
    mCookieNamespace = myCookieNamespace;
    mCookieName = myCookieNamespace + SESSION_COOKIE_NAME;
  }

  /**
   * Represents an individual HTTP session issued by {@link SessionManager} and stored in a browser
   * cookie.
   *
   * <p>A Session bundles the random {@link UUID} sent to the client, the stable user ID supplied by
   * the caller, and an arbitrary attribute map for request-scoped state. Expiration is tracked as a
   * time-to-idle timestamp and refreshed when the session is successfully reused. Instances are
   * created only through {@link #createSession(String, ToadletContext)}; equality and hash code are
   * based solely on the session ID to make them reliable map keys. Mutability is limited to
   * attribute storage and expiration updates. Concurrency is managed by the enclosing manager: the
   * Session type itself performs no synchronization.
   */
  public static final class Session {

    private final UUID mID;
    private final String mUserID;
    private final Map<String, Object> mAttributes = new HashMap<>();

    private long mExpiresAtTime;

    private Session(String myUserID, long currentTime) {
      mID = UUID.randomUUID();
      mUserID = myUserID;
      mExpiresAtTime = currentTime + SessionManager.MAX_SESSION_IDLE_TIME;
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == null) return false;
      if (!(obj instanceof Session other)) return false;
      return other.getID().equals(mID);
    }

    @Override
    public int hashCode() {
      return mID.hashCode();
    }

    /**
     * Returns the immutable identifier assigned to this session when it was created.
     *
     * <p>The identifier is a randomly generated {@link UUID} and serves as the value stored in the
     * session cookie. It never changes for the lifetime of the session and is unique enough to be
     * safely used as the primary key in the manager's maps. Callers may log or compare the value,
     * but should not attempt to interpret or reconstruct it. The ID becomes invalid once the
     * session expires or is explicitly removed.
     *
     * @return unique, stable UUID that backs the cookie and map lookups for this session
     */
    public UUID getID() {
      return mID;
    }

    /**
     * Returns the user identifier associated with this session.
     *
     * <p>The value is supplied by the caller of {@link SessionManager#createSession(String,
     * ToadletContext)} and remains stable throughout the session lifetime. It is not transformed or
     * validated beyond what the manager already performed at creation time. The string may be used
     * for authorization decisions or UI display, but it is not guaranteed to be unique outside the
     * managing instance, so consumers should scope comparisons accordingly.
     *
     * @return application-defined user ID bound to this session and never modified by the session
     */
    public String getUserID() {
      return mUserID;
    }

    private long getExpirationTime() {
      return mExpiresAtTime;
    }

    private boolean isExpired(long time) {
      return time >= mExpiresAtTime;
    }

    private void updateExpiresAtTime(long currentTime) {
      mExpiresAtTime = currentTime + SessionManager.MAX_SESSION_IDLE_TIME;
    }

    /**
     * Checks whether an attribute with the provided name is present in this session.
     *
     * <p>Attributes are stored in a simple in-memory map and are not persisted beyond the lifetime
     * of the session. Lookups are case-sensitive and treat {@code null} names the same way as any
     * other map key. Use this method when you need to branch on optional values without triggering
     * a retrieval or default computation. The call is constant-time and does not alter the session
     * state or expiration timer.
     *
     * @param name attribute key to test; expected to be non-null and meaningful to the caller
     * @return {@code true} when an entry exists for the key; {@code false} otherwise
     */
    public boolean hasAttribute(String name) {
      return mAttributes.containsKey(name);
    }

    /**
     * Retrieves the value stored under the provided attribute name.
     *
     * <p>When no entry exists, this method returns {@code null} without creating one. Attribute
     * values are stored as raw {@link Object} instances; callers are responsible for casting to the
     * expected type. The map permits {@code null} values, so callers should distinguish between
     * absence and explicit null where necessary, possibly by pairing with {@link
     * #hasAttribute(String)}. Access does not refresh the parent session's expiration timer and is
     * safe to call repeatedly.
     *
     * @param name attribute key whose value should be retrieved; typically non-null and stable
     * @return stored attribute value or {@code null} when missing or explicitly set to {@code null}
     */
    public Object getAttribute(String name) {
      return mAttributes.get(name);
    }

    /**
     * Stores or replaces an attribute under the provided name.
     *
     * <p>The value may be any {@link Object}, including {@code null}; storing {@code null}
     * deliberately distinguishes between an explicit null payload and a missing entry. Repeated
     * calls with the same name overwrite the previous value. Attribute updates do not touch the
     * session's expiration counter; refreshing idle time still requires {@link
     * SessionManager#useSession(ToadletContext)}. Callers should avoid storing large mutable
     * objects because Session instances are kept entirely in memory.
     *
     * @param name attribute key to insert or overwrite; should be non-null and consistent
     * @param value attribute payload to associate with the key; may be {@code null}
     */
    public void setAttribute(String name, Object value) {
      mAttributes.put(name, value);
    }

    /**
     * Removes any attribute stored under the specified name.
     *
     * <p>If no mapping exists, the call is a no-op. Removing an attribute frees the entry from the
     * in-memory map but does not alter session expiration or other state. Use this method when
     * clearing sensitive or temporary data after it is no longer needed, or before reusing the key
     * for a different type. The operation returns immediately and does not signal whether a value
     * was present beforehand.
     *
     * @param name attribute key to delete; treated exactly as the key originally stored
     */
    public void removeAttribute(String name) {
      mAttributes.remove(name);
    }

    /**
     * Lists the names of all attributes currently stored on this session.
     *
     * <p>The returned set is backed directly by the internal map, so modifications to the set will
     * affect the stored attributes. Callers that need an immutable snapshot should copy the set
     * before iterating. Names reflect exactly what was supplied to {@link #setAttribute(String,
     * Object)}; no normalization is performed. The set may be empty when no attributes have been
     * defined, or after they were removed.
     *
     * @return live view of attribute keys present on this session; may be empty but never null
     */
    public Set<String> getAttributeNames() {
      return mAttributes.keySet();
    }
  }

  private final LRUMap<UUID, Session> mSessionsByID = new LRUMap<>();
  private final Map<String, Session> mSessionsByUserID = new HashMap<>();

  /**
   * Exposes the cookie path configured for this manager.
   *
   * <p>For namespace-based managers the path is always {@code /}, enabling cookies to accompany all
   * requests. For path-based managers, the value corresponds to the constructor argument and limits
   * when browsers return the session cookie. The path is immutable after construction, so callers
   * can cache the value when building HTTP responses or diagnostics. It does not include the cookie
   * name or namespace; it is solely the path restriction recognized by the browser.
   *
   * @return immutable cookie path URI used when issuing and parsing session cookies
   */
  public URI getCookiePath() {
    return mCookiePath;
  }

  /**
   * Returns the cookie namespace associated with this manager, or an empty string when unused.
   *
   * <p>The namespace, when provided, prefixes the cookie name to isolate sessions among multiple
   * applications sharing the same origin. Namespace selection happens at construction time and
   * cannot be altered later. Callers may incorporate the namespace into logging or UI labels to
   * clarify which application issued the cookie. An empty string indicates the manager was created
   * with the path-specific constructor and therefore uses the unprefixed {@link
   * #SESSION_COOKIE_NAME}.
   *
   * @return namespace prefix for cookie names, or empty when none is configured
   */
  public String getCookieNamespace() {
    return mCookieNamespace;
  }

  /**
   * Creates a new session for the supplied user ID and writes the cookie to the response context.
   *
   * <p>If the user already has an active session, that session is removed before generating a new
   * identifier, preventing parallel logins for the same account across devices. The method also
   * purges any expired sessions, assigns a fresh {@link Session}, stores it in both lookup tables,
   * and emits a cookie scoped to this manager's path and namespace. Calls are synchronized to keep
   * LRU ordering consistent with the captured timestamp used for expiration refresh.
   *
   * @param userID caller-supplied user identifier to bind to the new session
   * @param context request/response context whose cookies will carry the new session identifier
   * @return newly created Session object representing the issued credentials
   */
  public synchronized Session createSession(String userID, ToadletContext context) {
    // We must synchronize around the fetching of the time and mSessionsByID.push() because
    // mSessionsByID is no sorting data structure: It's a plain
    // LRUMap so to ensure that it stays sorted the operation "getTime(); push();" must be atomic.
    long time = System.currentTimeMillis();

    removeExpiredSessions(time);

    deleteSessionByUserID(userID);

    Session session = new Session(userID, time);
    mSessionsByID.push(session.getID(), session);
    mSessionsByUserID.put(session.getUserID(), session);

    setSessionCookie(session, context);

    return session;
  }

  /**
   * Checks whether the provided context holds a cookie for a currently valid session.
   *
   * <p>This method is intended for lightweight "peek" operations such as deciding whether to show
   * authenticated UI controls. It does not refresh the idle timer or modify cookies; it merely
   * validates that the cookie maps to an existing, non-expired {@link Session}. Expired sessions
   * are purged before the check to avoid false positives. The call is synchronized to maintain
   * consistent cache state during expiration cleanup.
   *
   * @param context HTTP toadlet context whose cookies should be inspected for a session identifier
   * @return {@code true} when a non-expired session exists for the cookie; {@code false} otherwise
   */
  public synchronized boolean sessionExists(ToadletContext context) {
    UUID sessionID = getSessionID(context);

    if (sessionID == null) return false;

    removeExpiredSessions(System.currentTimeMillis());

    return mSessionsByID.containsKey(sessionID);
  }

  /**
   * Retrieves and refreshes a session based on the cookie stored in the given context.
   *
   * <p>The method resolves the session ID from the cookies, discards expired entries, and returns
   * the corresponding {@link Session} when found. Successful lookups extend the expiration window
   * by {@link #MAX_SESSION_IDLE_TIME} and reissue the cookie with the updated expiry to keep the
   * browser in sync. When no valid session exists, {@code null} is returned and no cookies are
   * modified. Synchronization ensures that LRU ordering and expiration timestamps remain coherent.
   *
   * @param context HTTP toadlet context from which to read and to which to rewrite the session
   *     cookie
   * @return live Session when the cookie maps to a valid entry; {@code null} if missing or expired
   */
  public synchronized Session useSession(ToadletContext context) {
    UUID sessionID = getSessionID(context);
    if (sessionID == null) return null;

    // We must synchronize around the fetching of the time and mSessionsByID.push() because
    // mSessionsByID is no sorting data structure: It's a plain
    // LRUMap so to ensure that it stays sorted the operation "getTime(); push();" must be atomic.
    long time = System.currentTimeMillis();

    removeExpiredSessions(time);

    Session session = mSessionsByID.get(sessionID);

    if (session == null) return null;

    session.updateExpiresAtTime(time);
    mSessionsByID.push(session.getID(), session);

    setSessionCookie(session, context);

    return session;
  }

  /**
   * Deletes the session referenced by the cookie in the provided context, if present and valid.
   *
   * <p>The method resolves the session ID from the incoming cookies, validates existence, and
   * removes the session from both lookup tables. Expired sessions are silently ignored. Cookies in
   * the context are not cleared here; callers can choose whether to overwrite them after deletion.
   * This is useful for logout flows that should not extend idle timers.
   *
   * @param context HTTP toadlet context supplying the cookie that identifies the session to remove
   * @return {@code true} when a matching session existed and was removed; {@code false} otherwise
   */
  public boolean deleteSession(ToadletContext context) {
    UUID sessionID = getSessionID(context);
    if (sessionID == null) return false;

    return deleteSession(sessionID);
  }

  /**
   * @return Returns the session ID stored in the cookies of the HTTP headers of the given {@link
   *     ToadletContext}. Returns null if there is no session ID stored.
   */
  private UUID getSessionID(ToadletContext context) {
    if (context == null) return null;

    try {
      ReceivedCookie sessionCookie = context.getCookie(null, mCookiePath, mCookieName);

      return sessionCookie == null ? null : UUID.fromString(sessionCookie.getValue());
    } catch (ParseException | IllegalArgumentException e) {
      LOG.error("Getting session cookie failed", e);
      return null;
    }
  }

  /**
   * Stores a session cookie for the given session in the given {@link ToadletContext}'s HTTP
   * headers.
   *
   * @param session The session to create a cookie for
   * @param context The context to store the cookie in
   */
  private void setSessionCookie(Session session, ToadletContext context) {
    context.setCookie(
        new Cookie(
            mCookiePath,
            mCookieName,
            session.getID().toString(),
            new Date(session.getExpirationTime())));
  }

  /**
   * Deletes the session with the given ID.
   *
   * @return True if a session with the given ID existed.
   */
  private synchronized boolean deleteSession(UUID sessionID) {
    Session session = mSessionsByID.get(sessionID);

    if (session == null) return false;

    mSessionsByID.removeKey(sessionID);
    mSessionsByUserID.remove(session.getUserID());
    return true;
  }

  /** Deletes the session associated with the given user ID. */
  private synchronized void deleteSessionByUserID(String userID) {
    Session session = mSessionsByUserID.remove(userID);
    if (session == null) return;

    mSessionsByID.removeKey(session.getID());
  }

  /**
   * Garbage-collects any expired sessions. Must be called before client-interface functions do
   * anything which relies on the existence a session, that is: creating sessions, using sessions or
   * checking whether sessions exist.
   *
   * <p>Sessions are garbage-collected lazily when clients interact with the SessionManager; if no
   * client activity occurs, expired sessions remain until the next access. A periodic collector
   * could be added if this becomes an issue.
   *
   * @param time The current time.
   */
  private synchronized void removeExpiredSessions(long time) {
    for (Session session = mSessionsByID.peekValue();
        session != null && session.isExpired(time);
        session = mSessionsByID.peekValue()) {
      mSessionsByID.popValue();
      mSessionsByUserID.remove(session.getUserID());
    }

    // This debug check runs on each call; optimize to a periodic run if it proves expensive.
    verifySessionsByUserIDTable();
  }

  /**
   * Debug function which checks whether the sessions by user ID table does not contain any sessions
   * which do not exist anymore;
   */
  private synchronized void verifySessionsByUserIDTable() {

    Iterator<Session> sessions = mSessionsByUserID.values().iterator();
    while (sessions.hasNext()) {
      Session session = sessions.next();

      if (!mSessionsByID.containsKey(session.getID())) {
        LOG.error(
            "Sessions by user ID hashtable contains deleted session, removing it: {}", session);

        sessions.remove();
      }
    }
  }
}
