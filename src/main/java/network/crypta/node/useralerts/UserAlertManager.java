package network.crypta.node.useralerts;

import static java.util.Arrays.stream;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Manages the lifecycle, ordering, and presentation of {@link UserAlert} instances for a node.
 *
 * <p>This class registers and unregisters alerts, keeps the latest {@link UserEvent} per event
 * type, and exposes rendering helpers for HTML summaries and Atom feed output. Typical usage is to
 * create one manager per {@link NodeClientCore}, register alerts as they occur, and query snapshots
 * for rendering in web or FCP contexts. Alerts are stored in a mutable set and sorted on demand
 * using a deterministic comparator, so callers should treat returned arrays as snapshots.
 *
 * <p>Concurrency: registration and state updates synchronize on internal collections, while
 * subscriber notifications are dispatched asynchronously to avoid blocking alert updates. The
 * manager is mutable and not thread-safe for external iteration; call {@link #getAlerts()} to
 * obtain a stable array.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Maintaining alert and event registries with dismissal semantics
 *   <li>Generating HTML fragments and summary lines for UI integration
 *   <li>Producing an Atom feed that mirrors the current alert state
 * </ul>
 *
 * @see UserAlert
 * @see UserEvent
 */
public class UserAlertManager implements Comparator<UserAlert> {
  private static final Logger LOG = LoggerFactory.getLogger(UserAlertManager.class);
  private static final char PATH_SEPARATOR = '/';
  private static final String ALERTS_PATH_SEGMENT = "alerts";
  private static final String ALERTS_PATH = PATH_SEPARATOR + ALERTS_PATH_SEGMENT + PATH_SEPARATOR;
  private static final String ALERT_LEVEL_ERROR = "error";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_VALUE = "value";
  private static final String INPUT_TAG = "input";
  private static final String INPUT_TYPE_HIDDEN = "hidden";

  // No point keeping them sorted as some alerts can change priority.
  private final Set<UserAlert> alerts;
  private final NodeClientCore core;
  private final Set<FCPConnectionHandler> subscribers;
  private final Map<UserEvent.Type, UserEvent> events;
  private final Set<UserEvent.Type> unregisteredEventTypes;
  private long lastUpdated;

  /**
   * Creates a manager bound to the given core and initializes empty alert state.
   *
   * <p>The manager stores alerts in mutable collections, tracks the most recent update time, and
   * prepares to notify FCP subscribers asynchronously. Callers should typically construct this once
   * during node startup and reuse it for the lifetime of the {@link NodeClientCore}.
   *
   * @param core the owning core used for executors, localization, and passwords
   */
  public UserAlertManager(NodeClientCore core) {
    this.core = core;
    alerts = new HashSet<>();
    subscribers = new CopyOnWriteArraySet<>();
    events = new EnumMap<>(UserEvent.Type.class);
    unregisteredEventTypes = new HashSet<>();
    lastUpdated = System.currentTimeMillis();
  }

  /**
   * Registers a new alert and notifies subscribers if it is newly added.
   *
   * <p>If the alert is also a {@link UserEvent}, this method delegates to {@link
   * #register(UserEvent)} to enforce the "latest event only" invariant. For non-event alerts,
   * registration is idempotent: the alert is added only if it is not already present. Successful
   * registration updates the manager timestamp and schedules asynchronous FCP notifications.
   *
   * @param alert the alert to register; must be a non-null alert instance
   */
  public void register(UserAlert alert) {
    if (alert instanceof UserEvent event) register(event);
    synchronized (alerts) {
      if (!alerts.contains(alert)) {
        alerts.add(alert);
        lastUpdated = System.currentTimeMillis();
        notifySubscribers(alert);
      }
    }
  }

  /**
   * Registers an event alert, replacing any previously registered event of the same type.
   *
   * <p>Events are treated specially: only the newest {@link UserEvent} for a given type is kept in
   * the alerts list. If the event type has been permanently unregistered, this call is ignored.
   * Registration updates the timestamp and sends an asynchronous FCP notification to subscribers.
   *
   * @param event the event to register; its type determines replacement behavior
   */
  public void register(UserEvent event) {
    // The event is ignored if it has been indefinitely unregistered
    synchronized (unregisteredEventTypes) {
      if (unregisteredEventTypes.contains(event.getEventType())) return;
    }
    // Only the latest event is displayed as an alert
    synchronized (events) {
      UserEvent lastEvent = events.get(event.getEventType());
      synchronized (alerts) {
        if (lastEvent != null) alerts.remove(lastEvent);
        alerts.add(event);
      }
      events.put(event.getEventType(), event);
      lastUpdated = System.currentTimeMillis();
      notifySubscribers(event);
    }
  }

  private void notifySubscribers(final UserAlert alert) {
    // Run off-thread, because of locking, and because client
    // callbacks may take some time
    core.getClientContext()
        .getMainExecutor()
        .execute(
            () -> {
              for (FCPConnectionHandler subscriber : subscribers)
                subscriber.send(alert.getFCPMessage());
            },
            "UserAlertManager callback executor");
  }

  /**
   * Unregisters a non-event alert or forwards to event-type unregistration.
   *
   * <p>If the alert is a {@link UserEvent}, this method delegates to {@link
   * #unregister(UserEvent.Type)} to enforce the event registry rules. For other alerts, it simply
   * removes the alert from the internal set. Passing {@code null} is a no-op. This method does not
   * invoke {@link UserAlert#onDismiss()} or alter the alert's validity flag.
   *
   * @param alert the alert to remove from the active alert set, or {@code null}
   */
  public void unregister(UserAlert alert) {
    if (alert == null) return;
    if (alert instanceof UserEvent event) unregister(event.getEventType());
    synchronized (alerts) {
      alerts.remove(alert);
    }
  }

  /**
   * Unregisters the latest event alert for the given event type.
   *
   * <p>If the event type supports indefinite unregistration, the type is remembered so future
   * events of the same type are ignored. Any existing alert for the type is removed from both the
   * event registry and the alert set. This method is safe to call even if the event type is not
   * currently registered.
   *
   * @param eventType the event type to remove and optionally disable permanently
   */
  public void unregister(UserEvent.Type eventType) {
    if (eventType.unregisterIndefinitely())
      synchronized (unregisteredEventTypes) {
        unregisteredEventTypes.add(eventType);
      }
    synchronized (events) {
      UserEvent latestEvent;
      latestEvent = events.remove(eventType);
      if (latestEvent != null)
        synchronized (alerts) {
          alerts.remove(latestEvent);
        }
    }
  }

  /**
   * Dismisses a user-dismissable alert that matches the provided hash code.
   *
   * <p>This method scans the current snapshot of alerts and checks each candidate for matching
   * {@code hashCode} as well as {@link UserAlert#userCanDismiss()}. When a match is found, it
   * applies the alert's dismissal policy: alerts that request unregistration are removed and have
   * their {@link UserAlert#onDismiss()} callback invoked; others are simply marked invalid. The
   * operation is best-effort and ignores non-dismissable alerts.
   *
   * @param alertHashCode the hash code identifying the alert to dismiss
   * @see #unregister(UserAlert)
   */
  public void dismissAlert(int alertHashCode) {
    UserAlert[] userAlerts = getAlerts();
    for (UserAlert userAlert : userAlerts) {
      if (userAlert.hashCode() != alertHashCode || !userAlert.userCanDismiss()) {
        continue;
      }
      if (userAlert.shouldUnregisterOnDismiss()) {
        userAlert.onDismiss();
        unregister(userAlert);
      } else {
        userAlert.isValid(false);
      }
    }
  }

  /**
   * Returns a sorted snapshot of all current alerts.
   *
   * <p>The returned array is a stable snapshot at the time of call and is sorted using the manager
   * comparator. It is safe for callers to iterate without holding locks, but the snapshot will not
   * reflect subsequent registrations or dismissals. Callers should not mutate or retain elements
   * expecting live updates.
   *
   * @return a newly allocated array sorted by alert priority and recency
   */
  public UserAlert[] getAlerts() {
    UserAlert[] a;
    synchronized (alerts) {
      a = alerts.toArray(new UserAlert[0]);
    }
    Arrays.sort(a, this);
    return a;
  }

  /**
   * Orders alerts by priority, event status, class hash, update time, and hash code.
   *
   * <p>Higher-priority alerts (lower numeric priority class) come first. Non-event alerts are
   * ordered before event notifications, then by class hash for stable grouping, followed by
   * descending updated time, and finally by {@code hashCode} to break remaining ties. This
   * comparator is consistent with identity checks and provides deterministic ordering for
   * snapshots.
   *
   * @param a0 the first alert to compare; must be a non-null alert
   * @param a1 the second alert to compare; must be a non-null alert
   * @return a negative, zero, or positive value per the ordering described above
   */
  @Override
  public int compare(UserAlert a0, UserAlert a1) {
    if (a0 == a1)
      return 0; // common case, also we should be consistent with == even with proxyuseralert's
    int priorityComparison = Short.compare(a0.getPriorityClass(), a1.getPriorityClass());
    if (priorityComparison != 0) {
      return priorityComparison;
    }
    int eventComparison = compareEventNotifications(a0, a1);
    if (eventComparison != 0) {
      return eventComparison;
    }
    int classComparison = Integer.compare(a0.getClass().hashCode(), a1.getClass().hashCode());
    if (classComparison != 0) {
      return classComparison;
    }
    int timeComparison = Long.compare(a1.getUpdatedTime(), a0.getUpdatedTime());
    if (timeComparison != 0) {
      return timeComparison;
    }
    return Integer.compare(a0.hashCode(), a1.hashCode());
  }

  private int compareEventNotifications(UserAlert a0, UserAlert a1) {
    boolean isEvent0 = a0.isEventNotification();
    boolean isEvent1 = a1.isEventNotification();
    if (isEvent0 == isEvent1) {
      return 0;
    }
    return isEvent0 ? 1 : -1;
  }

  /**
   * Creates an HTML fragment containing only error-level alerts.
   *
   * <p>This convenience overload delegates to {@link #createAlerts(boolean)} with {@code
   * showOnlyErrors=true}. It is commonly used by status views that want to avoid rendering
   * lower-severity information, while still providing a consistent HTML structure.
   *
   * @return an HTML node containing error-level alerts, or an empty marker node
   */
  @SuppressWarnings("unused")
  public HTMLNode createAlerts() {
    return createAlerts(true);
  }

  /**
   * Renders alert entries as an HTML container.
   *
   * <p>The container includes anchors for each alert, with content generated by {@link
   * #renderAlert(UserAlert)}. When {@code showOnlyErrors} is true, the method only renders alerts
   * at or above {@link UserAlert#ERROR}, and it guards rendering with a catch-all to avoid breaking
   * the UI when an alert misbehaves. When false, all valid alerts are rendered and exceptions are
   * allowed to propagate.
   *
   * @param showOnlyErrors whether to include only error-level alerts in the output
   * @return the root HTML node for the rendered alerts, or an empty marker node
   */
  public HTMLNode createAlerts(boolean showOnlyErrors) {
    HTMLNode alertsNode = new HTMLNode("div");
    int totalNumber = 0;
    for (UserAlert alert : getAlerts()) {
      if (shouldSkipAlert(alert, showOnlyErrors)) {
        continue;
      }
      totalNumber++;
      alertsNode.addChild("a", "name", alert.anchor());
      if (showOnlyErrors) {
        // Paranoia. Don't break the web interface no matter what.
        try {
          alertsNode.addChild(renderAlert(alert));
        } catch (Exception e) {
          LOG.error("FAILED TO RENDER ALERT: {} : {}", alert, e, e);
        }
      } else {
        // Alerts toadlet itself can error, that's OK.
        alertsNode.addChild(renderAlert(alert));
      }
    }
    if (totalNumber == 0) {
      return new HTMLNode("#", "");
    }
    return alertsNode;
  }

  private boolean shouldSkipAlert(UserAlert alert, boolean showOnlyErrors) {
    return (!alert.isValid()) || (showOnlyErrors && alert.getPriorityClass() > UserAlert.ERROR);
  }

  /**
   * Renders a single alert as an HTML block with header, content, and dismissal controls.
   *
   * <p>The generated node includes CSS classes based on the alert priority class, the localized
   * title as a header, and the full HTML body from the alert. If the alert is dismissable, a
   * standard dismiss form is appended. This method does not catch exceptions from the alert
   * implementation; callers should guard if failures must not propagate.
   *
   * @param userAlert the alert to render; must be non-null and already validated
   * @return an HTML node representing the alert content and controls
   */
  public HTMLNode renderAlert(UserAlert userAlert) {
    HTMLNode userAlertNode;
    short level = userAlert.getPriorityClass();
    userAlertNode = new HTMLNode("div", ATTR_CLASS, "infobox infobox-" + getAlertLevelName(level));

    userAlertNode.addChild("div", ATTR_CLASS, "infobox-header", userAlert.getTitle());
    HTMLNode alertContentNode = userAlertNode.addChild("div", ATTR_CLASS, "infobox-content");
    alertContentNode.addChild(userAlert.getHTMLText());
    alertContentNode.addChild(renderDismissButton(userAlert, null));

    return userAlertNode;
  }

  /**
   * Builds a dismiss button form for a given alert.
   *
   * <p>If the alert can be dismissed, this method generates a form that posts to the alerts
   * endpoint with the alert hash code and form password. An optional redirect target can be
   * provided to return users to the originating page after dismissal. Non-dismissable alerts return
   * an empty container.
   *
   * @param userAlert the alert whose dismissal form should be generated
   * @param redirectToAfterDisable optional redirect target after dismissal, or {@code null}
   * @return a container HTML node that may include a dismissal form
   */
  public HTMLNode renderDismissButton(UserAlert userAlert, String redirectToAfterDisable) {
    HTMLNode result = new HTMLNode("div");
    if (userAlert.userCanDismiss()) {
      HTMLNode dismissFormNode =
          result
              .addChild(
                  "form", new String[] {"action", "method"}, new String[] {ALERTS_PATH, "post"})
              .addChild("div");
      dismissFormNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, "disable", String.valueOf(userAlert.hashCode())});
      dismissFormNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, "formPassword", core.getFormPassword()});
      dismissFormNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"submit", "dismiss-user-alert", userAlert.dismissButtonText()});

      if (redirectToAfterDisable != null) {
        dismissFormNode.addChild(
            INPUT_TAG,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {INPUT_TYPE_HIDDEN, "redirectToAfterDisable", redirectToAfterDisable});
      }
    }
    return result;
  }

  private String getAlertLevelName(short level) {
    if (level <= UserAlert.CRITICAL_ERROR) return ALERT_LEVEL_ERROR;
    else if (level == UserAlert.ERROR) return "alert";
    else if (level == UserAlert.WARNING) return "warning";
    else if (level == UserAlert.MINOR) return "minor";
    else {
      LOG.error("Unknown alert level: {}", level);
      return ALERT_LEVEL_ERROR;
    }
  }

  /**
   * Creates a summary fragment intended for status views.
   *
   * <p>This overload delegates to {@link #createAlerts(boolean)} with error-only filtering. It is
   * used by status bar and summary pages that only display higher-severity messages and do not
   * require the full alert list.
   *
   * @return an HTML fragment containing error-level alerts, or an empty marker node
   */
  public HTMLNode createSummary() {
    // This method is called by the toadlets when they want to show
    // a summary of alerts. With a status bar, we only show full errors here.
    return createAlerts(true);
  }

  static final HTMLNode ALERTS_LINK = new HTMLNode("a", "href", ALERTS_PATH).setReadOnly();

  /**
   * Builds a textual summary of the current alerts and returns it as an HTML infobox.
   *
   * <p>The summary aggregates counts by severity and formats them either as a single line or as a
   * multipart infobox, depending on {@code oneLine}. When there are no alerts to display, an empty
   * marker node is returned. In one-line mode, the summary can be suppressed entirely for
   * low-severity alerts; in that case, this method returns {@code null}.
   *
   * @param oneLine whether to emit a compact single-line summary instead of a full infobox
   * @return the summary infobox node, an empty marker node, or {@code null} when suppressed
   */
  public HTMLNode createSummary(boolean oneLine) {
    SummaryStats stats = collectSummaryStats();
    if (stats.shouldHideSummary(oneLine)) {
      return null;
    }
    if (stats.totalNumber == 0) {
      return new HTMLNode("#", "");
    }

    String separator = oneLine ? ", " : " | ";
    StringBuilder alertSummaryString = buildAlertSummaryString(stats, oneLine, separator);
    HTMLNode summaryBox = createSummaryBox(stats.highestLevel, oneLine);
    summaryBox.addChild("div", ATTR_CLASS, "infobox-header", l10n("alertsTitle"));
    HTMLNode summaryContent = summaryBox.addChild("div", ATTR_CLASS, "infobox-content");
    if (!oneLine) {
      summaryContent.addChild("#", alertSummaryString + separator + " ");
      NodeL10n.getBase()
          .addL10nSubstitution(
              summaryContent,
              "UserAlertManager.alertsOnAlertsPage",
              new String[] {"link"},
              new HTMLNode[] {ALERTS_LINK});
    } else {
      summaryContent.addChild(
          "a",
          "href",
          ALERTS_PATH,
          NodeL10n.getBase().getString("StatusBar.alerts") + " " + alertSummaryString);
    }
    summaryBox.addAttribute("id", "messages-summary-box");
    return summaryBox;
  }

  private SummaryStats collectSummaryStats() {
    SummaryStats stats = new SummaryStats();
    for (UserAlert alert : getAlerts()) {
      if (!alert.isValid()) {
        continue;
      }
      stats.recordAlert(alert);
    }
    return stats;
  }

  private StringBuilder buildAlertSummaryString(
      SummaryStats stats, boolean oneLine, String separator) {
    StringBuilder alertSummaryString = new StringBuilder(1024);
    SummaryTextBuilder builder = new SummaryTextBuilder(stats, alertSummaryString, separator);
    builder.appendIfPresent(stats.numberOfCriticalError, !oneLine, l10n("criticalErrorCountLabel"));
    builder.appendIfPresent(stats.numberOfError, !oneLine, l10n("errorCountLabel"));
    builder.appendWarningCount(stats.numberOfWarning, oneLine);
    builder.appendMinorCount(stats.numberOfMinor, oneLine);
    builder.appendTotal(stats.totalNumber, oneLine);
    return alertSummaryString;
  }

  private HTMLNode createSummaryBox(short highestLevel, boolean oneLine) {
    String classes = oneLine ? "alerts-line contains-" : "infobox infobox-";
    if (highestLevel <= UserAlert.CRITICAL_ERROR && !oneLine) {
      return new HTMLNode("div", ATTR_CLASS, classes + ALERT_LEVEL_ERROR);
    }
    if (highestLevel <= UserAlert.ERROR && !oneLine) {
      return new HTMLNode("div", ATTR_CLASS, classes + "alert");
    }
    if (highestLevel <= UserAlert.WARNING) {
      return new HTMLNode("div", ATTR_CLASS, classes + "warning");
    }
    return new HTMLNode("div", ATTR_CLASS, classes + "information");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("UserAlertManager." + key);
  }

  /**
   * Dismisses event alerts whose anchors appear in the supplied set.
   *
   * <p>This method iterates over a snapshot of current alerts and, for each event notification
   * whose anchor is present in {@code toDump}, unregisters the alert and invokes its dismissal
   * callback. Non-event alerts are ignored. The operation is best-effort and does not report which
   * alerts were removed.
   *
   * @param toDump the set of alert anchor strings to dismiss when matched
   */
  public void dumpEvents(Set<String> toDump) {
    // An iterator might be faster, but we don't want to call methods on the alert within the lock.
    for (UserAlert alert : getAlerts()) {
      if (alert.isEventNotification() && toDump.contains(alert.anchor())) {
        unregister(alert);
        alert.onDismiss();
      }
    }
  }

  /**
   * Registers a subscriber and immediately sends the current valid alerts.
   *
   * <p>The subscriber is added to the internal subscriber set and then receives a snapshot of all
   * valid alerts via asynchronous FCP callbacks. The snapshot is taken at execution time on the
   * executor, so it reflects the state at that moment. Registering the same subscriber multiple
   * times is safe because the set de-duplicates entries.
   *
   * @param subscriber the FCP connection that should receive alert notifications
   */
  public void watch(final FCPConnectionHandler subscriber) {
    subscribers.add(subscriber);
    // Run off-thread, because of locking, and because client
    // callbacks may take some time
    core.getClientContext()
        .getMainExecutor()
        .execute(
            () -> {
              for (UserAlert alert : getAlerts())
                if (alert.isValid()) subscriber.send(alert.getFCPMessage());
            },
            "UserAlertManager callback executor");
    subscribers.add(subscriber);
  }

  /**
   * Unregisters a subscriber so it no longer receives alert notifications.
   *
   * <p>This method removes the subscriber from the internal set. It does not attempt to cancel any
   * in-flight asynchronous notifications already queued on the executor.
   *
   * @param subscriber the FCP connection to remove from the subscriber list
   */
  public void unwatch(FCPConnectionHandler subscriber) {
    subscribers.remove(subscriber);
  }

  // Formats a Unix timestamp according to RFC 3339
  private String formatTime(long time) {
    final Format format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
    String date = format.format(new Date(time));
    // Z doesn't include a colon between the hour and the minutes
    return date.substring(0, 22) + ":" + date.substring(22);
  }

  /**
   * Builds an Atom feed document containing the current alerts.
   *
   * <p>The feed uses the provided start URI as the base for links to the alerts page and is updated
   * with the most recent alert timestamp. Each valid alert becomes a feed entry containing its
   * title, summary, and full text. The generated XML is intended for lightweight status polling and
   * does not include pagination or history beyond the current alert snapshot.
   *
   * @param startURI the base URI used to construct alert and feed links
   * @return a serialized Atom feed containing the current alert snapshot
   */
  public String getAtom(String startURI) {
    String messagesURI = startURI + ALERTS_PATH;
    String feedURI = startURI + "/feed/";

    XmlBuilder xmlBuilder = new XmlBuilder();
    xmlBuilder.addNamespaceElement(
        "http://www.w3.org/2005/Atom",
        "feed",
        feed -> {
          feed.addElement("title", l10n("feedTitle"));
          feed.addElement(
              "link",
              link -> {
                link.setAttribute("rel", "self");
                link.setAttribute("href", feedURI);
              });
          feed.addElement("link", link -> link.setAttribute("href", startURI));
          feed.addElement(
              "id", "urn:node:" + Base64.encode(core.getNode().network().darknetPubKeyHash()));
          feed.addElement("updated", formatTime(lastUpdated));
          feed.addElement("logo", "/favicon.ico");

          stream(getAlerts())
              .filter(UserAlert::isValid)
              .forEach(
                  alert ->
                      feed.addElement(
                          "entry",
                          entry -> {
                            entry.addElement("id", "urn:feed:" + alert.anchor());
                            entry.addElement(
                                "link",
                                link ->
                                    link.setAttribute("href", messagesURI + "#" + alert.anchor()));
                            entry.addElement("updated", formatTime(alert.getUpdatedTime()));
                            entry.addElement("title", alert.getTitle());
                            entry.addElement("summary", alert.getShortText());
                            entry.addElement(
                                "content",
                                alert.getText(),
                                content -> content.setAttribute("type", "text"));
                          }));
        });
    return xmlBuilder.generate();
  }

  private interface ElementBuilder {

    void addElement(String name, Consumer<ElementBuilder> elementBuilder);

    void addElement(String name, String content, Consumer<ElementBuilder> elementBuilder);

    void setAttribute(String name, String value);

    default void addElement(String name, String content) {
      addElement(name, content, _ -> {});
    }
  }

  private static class XmlBuilder implements ElementBuilder {

    @Override
    public void addElement(String name, Consumer<ElementBuilder> elementBuilder) {
      Element childElement = document.createElement(name);
      elementBuilder.accept(new XmlBuilder(document, childElement));
      ((this.element == null) ? document : this.element).appendChild(childElement);
    }

    @Override
    public void addElement(String name, String content, Consumer<ElementBuilder> elementBuilder) {
      Element childElement = document.createElement(name);
      childElement.setTextContent(content);
      elementBuilder.accept(new XmlBuilder(document, childElement));
      ((this.element == null) ? document : this.element).appendChild(childElement);
    }

    public void addNamespaceElement(
        String namespace, String name, Consumer<ElementBuilder> elementBuilder) {
      Element childElement = document.createElementNS(namespace, name);
      elementBuilder.accept(new XmlBuilder(document, childElement));
      ((this.element == null) ? document : this.element).appendChild(childElement);
    }

    @Override
    public void setAttribute(String name, String value) {
      if (element != null) {
        element.setAttribute(name, value);
      }
    }

    public String generate() {
      DOMSource source = new DOMSource(document);
      try (StringWriter stringWriter = new StringWriter()) {
        StreamResult result = new StreamResult(stringWriter);
        transformer.transform(source, result);
        return stringWriter.toString();
      } catch (TransformerException e) {
        throw new IllegalStateException("Failed to render user alerts feed.", e);
      } catch (IOException e) {
        throw new UncheckedIOException("Failed to write user alerts feed.", e);
      }
    }

    public XmlBuilder() {
      this(documentBuilder.newDocument(), null);
    }

    private XmlBuilder(Document document, Element element) {
      this.document = document;
      this.element = element;
    }

    private final Document document;
    private final Element element;
    private static final DocumentBuilder documentBuilder;
    private static final TransformerFactory transformerFactory = TransformerFactory.newInstance();
    private static final Transformer transformer;

    static {
      try {
        documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xalan}indent-amount", "2");
      } catch (ParserConfigurationException | TransformerConfigurationException e) {
        throw new IllegalStateException("Failed to initialize alert feed generator.", e);
      }
    }
  }

  private static final class SummaryStats {
    private short highestLevel = Short.MAX_VALUE;
    private int numberOfCriticalError;
    private int numberOfError;
    private int numberOfWarning;
    private int numberOfMinor;
    private int totalNumber;
    private int messageTypes;

    private void recordAlert(UserAlert alert) {
      short level = alert.getPriorityClass();
      if (level < highestLevel) {
        highestLevel = level;
      }
      if (level <= UserAlert.CRITICAL_ERROR) {
        numberOfCriticalError++;
      } else if (level == UserAlert.ERROR) {
        numberOfError++;
      } else if (level == UserAlert.WARNING) {
        numberOfWarning++;
      } else if (level == UserAlert.MINOR) {
        numberOfMinor++;
      }
      totalNumber++;
    }

    private boolean shouldHideSummary(boolean oneLine) {
      return oneLine && numberOfMinor == 0 && numberOfWarning == 0;
    }
  }

  private final class SummaryTextBuilder {
    private final SummaryStats stats;
    private final StringBuilder builder;
    private final String separator;
    private boolean separatorNeeded;

    private SummaryTextBuilder(SummaryStats stats, StringBuilder builder, String separator) {
      this.stats = stats;
      this.builder = builder;
      this.separator = separator;
    }

    private void appendIfPresent(int count, boolean include, String label) {
      if (count == 0 || !include) {
        return;
      }
      appendSeparatorIfNeeded();
      builder.append(label).append(' ').append(count);
      separatorNeeded = true;
      stats.messageTypes++;
    }

    private void appendWarningCount(int count, boolean oneLine) {
      if (count == 0) {
        return;
      }
      appendSeparatorIfNeeded();
      if (oneLine) {
        builder.append(count).append(' ').append(l10n("warningCountLabel").replace(":", ""));
      } else {
        builder.append(l10n("warningCountLabel")).append(' ').append(count);
      }
      separatorNeeded = true;
      stats.messageTypes++;
    }

    private void appendMinorCount(int count, boolean oneLine) {
      if (count == 0) {
        return;
      }
      appendSeparatorIfNeeded();
      if (oneLine) {
        builder.append(count).append(' ').append(l10n("minorCountLabel").replace(":", ""));
      } else {
        builder.append(l10n("minorCountLabel")).append(' ').append(count);
      }
      separatorNeeded = true;
      stats.messageTypes++;
    }

    private void appendTotal(int totalNumber, boolean oneLine) {
      if (stats.messageTypes == 1 || oneLine) {
        return;
      }
      appendSeparatorIfNeeded();
      builder.append(l10n("totalLabel")).append(' ').append(totalNumber);
    }

    private void appendSeparatorIfNeeded() {
      if (separatorNeeded) {
        builder.append(separator);
      }
    }
  }
}
