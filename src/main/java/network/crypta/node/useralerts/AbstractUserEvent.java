package network.crypta.node.useralerts;

import network.crypta.node.useralerts.AbstractUserAlert.Body;
import network.crypta.node.useralerts.AbstractUserAlert.DismissOptions;
import network.crypta.support.HTMLNode;

public class AbstractUserEvent extends AbstractUserAlert implements UserEvent {

  private Type eventType;

  public AbstractUserEvent(
      Type eventType,
      boolean userCanDismiss,
      String title,
      String text,
      String shortText,
      HTMLNode htmlText,
      short priorityClass,
      boolean valid,
      String dismissButtonText,
      boolean shouldUnregisterOnDismiss) {
    super(
        userCanDismiss,
        title,
        Body.of(text, shortText, htmlText),
        priorityClass,
        valid,
        new DismissOptions(dismissButtonText, shouldUnregisterOnDismiss));
    this.eventType = eventType;
  }

  public AbstractUserEvent() {}

  @Override
  public Type getEventType() {
    return eventType;
  }
}
