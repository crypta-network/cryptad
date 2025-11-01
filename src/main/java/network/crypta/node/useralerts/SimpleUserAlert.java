package network.crypta.node.useralerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.AbstractUserAlert.Body;
import network.crypta.node.useralerts.AbstractUserAlert.DismissOptions;
import network.crypta.support.HTMLNode;

public class SimpleUserAlert extends AbstractUserAlert {

  public SimpleUserAlert(
      boolean canDismiss, String title, String text, String shortText, short type) {
    this(canDismiss, title, text, shortText, type, null);
  }

  public SimpleUserAlert(
      boolean canDismiss,
      String title,
      String text,
      String shortText,
      short type,
      Object userIdentifier) {
    super(
        canDismiss,
        title,
        Body.of(text, shortText, new HTMLNode("div", text)),
        type,
        true,
        new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), true));
  }

  @Override
  public void isValid(boolean validity) {
    // Do nothing
  }
}
