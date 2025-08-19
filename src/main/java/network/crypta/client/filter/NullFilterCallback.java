package network.crypta.client.filter;

import network.crypta.client.filter.HTMLFilter.ParsedTag;

public class NullFilterCallback implements FilterCallback {

  @Override
  public String processURI(String uri, String overrideType) {
    return null;
  }

  @Override
  public String onBaseHref(String baseHref) {
    return null;
  }

  @Override
  public void onText(String s, String type) {
    // Do nothing
  }

  @Override
  public String processForm(String method, String action) {
    return null;
  }

  @Override
  public String processURI(String uri, String overrideType, boolean noRelative, boolean inline)
      throws CommentException {
    return null;
  }

  @Override
  public String processURI(
      String uri, String overrideType, String forceSchemeHostAndPort, boolean inline)
      throws CommentException {
    return null;
  }

  @Override
  public String processTag(ParsedTag pt) {
    return null;
  }

  @Override
  public void onFinished() {
    // Ignore.
  }
}
