package network.crypta.clients.http;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;

public abstract class LocalDirectoryToadlet extends LocalFileBrowserToadlet {

  protected final String postTo;
  protected static final String basePath = "/directory-browser";

  public LocalDirectoryToadlet(
      NodeClientCore core, HighLevelSimpleClient highLevelSimpleClient, String postTo) {
    super(core, highLevelSimpleClient);
    this.postTo = postTo;
  }

  @Override
  public String path() {
    return basePath + postTo;
  }

  public static String basePath() {
    return basePath;
  }

  @Override
  protected String postTo() {
    return postTo;
  }

  @Override
  protected void createSelectFileButton(HTMLNode fileRow, String filename, HTMLNode persist) {}
}
