package network.crypta.clients.http.utils;

import network.crypta.clients.http.utils.L10nExtension.L10nFunction;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Map;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.loader.ClasspathLoader;
import io.pebbletemplates.pebble.loader.Loader;
import io.pebbletemplates.pebble.template.PebbleTemplate;

import network.crypta.support.HTMLNode;

public class PebbleUtils {
  private static final String TEMPLATE_ROOT_PATH = "network/crypta/clients/http/templates/";
  private static final String TEMPLATE_NAME_SUFFIX = ".html";
  private static final PebbleEngine templateEngine;

  static {
    Loader loader = new ClasspathLoader(PebbleUtils.class.getClassLoader());
    loader.setPrefix(PebbleUtils.TEMPLATE_ROOT_PATH);
    loader.setSuffix(PebbleUtils.TEMPLATE_NAME_SUFFIX);

    templateEngine = new PebbleEngine.Builder().loader(loader).extension(new L10nExtension(NodeL10n.getBase())).build();
  }

  public static void addChild(
      HTMLNode parent,
      String templateName,
      Map<String, Object> model,
      String l10nPrefix) throws
      IOException {
    model.put("l10nPrefix", l10nPrefix);
    PebbleTemplate template = templateEngine.getTemplate(templateName);

    Writer writer = new StringWriter();
    template.evaluate(writer, model);

    parent.addChild("%", writer.toString());
  }

  /**
   * Sets the {@link BaseL10n l10n provider} to use with the
   * {@link L10nFunction}. If this method is not called, {@link NodeL10n}’s
   * {@link NodeL10n#getBase() l10n provider} is used.
   * <p>
   * This method should only be called from tests.
   *
   * @param l10n The l10n provider to use
   */
  static void setBaseL10n(BaseL10n l10n) {
    // this will remove the old function from the registry, because the
    // registry is a big Map, with the function name as key.
    templateEngine.getExtensionRegistry().addExtension(new L10nExtension(l10n));
  }

}
