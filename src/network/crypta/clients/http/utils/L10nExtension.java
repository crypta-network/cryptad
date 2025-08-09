package network.crypta.clients.http.utils;

import network.crypta.l10n.BaseL10n;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.pebbletemplates.pebble.extension.AbstractExtension;
import io.pebbletemplates.pebble.extension.Function;
import io.pebbletemplates.pebble.template.EvaluationContext;
import io.pebbletemplates.pebble.template.PebbleTemplate;

class L10nExtension extends AbstractExtension {

  public L10nExtension(BaseL10n l10n) {
    l10nFunction = new L10nFunction(l10n);
  }

  @Override
  public Map<String, Function> getFunctions() {
    Map<String, Function> functions = new HashMap<>();
    functions.put("l10n", l10nFunction);
    return functions;
  }

    private final L10nFunction l10nFunction;

    static class L10nFunction implements Function {

		public L10nFunction(BaseL10n l10n) {
			this.l10n = l10n;
		}

        @Override
        public Object execute(Map<String, Object> args, PebbleTemplate self, EvaluationContext context, int lineNumber) {
            Object key = args.get("0");
            if (key == null) {
                return "null";
            }
            return l10n.getString(context.getVariable("l10nPrefix") + key.toString());
        }

        @Override
        public List<String> getArgumentNames() {
            return null;
        }

        private final BaseL10n l10n;

    }
}
