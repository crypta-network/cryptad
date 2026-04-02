package network.crypta.clients.http.utils;

import io.pebbletemplates.pebble.extension.AbstractExtension;
import io.pebbletemplates.pebble.extension.Function;
import io.pebbletemplates.pebble.template.EvaluationContext;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.l10n.BaseL10n;

/**
 * Pebble extension that exposes Crypta localization to HTTP templates.
 *
 * <p>This extension registers a single Pebble function named {@code l10n}. Templates can call it
 * with a localization key to obtain a user-facing string from a provided {@link BaseL10n} instance.
 * The function also supports an optional prefix taken from the Pebble evaluation context variable
 * {@code l10nPrefix}, allowing templates to share a common namespace without repeating it at each
 * call site.
 *
 * <p>The extension is intentionally small and immutable: it does not cache results, and it does not
 * mutate the evaluation context. Any thread-safety guarantees depend on the supplied {@link
 * BaseL10n} implementation; this wrapper itself only stores references and performs simple string
 * composition.
 *
 * <ul>
 *   <li>Registers {@code l10n} as a template function.
 *   <li>Supports both positional and named argument styles for the key.
 *   <li>Optionally prepends a context-provided prefix for key namespacing.
 * </ul>
 */
class L10nExtension extends AbstractExtension {

  /**
   * Creates a new extension instance backed by the given localization provider.
   *
   * <p>The supplied {@link BaseL10n} is stored and used for all subsequent template evaluations.
   * This class does not take ownership of the instance and does not alter its configuration. The
   * resulting extension is immutable and safe to reuse across requests provided that the underlying
   * {@link BaseL10n} is safe for the intended concurrency model.
   *
   * @param l10n localization provider used to resolve keys into display strings; must be non-null
   */
  public L10nExtension(BaseL10n l10n) {
    l10nFunction = new L10nFunction(l10n);
  }

  /**
   * Returns the Pebble functions exported by this extension.
   *
   * <p>The returned map contains a single entry mapping the name {@code l10n} to an implementation
   * that resolves localization keys using the {@link BaseL10n} supplied at construction time. A new
   * map is created on each invocation to match Pebble's extension contract; callers should treat
   * the returned map as owned by the caller and not rely on identity or mutability across
   * invocations.
   *
   * @return a map of Pebble function name to function implementation, containing {@code l10n}
   */
  @Override
  public Map<String, Function> getFunctions() {
    Map<String, Function> functions = new HashMap<>();
    functions.put("l10n", l10nFunction);
    return functions;
  }

  /**
   * Pebble {@code l10n} function implementation owned by this extension instance.
   *
   * <p>This field is immutable after construction and is registered under the name {@code l10n}. It
   * encapsulates the configured {@link BaseL10n} and performs argument parsing for each invocation.
   */
  private final L10nFunction l10nFunction;

  /**
   * Pebble function that resolves localization keys via {@link BaseL10n}.
   *
   * <p>The function accepts a single optional argument representing the localization key. Pebble
   * may provide the key as positional argument {@code "0"} or as a named argument {@code "key"}.
   * When argument names are not declared by the function, Pebble may use other keys; in that case
   * the first value in the argument map is treated as the key.
   *
   * <p>If the evaluation context contains a variable named {@code l10nPrefix}, its string value is
   * prepended to the key before calling {@link BaseL10n#getString(String)}. When no key is
   * available, this implementation returns the literal string {@code "null"} to avoid returning a
   * Java {@code null} into the template engine.
   */
  static class L10nFunction implements Function {

    /**
     * Creates a function instance bound to the supplied localization provider.
     *
     * <p>The provider is stored as-is and consulted on each {@link #execute(Map, PebbleTemplate,
     * EvaluationContext, int)} call. The function does not cache results, so repeated invocations
     * may perform repeated lookups depending on the {@link BaseL10n} implementation.
     *
     * @param l10n localization provider used to resolve keys; must be non-null
     */
    public L10nFunction(BaseL10n l10n) {
      this.l10n = l10n;
    }

    /**
     * Resolves a localization key from Pebble arguments and returns the corresponding string.
     *
     * <p>This method extracts the key from {@code args} using {@link #extractKey(Map)}. If no key
     * is provided (including when the argument map is empty), it returns the literal {@code "null"}
     * to avoid inserting a Java {@code null} into the template output. When a key is available, it
     * is prefixed with the optional {@code l10nPrefix} variable from {@code context} and then
     * resolved with {@link BaseL10n#getString(String)}.
     *
     * @param args Pebble argument map for this function call; may be empty or null depending on how
     *     the template is invoked
     * @param self template instance invoking the function, provided by Pebble; unused by this
     *     implementation
     * @param context evaluation context containing variables such as {@code l10nPrefix}; may be
     *     null for some call sites
     * @param lineNumber template line number for diagnostics, provided by Pebble; unused here
     * @return resolved localized string, or the literal {@code "null"} when no key is provided
     */
    @Override
    public Object execute(
        Map<String, Object> args, PebbleTemplate self, EvaluationContext context, int lineNumber) {
      Object key = extractKey(args);
      if (key == null) {
        return "null";
      }
      return l10n.getString(extractPrefix(context) + key);
    }

    /**
     * Declares the set of accepted argument names for this Pebble function.
     *
     * <p>This implementation declares a single optional positional argument named {@code "0"} to
     * support calls such as {@code l10n("some.key")}. Pebble accepts calls with fewer arguments
     * (for example {@code l10n()}) and provides an empty argument map in that case, which is
     * handled by {@link #execute(Map, PebbleTemplate, EvaluationContext, int)}.
     *
     * @return an immutable list containing the single name {@code "0"}
     */
    @Override
    public List<String> getArgumentNames() {
      // Declare a single optional positional argument. Pebble accepts calls with fewer arguments
      // (e.g. l10n()) and provides an empty args map in that case.
      return List.of("0");
    }

    /**
     * Extracts the localization key argument from a Pebble argument map.
     *
     * <p>The resolution order is:
     *
     * <ol>
     *   <li>Return {@code null} when {@code args} is null or empty.
     *   <li>Use the positional argument under key {@code "0"} when present.
     *   <li>Use the named argument {@code "key"} when present.
     *   <li>Otherwise, treat the first value in the map as the key.
     * </ol>
     *
     * <p>The fallback to the first value exists because Pebble may use arbitrary keys when argument
     * names are not declared.
     *
     * @param args argument map provided by Pebble; may be null or empty
     * @return the extracted key object, or null when no key is available
     */
    private static Object extractKey(Map<String, Object> args) {
      if (args == null || args.isEmpty()) {
        return null;
      }

      if (args.containsKey("0")) {
        return args.get("0");
      }
      if (args.containsKey("key")) {
        return args.get("key");
      }

      // Pebble may use arbitrary keys when argument names aren't declared. In that case, treat the
      // first value as the key.
      return args.values().iterator().next();
    }

    /**
     * Extracts the localization prefix from the Pebble evaluation context.
     *
     * <p>The prefix is read from the context variable {@code l10nPrefix}. If the context is null or
     * the variable is missing, this method returns an empty string. The returned value is always a
     * non-null string suitable for concatenation with a key.
     *
     * @param context Pebble evaluation context from which to read {@code l10nPrefix}; may be null
     * @return a string prefix to prepend to localization keys, or {@code ""} when unset
     */
    private static String extractPrefix(EvaluationContext context) {
      if (context == null) {
        return "";
      }
      return Optional.ofNullable(context.getVariable("l10nPrefix"))
          .map(Object::toString)
          .orElse("");
    }

    /**
     * Localization provider used to resolve composed keys via {@link BaseL10n#getString(String)}.
     *
     * <p>This reference is immutable after construction. Any caching, fallback, or key resolution
     * behavior is defined by the {@link BaseL10n} implementation.
     */
    private final BaseL10n l10n;
  }
}
