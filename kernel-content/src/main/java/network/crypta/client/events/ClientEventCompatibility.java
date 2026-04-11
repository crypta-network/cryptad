package network.crypta.client.events;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Compatibility bridges for legacy {@code ClientContext}-based event SPI implementations.
 *
 * <p>This helper preserves upgrade compatibility while the compile-neutral event seam moves from a
 * runtime-owned {@code ClientContext} parameter to the narrower {@link ClientEventDispatchContext}
 * contract. Current call sites first try the new listener or producer method directly. When a
 * downstream implementation was compiled against the older descriptor and therefore throws {@link
 * AbstractMethodError}, this class reflectively looks for the legacy overload that still accepts
 * {@code network.crypta.client.async.ClientContext}. If that overload exists and the supplied
 * context is a real runtime {@code ClientContext}, the bridge invokes it and preserves the old
 * behavior. If not, it rethrows a more explicit linkage failure.
 *
 * <p>The bridge is intentionally package-private and narrowly scoped to the event dispatch. It does
 * not attempt to emulate a broader runtime SPI or synthesize legacy contexts. The helper simply
 * keeps existing listener and producer extensions working when the runtime can supply the original
 * context object.
 */
final class ClientEventCompatibility {
  /**
   * Binary name of the legacy runtime context type used by older event extensions.
   *
   * <p>The bridge resolves this class lazily so {@code :kernel-content} can stay free of a direct
   * compile-time dependency on {@code :runtime-node}.
   */
  private static final String LEGACY_CLIENT_CONTEXT_CLASS_NAME =
      "network.crypta.client.async.ClientContext";

  /**
   * Utility class; not meant to be instantiated.
   *
   * <p>All entry points are static because the bridge carries no mutable state.
   */
  private ClientEventCompatibility() {}

  /**
   * Dispatches to a listener and falls back to the legacy {@code ClientContext}-based overload when
   * needed.
   *
   * <p>The direct call is attempted first, so new implementations incur no reflective overhead. A
   * fallback is only attempted after {@link AbstractMethodError}, which is the expected signal that
   * the listener was compiled against the old descriptor.
   *
   * @param listener listener receiving the event
   * @param event event being delivered
   * @param context runtime-backed dispatch context supplied by the producer; may be {@code null}
   */
  static void dispatchToListener(
      ClientEventListener listener, ClientEvent event, ClientEventDispatchContext context) {
    try {
      listener.receive(event, context);
    } catch (AbstractMethodError e) {
      invokeLegacyMethod(listener, "receive", event, context, e);
    }
  }

  /**
   * Dispatches to a producer and falls back to the legacy {@code ClientContext}-based overload when
   * needed.
   *
   * <p>This mirrors {@link #dispatchToListener(ClientEventListener, ClientEvent,
   * ClientEventDispatchContext)} for custom producer implementations compiled against the older
   * SPI.
   *
   * @param producer producer emitting the event
   * @param event event being raised
   * @param context runtime-backed dispatch context supplied by the caller; may be {@code null}
   */
  static void dispatchToProducer(
      ClientEventProducer producer, ClientEvent event, ClientEventDispatchContext context) {
    try {
      producer.produceEvent(event, context);
    } catch (AbstractMethodError e) {
      invokeLegacyMethod(producer, "produceEvent", event, context, e);
    }
  }

  /**
   * Invokes the legacy overload for a listener or producer after a linkage failure on the new
   * method signature.
   *
   * <p>The supplied context must either be {@code null} or an actual instance of the legacy runtime
   * context class. The bridge does not attempt any adaptation beyond that check.
   *
   * @param target listener or producer that failed the direct dispatch
   * @param methodName legacy method name to invoke
   * @param event event value being passed through
   * @param context current dispatch context from the runtime
   * @param originalError linkage failure raised by the direct call path
   */
  private static void invokeLegacyMethod(
      Object target,
      String methodName,
      ClientEvent event,
      ClientEventDispatchContext context,
      AbstractMethodError originalError) {
    Class<?> legacyContextClass = legacyClientContextClass();
    if (context != null && !legacyContextClass.isInstance(context)) {
      throw missingLegacyMethod(target, methodName, legacyContextClass, originalError);
    }
    Method legacyMethod = legacyMethod(target, methodName, legacyContextClass, originalError);
    try {
      legacyMethod.invoke(target, event, context);
    } catch (IllegalAccessException e) {
      throw new LinkageError("Cannot access legacy client-event compatibility method", e);
    } catch (InvocationTargetException e) {
      rethrowInvocationCause(e);
    }
  }

  /**
   * Resolves the legacy method on the concrete target type.
   *
   * <p>The lookup is performed on the runtime class rather than on the interface so that downstream
   * implementations compiled against older releases can still be invoked through reflection.
   *
   * @param target listener or producer instance being bridged
   * @param methodName legacy method name to locate
   * @param legacyContextClass runtime context class required by the legacy overload
   * @param originalError linkage failure raised by the new-signature dispatch
   * @return reflected legacy method ready for invocation
   */
  private static Method legacyMethod(
      Object target,
      String methodName,
      Class<?> legacyContextClass,
      AbstractMethodError originalError) {
    try {
      return target.getClass().getMethod(methodName, ClientEvent.class, legacyContextClass);
    } catch (NoSuchMethodException _) {
      throw missingLegacyMethod(target, methodName, legacyContextClass, originalError);
    }
  }

  /**
   * Resolves the runtime-owned legacy context type by name.
   *
   * <p>Using reflective lookup keeps the compile-neutral event leaf free of a direct import while
   * still allowing compatibility dispatch when the runtime module is present.
   *
   * @return the legacy runtime {@code ClientContext} class
   */
  private static Class<?> legacyClientContextClass() {
    try {
      return Class.forName(LEGACY_CLIENT_CONTEXT_CLASS_NAME);
    } catch (ClassNotFoundException e) {
      throw new LinkageError("Legacy ClientContext class is unavailable", e);
    }
  }

  /**
   * Builds a more explicit linkage failure when neither the new nor legacy event signature is
   * available.
   *
   * <p>The returned {@link AbstractMethodError} keeps the original linkage failure as its cause so
   * callers can still see which direct dispatch attempt failed first.
   *
   * @param target listener or producer that could not be bridged
   * @param methodName missing method name
   * @param legacyContextClass the required legacy context type
   * @param originalError original linkage failure from the direct call path
   * @return an error describing the required new and legacy method shapes
   */
  private static AbstractMethodError missingLegacyMethod(
      Object target,
      String methodName,
      Class<?> legacyContextClass,
      AbstractMethodError originalError) {
    AbstractMethodError error =
        new AbstractMethodError(
            target.getClass().getName()
                + " must implement "
                + methodName
                + '('
                + ClientEvent.class.getName()
                + ", "
                + ClientEventDispatchContext.class.getName()
                + ") or the legacy overload using "
                + legacyContextClass.getName());
    error.initCause(originalError);
    return error;
  }

  /**
   * Re-throws the underlying cause from a reflective invocation.
   *
   * <p>Runtime exceptions and errors keep their original type so callers observe the same failure
   * surface they would have seen without reflection. Checked exceptions are wrapped because the
   * event bridge does not declare them.
   *
   * @param e wrapper thrown by reflective invocation
   */
  private static void rethrowInvocationCause(InvocationTargetException e) {
    Throwable cause = e.getCause();
    if (cause instanceof RuntimeException runtimeException) {
      throw runtimeException;
    }
    if (cause instanceof Error error) {
      throw error;
    }
    throw new IllegalStateException(
        "Legacy client-event compatibility method threw a checked exception", cause);
  }
}
