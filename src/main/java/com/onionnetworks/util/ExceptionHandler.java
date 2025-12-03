package com.onionnetworks.util;

import java.util.EventListener;

/**
 * Listener interface for components that need to publish exception notifications.
 *
 * <p>This contract decouples error reporting from the code that detects the failure, allowing
 * callers to route exceptions to logging, UI feedback, or recovery workflows without forcing a
 * specific handling strategy. Implementations are typically lightweight and invoked on the same
 * thread that raised the exception event; therefore, handlers should avoid long-running or blocking
 * operations unless callers explicitly coordinate threading. Implementations may be stateless or
 * stateful, but they should remain robust in the presence of repeated failures and should clearly
 * document any shared-resource usage. The interface itself is deliberately minimal so that handlers
 * can be plugged into event-driven pipelines, background services, or testing harnesses without
 * carrying dependencies on particular logging or scheduling frameworks.
 *
 * <ul>
 *   <li>Responsibilities: receive {@link ExceptionEvent} instances and decide how to surface them.
 *   <li>Typical uses: bridge to logging frameworks, aggregate errors, or notify user interfaces.
 *   <li>Threading: callers invoke handlers directly; concurrency policies are implementation
 *       specific.
 * </ul>
 *
 * @author Justin F. Chapweske
 * @see ExceptionEvent
 * @see java.util.EventListener
 */
public interface ExceptionHandler extends EventListener {

  /**
   * Handles a dispatched exception event produced elsewhere in the system.
   *
   * <p>The event bundles the originating source object and the {@link Throwable} that was observed.
   * Implementations may log, surface, or attempt recovery but should not assume that invocation
   * will be serialized; callers may deliver multiple events in rapid succession. Null events are
   * not expected, and handlers should treat missing exception data defensively. Because this method
   * is often called synchronously by the code that detected the failure, keep processing brief or
   * offload heavy work to background execution when appropriate to avoid propagating delays or
   * additional errors.
   *
   * <pre>{@code
   * ExceptionHandler handler = ev -> logger.error("Task failed", ev.getException());
   * }</pre>
   *
   * @param ev non-null exception event carrying the originating source and captured Throwable
   */
  void handleException(ExceptionEvent ev);
}
