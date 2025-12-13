package network.crypta.clients.http.annotation;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Annotation that declares whether an HTTP handler method accepts a request payload.
 *
 * <p>This annotation is applied to HTTP handler methods to describe how the HTTP layer should treat
 * an entity body. Use it when a handler either requires caller-supplied data or can accept data but
 * still behaves correctly when no body is present. The dispatcher can use this metadata to validate
 * requests early and to document the handler’s contract.
 *
 * <p>The policy is expressed via the single {@link #value()} element. A value of {@code true}
 * requires a payload; {@code false} makes a payload optional. Some HTTP methods may still be
 * treated specially by the surrounding implementation (for example, POST may be handled as
 * requiring a body), so this annotation is guidance to the dispatcher rather than a protocol rule.
 *
 * <ul>
 *   <li>When {@code true}, the HTTP layer may reject requests that omit a body.
 *   <li>When {@code false}, handlers should tolerate a missing body and treat it as "no data".
 * </ul>
 *
 * <p>This is static metadata: it is immutable and thread-safe, and it has no runtime state beyond
 * the annotation value read by the dispatcher.
 *
 * @author saces
 */
@SuppressWarnings("unused")
@Target(METHOD)
@Retention(RUNTIME)
@Documented
public @interface AllowData {
  /**
   * Indicates whether the annotated handler requires a request payload.
   *
   * <p>When set to {@code true}, callers are expected to include a request body and the HTTP layer
   * may treat an absent body as an error. When set to {@code false}, a request body is permitted
   * but not mandatory; handlers should be prepared to operate when no payload is supplied.
   *
   * @return {@code true} when a request payload is required; {@code false} when it is optional.
   */
  boolean value() default false;
}
