package com.onionnetworks.util;

/**
 * Simple ordered pair that stores two related objects and exposes lightweight accessors.
 *
 * <p>This tuple is intentionally small and allocation-friendly, making it useful for returning
 * multiple values from a method or for bundling two closely coupled arguments together without
 * defining a dedicated value class. Instances carry a {@code left} and {@code right} component,
 * mirroring the {@code car}/{@code cdr} terminology from Lisp for callers that prefer that naming.
 * Values are assigned at construction time and can be read through the provided accessors;
 * subclasses may mutate the protected fields if needed, so callers should not assume immutability
 * when a tuple escapes their control. Because {@link #hashCode()} and {@link #equals(Object)}
 * dereference both components, supplying {@code null} will result in a {@link NullPointerException}
 * during those operations.
 *
 * <p>Thread-safety is not provided: if subclasses alter the stored references concurrently, callers
 * must supply their own synchronization. When used as a map key, ensure the contained objects are
 * themselves stable across the lifetime of the entry to preserve the hash/equals contract.
 *
 * <ul>
 *   <li>Provides dual accessor pairs: {@code getLeft()}/{@code getRight()} and {@code getCar()}/
 *       {@code getCdr()} for Lisp-style code.
 *   <li>Equality is value-based on both components; hash codes XOR the component hash codes.
 *   <li>Best suited for short-lived transport of two values where defining a richer type is
 *       unnecessary.
 * </ul>
 *
 * @see java.util.AbstractMap.SimpleEntry
 * @author Justin F. Chapweske
 */
public class Tuple {

  /**
   * First component of the pair; expected to be non-{@code null} for equality and hashing, and
   * readable by subclasses that may choose to replace the value.
   */
  protected Object left;

  /**
   * Second component of the pair; expected to be non-{@code null} for equality and hashing, and
   * available to subclasses that need to adjust or inspect the stored value.
   */
  protected Object right;

  /**
   * Construct a tuple with the provided component values.
   *
   * <p>The tuple stores the references exactly as supplied and does not defensively copy mutable
   * objects. To avoid {@link NullPointerException} in {@link #hashCode()} or {@link
   * #equals(Object)}, callers should pass non-{@code null} values. Subclasses may later adjust the
   * fields, but typical usage treats the tuple as effectively immutable once returned from a
   * method.
   *
   * @param left first component to store; expected non-{@code null} for safe hashing and equality
   * @param right second component to store; expected non-{@code null} for safe hashing and equality
   */
  public Tuple(Object left, Object right) {
    this.left = left;
    this.right = right;
  }

  /**
   * Return the first component using Lisp-style terminology.
   *
   * <p>This method is interchangeable with {@link #getLeft()} and exists for callers that prefer
   * {@code car}/{@code cdr} naming conventions. It performs no copying and simply returns the
   * stored reference, so the caller must avoid mutating shared objects when tuples are reused as
   * map keys or cached values.
   *
   * @return the {@code left} component reference; identical to {@link #getLeft()}
   */
  public Object getCar() {
    return left;
  }

  /**
   * Return the second component using Lisp-style terminology.
   *
   * <p>Functionally identical to {@link #getRight()}, this accessor helps migrate existing
   * Lisp-like codebases while preserving readability. The returned reference is the same instance
   * stored in the tuple; callers should treat it as read-only when the tuple participates in
   * hashing or equality comparisons to avoid contract violations.
   *
   * @return the {@code right} component reference; identical to {@link #getRight()}
   */
  public Object getCdr() {
    return right;
  }

  /**
   * Return the first component of the pair.
   *
   * <p>This is the conventional accessor name and mirrors {@link #getCar()}. No defensive copies
   * are performed, so if the stored object is mutable and shared, subsequent modifications may
   * affect equality or hash calculations elsewhere.
   *
   * @return the stored left component reference, or {@code null} if a subclass set it so
   */
  public Object getLeft() {
    return left;
  }

  /**
   * Return the second component of the pair.
   *
   * <p>Equivalent to {@link #getCdr()}, this accessor simply exposes the stored reference. Clients
   * relying on stable equality and hashing should avoid mutating the returned object or replacing
   * it via subclass hooks while it remains in hashed collections.
   *
   * @return the stored right component reference, or {@code null} if a subclass set it so
   */
  public Object getRight() {
    return right;
  }

  /**
   * Compute a hash code derived from both components.
   *
   * <p>The implementation XORs the component hash codes. This is fast but can lead to collisions
   * when the two components are identical or have symmetric hash codes; callers needing stronger
   * distribution should wrap the tuple in a more robust key type. Both components must be non-
   * {@code null} or this method will throw {@link NullPointerException}.
   *
   * @return combined hash code based on {@code left} and {@code right} components
   */
  public int hashCode() {
    return left.hashCode() ^ right.hashCode();
  }

  /**
   * Test value equality with another object.
   *
   * <p>Equality holds when the other object is also a {@code Tuple} and both stored components are
   * equal according to their {@link Object#equals(Object)} implementations. Reference identity is
   * not required, so tuples containing equal-but-distinct objects compare as equal. Neither
   * component may be {@code null} or the comparison will throw {@link NullPointerException}.
   *
   * @param obj candidate object to compare, typically another {@code Tuple}
   * @return {@code true} when both tuples contain equal component values; otherwise {@code false}
   */
  public boolean equals(Object obj) {
    if (!(obj instanceof Tuple t)) {
      return false;
    }
    return left.equals(t.getLeft()) && right.equals(t.getRight());
  }
}
