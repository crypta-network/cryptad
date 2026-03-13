package org.spaceroots.mantissa.utilities;

/**
 * Simple container for an offset and an {@link ArraySliceMappable} object.
 *
 * <p>{@code ArrayMapperEntry} represents one managed slice within an {@link ArrayMapper}. Each
 * entry pairs a single domain object (the slice owner) with the zero-based offset at which that
 * object's state begins in the mapper's logical flat {@code double[]} vector. Entries are created
 * when objects are registered with a mapper and then treated as immutable bookkeeping: the
 * reference to the domain object and its offset never change for the lifetime of the entry.
 *
 * <p>This type is package-private and intended only for internal coordination. It performs no
 * validation; in particular, offsets are assumed to be consistent with the mapper's sizing logic,
 * and the object reference may be {@code null} if a caller supplies one. The record itself is
 * shallowly immutable and thread-safe, but any thread-safety guarantees for the stored object are
 * inherited from that object's implementation.
 *
 * <ul>
 *   <li>Stores a direct reference to the managed {@link ArraySliceMappable} instance.
 *   <li>Stores a fixed offset into the mapper's flat state vector.
 * </ul>
 *
 * @param object domain object owning a contiguous slice; may be {@code null} if supplied.
 * @param offset zero-based start index for the object's slice within the flat vector.
 * @version $Id: ArrayMapperEntry.java 1257 2002-06-20 17:53:26Z luc $
 * @author L. Maisonobe
 */
record ArrayMapperEntry(ArraySliceMappable object, int offset) {}
