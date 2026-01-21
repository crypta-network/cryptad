/**
 * This package provides classes to perform linear algebra computation.
 *
 * <p>It is by no means a complete linear algebra system, it is enough to solve least squares
 * problems and linear equations systems, but it lacks lots of functionalities and matric types (for
 * example, sparse matrices are not supported).
 *
 * <p>The class diagram for the public classes of this package is displayed below. The user will
 * mainly use directly the implementation classes rather than the abstract {@link
 * org.spaceroots.mantissa.linalg.Matrix} class. The shape of the matrices used is often known in
 * the algorithms, so there is little need to hide this shape behind the general class. <img
 * src="doc-files/org_spaceroots_mantissa_linalg_classes.png" />
 *
 * @author L. Maisonobe
 */
package org.spaceroots.mantissa.linalg;
