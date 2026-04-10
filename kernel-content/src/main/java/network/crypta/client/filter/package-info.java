/**
 * Compile-neutral content filtering helpers extracted into {@code :kernel-content}.
 *
 * <p>This package keeps parser, filter-helper, and content-safety exception types available to
 * content-facing code while staying free of runtime-node, FCP, and legacy HTTP adapter execution
 * dependencies.
 */
package network.crypta.client.filter;
