/**
 * Security-level-oriented Platform API handlers.
 *
 * <p>This package owns the detached security-level snapshot and threat-level mutation endpoints for
 * Platform API v1. It keeps the mutation surface small while preserving the legacy page as the
 * fallback path for confirmation-heavy and password-management flows.
 */
package network.crypta.platform.api.security;
