package network.crypta.platform.api;

/**
 * Canonical path constants for the Platform API.
 *
 * <p>The initial read-only API is mounted under one versioned prefix, so transport-specific bridges
 * can expose it consistently without duplicating the route string throughout the codebase.
 */
public final class PlatformApiPaths {
  /** The current versioned mount prefix for the read-only Platform API v1. */
  public static final String API_V1_PREFIX = "/api/v1/";

  /** Prevents instantiation of this constants-only type. */
  private PlatformApiPaths() {}
}
