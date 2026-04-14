package network.crypta.clients.fcp;

import java.io.InvalidObjectException;

/**
 * Re-wraps legacy runtime-owned insert executions during persistent-request deserialization.
 *
 * <p>Older persisted FCP requests may still contain live runtime putter implementations in their
 * serialized form. The adapter uses this bridge to convert those legacy runtime objects back into
 * adapter-owned {@link ClientPutExecution} or {@link ClientPutDirExecution} handles without taking
 * a direct compile-time dependency on {@code :bridge-fcp-runtime}.
 *
 * <p>The bridge also owns the compatibility layer for the legacy serialized insert context. That
 * matters because the adapter now persists a detached {@link FcpInsertContextHandle} while older
 * queue entries may still deserialize into runtime-owned objects. Implementations therefore serve
 * as the one place where the adapter is allowed to ask, “turn this old runtime object back into the
 * detached representation or execution wrapper that current code expects.”
 */
public interface FcpLegacyInsertExecutionBridge {

  /**
   * Recreates a detached insert-context handle from the legacy runtime-owned serialized form.
   *
   * @param legacyInsertContext serialized legacy {@code InsertContext}, or {@code null} when none
   *     was persisted
   * @return detached adapter-owned handle, or {@code null} when {@code legacyInsertContext} is
   *     {@code null}
   * @throws InvalidObjectException if the legacy object cannot be adapted safely
   */
  FcpInsertContextHandle wrapLegacyInsertContext(Object legacyInsertContext)
      throws InvalidObjectException;

  /**
   * Converts a detached insert-context handle into the legacy runtime-owned serialized form.
   *
   * @param contextHandle detached adapter-owned insert context, or {@code null} when none is
   *     present
   * @return legacy runtime serialization object, or {@code null} when {@code contextHandle} is
   *     {@code null}
   * @throws InvalidObjectException if the handle cannot be serialized safely
   */
  Object legacyInsertContextForSerialization(FcpInsertContextHandle contextHandle)
      throws InvalidObjectException;

  /**
   * Converts a legacy single-file putter object into the adapter-owned execution handle.
   *
   * @param legacyPutter serialized legacy runtime putter, or {@code null} when none was persisted
   * @return adapter-owned execution wrapper, or {@code null} when {@code legacyPutter} is {@code
   *     null}
   * @throws InvalidObjectException if the legacy object cannot be adapted safely
   */
  ClientPutExecution wrapLegacySingleFileExecution(Object legacyPutter)
      throws InvalidObjectException;

  /**
   * Converts a legacy directory putter object into the adapter-owned execution handle.
   *
   * @param legacyPutter serialized legacy runtime putter, or {@code null} when none was persisted
   * @param executionSpec detached adapter-owned execution metadata required to rebuild callbacks
   * @return adapter-owned execution wrapper, or {@code null} when {@code legacyPutter} is {@code
   *     null}
   * @throws InvalidObjectException if the legacy object cannot be adapted safely
   */
  ClientPutDirExecution wrapLegacyDirectoryExecution(
      Object legacyPutter, ClientPutDirExecutionSpec executionSpec) throws InvalidObjectException;
}
