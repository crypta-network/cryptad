package com.onionnetworks.fec;

import com.onionnetworks.util.Util;

/**
 * Forward error correction (FEC) codec that operates on 16-bit symbols using the classic Rizzo
 * Vandermonde construction. It produces systematic parity shards compatible with the rest of the
 * {@code com.onionnetworks.fec} family while keeping all arithmetic in Java to simplify platform
 * portability.
 *
 * <p>This implementation targets scenarios where the encoder and decoder must exchange a small
 * number of repair blocks for comparatively large payloads and where native bindings are
 * undesirable. Typical call flow: allocate the codec with {@linkplain #Pure16Code(int, int)}, call
 * {@link #encode(byte[][], int[], byte[][], int[], int[], int)} to generate repair packets, and use
 * {@link #decode(byte[][], int[], int[], int, boolean)} to reconstruct missing data. It maintains
 * no shared mutable state beyond the precomputed encoding matrix, so a single instance may be
 * reused across independent jobs when external synchronization protects concurrent calls.
 *
 * <p>Key characteristics:
 *
 * <ul>
 *   <li>Systematic output: source packets are copied directly when possible to minimize work.
 *   <li>Deterministic arithmetic: all math uses the {@link FECMath} tables for 16-bit fields.
 *   <li>Thread-safety: callers must serialize access; the class itself performs no locking.
 * </ul>
 *
 * <p>(c) Copyright 2001 Onion Networks (c) Copyright 2000 OpenCola
 *
 * @author Justin F. Chapweske (justin@chapweske.com)
 * @see FECMath
 * @see PureCode
 */
public class Pure16Code extends PureCode {

  /**
   * Shared arithmetic tables for the GF(2^16) field, precomputed once to amortize table generation
   * across all codec instances created within the process.
   */
  protected static final FECMath fecMath = new FECMath(16);

  /**
   * Constructs a codec for a specific block configuration and precomputes the systematic encoding
   * matrix for later reuse.
   *
   * <p>Notes about large {@code n} support: you can generate the top {@code k*k} Vandermonde
   * matrix, call it {@code V}, invert it, generate a matrix {@code M} with the {@code k} rows you
   * need (r<sub>i</sub>), and compute {@code E = M * V^{-1}} as the encoding matrix for the
   * systematic code. Inversion of {@code E} may be simplified because {@code M} is also
   * Vandermonde.
   *
   * @param k number of source packets that form the original data set; must be positive.
   * @param n total number of packets including repair packets; must satisfy {@code n >= k}.
   */
  public Pure16Code(int k, int n) {
    super(k, n, fecMath.createEncodeMatrix(k, n));
  }

  /**
   * Encodes a batch of repair packets from source data expressed as byte buffers, leaving
   * systematic packets untouched when the requested index corresponds to original data.
   *
   * <p>The method expects packets to be aligned on 16-bit boundaries; misaligned buffers result in
   * an {@link IllegalArgumentException}. Repair data is derived using the precomputed encoding
   * matrix without modifying the input buffers. The caller must allocate {@code repair} arrays of
   * the correct length and ensure offsets are valid for all packets.
   *
   * @param src source packet array containing {@code k} data shards in little-endian byte order;
   *     null values are not permitted.
   * @param srcOff per-packet byte offsets indicating where each source shard begins in {@code src};
   *     lengths must align with {@code packetLength}.
   * @param repair destination array that will receive newly encoded parity shards; entries must be
   *     writable and sized to {@code packetLength}.
   * @param repairOff per-repair offsets measured in bytes; each value points to the start of the
   *     writable region inside the corresponding repair buffer.
   * @param index packet indexes for each repair buffer; values below {@code k} trigger direct
   *     copying, while values between {@code k} and {@code n - 1} compute parity.
   * @param packetLength length in bytes for every packet; must be even so it can be mapped to
   *     16-bit symbols.
   */
  @Override
  protected void encode(
      byte[][] src, int[] srcOff, byte[][] repair, int[] repairOff, int[] index, int packetLength) {
    if (packetLength % 2 != 0) {
      throw new IllegalArgumentException("For 16 bit codes, buffers " + "must be 16 bit aligned.");
    }
    char[][] srcChars = new char[src.length][];
    int[] srcCharsOff = new int[src.length];
    int numChars = packetLength / 2;
    char[] repairChars = new char[numChars];
    for (int i = 0; i < srcChars.length; i++) {
      srcChars[i] = new char[numChars];
      Util.arraycopy(src[i], srcOff[i], srcChars[i], 0, packetLength);
      srcCharsOff[i] = 0;
    }

    for (int i = 0; i < repair.length; i++) {
      if (index[i] < k) { // < k, systematic so direct copy.
        System.arraycopy(src[index[i]], srcOff[index[i]], repair[i], repairOff[i], packetLength);
      } else {
        encode(srcChars, srcCharsOff, repairChars, 0, index[i], numChars);
        Util.arraycopy(repairChars, 0, repair[i], repairOff[i], packetLength);
      }
    }
  }

  /**
   * Performs symbol-level encoding for parity packets once source buffers have been translated to
   * 16-bit arrays.
   *
   * @param src source symbols for each shard expressed as {@code char} arrays; entries must not be
   *     {@code null}.
   * @param srcOff per-source offsets measured in symbols; usually zero after translation from
   *     bytes.
   * @param repair destination array that receives encoded symbols for a single repair shard; must
   *     have room for {@code numChars} entries.
   * @param repairOff symbol offset inside {@code repair} where writing begins; typically zero in
   *     normal use.
   * @param index encoding matrix row associated with the target repair shard; must satisfy {@code
   *     index >= k} and {@code index < n}.
   * @param numChars number of 16-bit symbols per packet; derived from the packet byte length.
   */
  protected void encode(
      char[][] src, int[] srcOff, char[] repair, int repairOff, int index, int numChars) {
    int pos = index * k;
    Util.bzero(repair, repairOff, numChars);
    for (int i = 0; i < k; i++) {
      fecMath.addMul(repair, repairOff, src[i], srcOff[i], encMatrix[pos + i], numChars);
    }
  }

  /**
   * Decodes in-place packet data expressed as byte arrays, reconstructing any missing source shards
   * and normalizing the index array to the canonical order.
   *
   * <p>Packets must represent 16-bit aligned data; odd-length buffers are rejected. When {@code
   * inOrder} is {@code false} the method permutes inputs so that the first {@code k} entries
   * correspond to source shards before invoking the symbol-level decoder. Successful reconstruction
   * writes results back into {@code pkts} and updates {@code index} so callers can treat the output
   * as a reordered source set.
   *
   * @param pkts packet buffers that include both available source shards and repair shards; entries
   *     are modified in place.
   * @param pktsOff byte offsets for each packet indicating where valid data begins; values must be
   *     within array bounds.
   * @param index packet identifiers parallel to {@code pkts}; updated to canonical source ordering
   *     after successful decoding.
   * @param packetLength packet size in bytes; must be divisible by two for 16-bit symbol mapping.
   * @param inOrder whether {@code pkts} and {@code index} already place the first {@code k}
   *     elements in source order; set to {@code true} to skip shuffling overhead.
   */
  @Override
  protected void decode(
      byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean inOrder) {
    if (packetLength % 2 != 0) {
      throw new IllegalArgumentException("For 16 bit codes, buffers " + "must be 16 bit aligned.");
    }

    if (!inOrder) {
      shuffle(pkts, pktsOff, index, k);
    }

    char[][] pktsChars = new char[pkts.length][];
    int[] pktsCharsOff = new int[pkts.length];
    int numChars = packetLength / 2;
    for (int i = 0; i < pktsChars.length; i++) {
      pktsChars[i] = new char[numChars];
      Util.arraycopy(pkts[i], pktsOff[i], pktsChars[i], 0, packetLength);
      pktsCharsOff[i] = 0;
    }

    char[][] result = decode(pktsChars, pktsCharsOff, index, numChars);

    for (int i = 0; i < result.length; i++) {
      if (result[i] != null) {
        Util.arraycopy(result[i], 0, pkts[i], pktsOff[i], packetLength);
        index[i] = i;
      }
    }
  }

  /**
   * Decodes packet symbols expressed as 16-bit arrays, returning reconstructed source shards while
   * leaving existing packets untouched.
   *
   * <p>The method builds a decode matrix for the specific erasure pattern, multiplies repair
   * packets by the matrix rows, and returns a sparse array where non-{@code null} elements contain
   * recovered data. Callers typically copy non-null results back into their packet arrays and
   * adjust indexes to reflect the restored source order.
   *
   * @param pkts packet symbols including source and repair shards; not modified by this method.
   * @param pktsOff symbol offsets for each shard, aligning the start of valid data inside {@code
   *     pkts}.
   * @param index packet identifiers corresponding to {@code pkts}; values guide decode matrix
   *     construction and remain unchanged on return.
   * @param numChars number of symbols per packet; must match {@code pkts[i].length - pktsOff[i]}.
   * @return sparse array sized to {@code k} where recovered source shards are populated and missing
   *     entries remain {@code null}.
   */
  protected char[][] decode(char[][] pkts, int[] pktsOff, int[] index, int numChars) {

    char[] decMatrix = fecMath.createDecodeMatrix(encMatrix, index, k, n);

    // do the actual decoding
    char[][] tmpPkts = new char[k][];
    for (int row = 0; row < k; row++) {
      if (index[row] >= k) {
        tmpPkts[row] = new char[numChars];
        for (int col = 0; col < k; col++) {
          fecMath.addMul(
              tmpPkts[row], 0, pkts[col], pktsOff[col], decMatrix[row * k + col], numChars);
        }
      }
    }

    return tmpPkts;
  }

  @Override
  public String toString() {
    return "Pure16Code[k=" + k + ",n=" + n + "]";
  }
}
