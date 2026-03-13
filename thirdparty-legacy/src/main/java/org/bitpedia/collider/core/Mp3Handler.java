/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Mp3Handler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.nio.charset.StandardCharsets;
import org.bitpedia.util.Sha1;

/**
 * Parses MP3 frame headers to derive basic audio characteristics and a sliding-window audio
 * fingerprint.
 *
 * <p>This handler incrementally scans byte buffers that may arrive in arbitrary chunk sizes and
 * tolerates leading garbage or truncated frames. It searches for a sequence of three coherent MPEG
 * frames, records sample rate, stereo flag, MPEG version and bitrate information, and maintains a
 * running SHA-1 digest over audio payload bytes while ignoring ID3 metadata. Typical usage follows
 * a three-step lifecycle: call {@link #analyzeInit()}, feed blocks via {@link
 * #analyzeUpdate(byte[], int, int)}, then finalize with {@link #analyzeFinal()} to obtain derived
 * metrics. Instances are stateful and not thread-safe; callers should create one instance per
 * analysis flow. All extracted values remain mutable until finalization, allowing mid-stream resets
 * when the majority of input proves invalid.
 *
 * <ul>
 *   <li>Locates the probable start of audio data before processing frames.
 *   <li>Computes duration and average bitrate from counted frames.
 *   <li>Produces an audio SHA-1 that excludes trailing ID3 tags when present.
 * </ul>
 *
 * @see #analyzeInit()
 * @see #analyzeUpdate(byte[], int, int)
 * @see #analyzeFinal()
 */
public class Mp3Handler {

  private static final int[] mpeg1Bitrates = {
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320
  };
  private static final int[] mpeg2Bitrates = {
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160
  };
  private static final int[] mpeg1SampleRates = {44100, 48000, 32000};
  private static final int[] mpeg2SampleRates = {22050, 24000, 16000};
  private static final int[] mpegLayer = {0, 3, 2, 1};

  /**
   * Standard ID3v1 tag length in bytes retained for trailing tag detection when hashing audio
   * payloads. The sliding window keeps this many bytes to avoid polluting the audio SHA with
   * metadata appended to the stream.
   */
  public static final int ID3_TAG_LEN = 128;

  private int bitRate;
  private int sampleRate;
  private boolean stereo;
  private int duration;
  private byte[] audioSha;
  private int frames;
  private int mpegVer;
  private int avgBitRate;

  private int skipSize;
  private byte[] spanningHeader;
  private int spanningSize;
  private Sha1 sha;
  private int goodBytes;
  private int badBytes;
  private byte[] startBuffer;
  private int startBytes;
  private byte[] audioShaBuffer;
  private byte[] audioShaExtra;
  private int audioShaBytes;

  /**
   * Returns the constant bitrate observed in the first validated frame sequence, or {@code 0} when
   * mixed bitrates or insufficient data prevent a definitive value.
   *
   * <p>The value is derived from the first three coherent frames identified by {@link
   * #analyzeUpdate(byte[], int, int)} and remains stable unless a later frame contradicts the
   * initial reading, in which case it is reset to {@code 0} to represent variable bitrate input.
   * Callers typically invoke this after {@link #analyzeFinal()} to ensure the detection phase has
   * finished.
   *
   * @return bitrate in kilobits per second, or {@code 0} when indeterminate
   */
  public int getBitRate() {
    return bitRate;
  }

  /**
   * Manually overrides the detected bitrate value stored by this handler.
   *
   * <p>This setter is primarily useful for tests or callers that inject trusted metadata when
   * parsing is skipped or incomplete. Regular analysis paths assign the value automatically based
   * on the first validated frame sequence and later clear it if a conflicting bitrate appears, so
   * manual overrides should only be applied when the caller can guarantee consistency.
   *
   * @param bitRate bitrate in kilobits per second; use {@code 0} to disable
   */
  public void setBitRate(int bitRate) {
    this.bitRate = bitRate;
  }

  /**
   * Returns the sample rate detected from the first valid frame sequence.
   *
   * <p>The sample rate represents the playback frequency in hertz reported by MPEG headers. It is
   * captured on the first accepted frame and reused for duration and frame-size calculations. If
   * later frames disagree, detection halts and the value is cleared to {@code 0} to signal
   * uncertainty.
   *
   * @return sample rate in hertz; {@code 0} when no valid frames have been processed
   */
  public int getSampleRate() {
    return sampleRate;
  }

  /**
   * Records a sample rate value, overriding what frame parsing may have discovered.
   *
   * <p>Use this when external metadata provides a definitive rate, or when unit tests need to seed
   * a specific value. Overriding does not prevent subsequent parsing from clearing the value if
   * mismatched frames are encountered.
   *
   * @param sampleRate sample rate in hertz; use {@code 0} to clear
   */
  public void setSampleRate(int sampleRate) {
    this.sampleRate = sampleRate;
  }

  /**
   * Indicates whether the parsed stream reports a stereo channel mode.
   *
   * <p>The flag is derived from the channel mode bits in the first validated frame and remains
   * unchanged for the lifetime of the analysis unless explicitly overridden. Mono streams return
   * {@code false}, joint stereo or dual-channel streams return {@code true}.
   *
   * @return {@code true} when the first validated frame is not mono; {@code false} otherwise
   */
  public boolean isStereo() {
    return stereo;
  }

  /**
   * Sets the stereo flag manually.
   *
   * <p>Setting this value does not alter how frames are parsed; it only adjusts the reported state
   * for clients that rely on externally verified channel information. Downstream metrics such as
   * duration remain unaffected, but UI consumers may display the forced mode instead of the
   * detected one when this override is used.
   *
   * @param stereo {@code true} to force stereo reporting; {@code false} for mono
   */
  public void setStereo(boolean stereo) {
    this.stereo = stereo;
  }

  /**
   * Returns the calculated duration based on counted frames and MPEG version.
   *
   * <p>The duration is computed during {@link #analyzeFinal()} using frame counts and the detected
   * sample rate. Because frame sizes differ between MPEG versions, a value of {@code 0} indicates
   * either missing rate information or too few frames to establish a reliable length.
   *
   * @return duration in milliseconds; {@code 0} when insufficient data prevents calculation
   */
  public int getDuration() {
    return duration;
  }

  /**
   * Assigns a duration value, replacing any computed result.
   *
   * <p>External callers may set this when duration is known from container metadata or earlier
   * processing steps. Subsequent calls to {@link #analyzeFinal()} will overwrite the value based on
   * frame-derived metrics unless the analysis is reset. This allows batch tools to harmonize
   * reported lengths across multiple detectors without reprocessing audio data.
   *
   * @param duration total duration in milliseconds; {@code 0} clears the current value
   */
  public void setDuration(int duration) {
    this.duration = duration;
  }

  /**
   * Returns the computed SHA-1 digest over audio payload bytes.
   *
   * <p>The digest excludes trailing ID3v1 tags and any non-audio data preceding the first valid
   * frame, mirroring how typical audio fingerprinting tools treat metadata. The byte array is not
   * copied; callers should clone it if they require immutability.
   *
   * @return 20-byte SHA-1 digest, or {@code null} when analysis has not been finalized
   */
  public byte[] getAudioSha() {
    return audioSha;
  }

  /**
   * Injects a precomputed SHA-1 digest for the analyzed audio.
   *
   * <p>The provided array is stored by reference; callers should supply a defensive copy if the
   * backing data might be reused elsewhere. Manual injection is helpful when the digest is computed
   * by an external pipeline and this handler is used solely for reporting or compatibility with
   * existing interfaces.
   *
   * @param audioSha SHA-1 digest bytes to set; may be {@code null} to clear
   */
  public void setAudioSha(byte[] audioSha) {
    this.audioSha = audioSha;
  }

  /**
   * Returns the number of valid frames processed during analysis.
   *
   * <p>This counter increments each time a frame passes header sanity checks and matches the
   * expected sample rate. Frames that fail validation contribute to {@code badBytes} but do not
   * affect this total. The count forms the basis for duration and average bitrate calculations.
   *
   * @return count of accepted MPEG frames; {@code 0} when none have been found
   */
  public int getFrames() {
    return frames;
  }

  /**
   * Overrides the internal frame counter.
   *
   * <p>This is mainly intended for deterministic tests. It does not adjust related aggregates such
   * as average bitrate or duration, so callers should ensure the rest of the state matches the new
   * count. Altering this after parsing may result in misleading averages if supporting fields are
   * not updated consistently.
   *
   * @param frames total frame count to record; negative values are not allowed
   */
  public void setFrames(int frames) {
    this.frames = frames;
  }

  /**
   * Returns the MPEG version detected from the first valid frame.
   *
   * <p>The value maps directly to MPEG header bits: {@code 1} represents MPEG-1 streams with 1152
   * samples per frame, while {@code 2} covers MPEG-2 or 2.5 with 576 samples. A value of {@code 0}
   * signals that detection has not yet succeeded.
   *
   * @return {@code 1} for MPEG-1, {@code 2} for MPEG-2/2.5, or {@code 0} when unknown
   */
  public int getMpegVer() {
    return mpegVer;
  }

  /**
   * Sets the MPEG version value explicitly.
   *
   * <p>Manual assignment is rarely needed outside testing scenarios. When set to a value other than
   * {@code 1} or {@code 2}, subsequent computations may reset the field to {@code 0} to avoid
   * misrepresenting stream characteristics.
   *
   * @param mpegVer {@code 1} for MPEG-1 or {@code 2} for MPEG-2/2.5
   */
  public void setMpegVer(int mpegVer) {
    this.mpegVer = mpegVer;
  }

  /**
   * Returns the average bitrate accumulated across all processed frames.
   *
   * <p>The value is calculated in {@link #analyzeFinal()} by summing per-frame bitrates during
   * parsing and dividing by the number of accepted frames. It reflects simple arithmetic mean and
   * does not weight durations differently for variable-size frames.
   *
   * @return average bitrate in kilobits per second; {@code 0} before finalization
   */
  public int getAvgBitRate() {
    return avgBitRate;
  }

  /**
   * Overrides the computed average bitrate.
   *
   * <p>When supplied, the new value replaces any computed mean without adjusting supporting
   * aggregates. This is intended for scenarios where callers possess authoritative metadata or wish
   * to simulate analysis outcomes.
   *
   * @param avgBitRate average bitrate in kilobits per second to store
   */
  public void setAvgBitRate(int avgBitRate) {
    this.avgBitRate = avgBitRate;
  }

  private static int extractBitRate(byte[] header, int ofs) {

    int id = header[ofs + 1] >= 0 ? header[ofs + 1] : header[ofs + 1] + 256;
    int br = header[ofs + 2] >= 0 ? header[ofs + 2] : header[ofs + 2] + 256;

    id = (id & 0x8) >> 3;
    br = (br & 0xF0) >> 4;

    if (0 != id) {
      if (br < mpeg1Bitrates.length) {
        return mpeg1Bitrates[br];
      }
    } else {
      if (br < mpeg2Bitrates.length) {
        return mpeg2Bitrates[br];
      }
    }

    return 0;
  }

  private static int extractSampleRate(byte[] header, int ofs) {

    int id = header[ofs + 1] >= 0 ? header[ofs + 1] : header[ofs + 1] + 256;
    int sr = header[ofs + 2] >= 0 ? header[ofs + 2] : header[ofs + 2] + 256;

    id = (id & 0x8) >> 3;
    sr = (sr >> 2) & 0x3;

    if (0 != id) {
      if (sr < mpeg1SampleRates.length) {
        return mpeg1SampleRates[sr];
      }
    } else {
      if (sr < mpeg2SampleRates.length) {
        return mpeg2SampleRates[sr];
      }
    }

    return 0;
  }

  private static boolean extractStereo(byte[] header, int ofs) {

    int b = header[ofs + 3] >= 0 ? header[ofs + 3] : header[ofs + 3] + 256;
    return 3 != ((b & 0xc0) >> 6);
  }

  private static int extractMpegVer(byte[] header, int ofs) {

    int b = header[ofs + 1] >= 0 ? header[ofs + 1] : header[ofs + 1] + 256;
    if (0 == ((b & 0x8) >> 3)) {
      return 2;
    } else {
      return 1;
    }
  }

  private static int extractMpegLayer(byte[] header, int ofs) {

    int b = header[ofs + 1] >= 0 ? header[ofs + 1] : header[ofs + 1] + 256;
    return mpegLayer[((b & 0x7) >> 1)];
  }

  private static int extractPadding(byte[] header, int ofs) {

    int b = header[ofs + 2] >= 0 ? header[ofs + 2] : header[ofs + 2] + 256;
    return (b >> 1) & 0x1;
  }

  private int findStart(byte[] buffer, int ofs, int len) {

    int goodFrames = 0;
    int goodFrameOffset = -1;

    if (null != startBuffer) {

      byte[] newBuffer = new byte[startBytes + len];
      System.arraycopy(startBuffer, 0, newBuffer, 0, startBytes);
      System.arraycopy(buffer, ofs, newBuffer, startBytes, len);
      startBuffer = newBuffer;
      startBytes += len;
      buffer = startBuffer;
      len = startBytes;
      ofs = 0;
    }

    int max = len;
    int i = 0;
    while (i < max - 1) {
      if (isFrameMarker(buffer, ofs + i)) {
        StartSearchResult result =
            evaluateFrameCandidate(buffer, ofs, len, i, max, goodFrameOffset, goodFrames);
        if (result.foundOffset >= 0) {
          return result.foundOffset;
        }
        if (result.needMoreData) {
          return -1;
        }
        i = result.nextIndex;
        goodFrameOffset = result.goodFrameOffset;
        goodFrames = result.goodFrames;
      } else {
        i++;
      }
    }

    return -1;
  }

  private StartSearchResult evaluateFrameCandidate(
      byte[] buffer, int ofs, int len, int i, int max, int goodFrameOffset, int goodFrames) {
    int firstSampleRate = extractSampleRate(buffer, i + ofs);
    int firstLayer = extractMpegLayer(buffer, i + ofs);

    if (0 == firstSampleRate) {
      return StartSearchResult.advance(i + 1, goodFrames, -1);
    }

    int size = calculateFrameSize(buffer, i + ofs);
    if (isInvalidFrameSize(size)) {
      return StartSearchResult.advance(i + 1, goodFrames, -1);
    }
    if (max <= i + size) {
      storeStartBuffer(buffer, ofs, len);
      return StartSearchResult.needMoreData();
    }

    boolean matchesNext = hasMatchingNextFrame(buffer, ofs + i, size, firstSampleRate, firstLayer);
    if (matchesNext) {
      int updatedGoodFrames = goodFrames + 1;
      int updatedOffset = goodFrameOffset < 0 ? i : goodFrameOffset;
      if (3 == updatedGoodFrames) {
        return StartSearchResult.found(updatedOffset);
      }
      return StartSearchResult.advance(i + size, updatedGoodFrames, updatedOffset);
    }

    int nextIndex = (goodFrameOffset >= 0) ? goodFrameOffset + 1 : i + 1;
    return StartSearchResult.advance(nextIndex, 0, -1);
  }

  private boolean hasMatchingNextFrame(
      byte[] buffer, int offset, int size, int firstSampleRate, int firstLayer) {
    int secondSampleRate = extractSampleRate(buffer, offset + size);
    int secondLayer = extractMpegLayer(buffer, offset + size);
    return (firstSampleRate == secondSampleRate) && (firstLayer == secondLayer);
  }

  private void storeStartBuffer(byte[] buffer, int ofs, int len) {
    if (null == startBuffer) {
      startBytes = len;
      startBuffer = new byte[len];
      System.arraycopy(buffer, ofs, startBuffer, 0, len);
    }
  }

  private int calculateFrameSize(byte[] buffer, int offset) {
    int br = extractBitRate(buffer, offset);
    int sr = extractSampleRate(buffer, offset);
    int pd = extractPadding(buffer, offset);
    if (1 == extractMpegVer(buffer, offset)) {
      return (144000 * br) / sr + pd;
    } else {
      return (72000 * br) / sr + pd;
    }
  }

  private boolean isInvalidFrameSize(int size) {
    return (size <= 1) || (size > 2048);
  }

  private boolean isFrameMarker(byte[] buffer, int index) {
    int bi = buffer[index] >= 0 ? buffer[index] : buffer[index] + 256;
    int bi1 = buffer[index + 1] >= 0 ? buffer[index + 1] : buffer[index + 1] + 256;
    return (0xFF == bi) && ((0xF0 == (bi1 & 0xF0)) || (0xE0 == (bi1 & 0xF0)));
  }

  private boolean isNotFrameMarker(byte[] buffer, int index) {
    return !isFrameMarker(buffer, index);
  }

  private void resetValues() {

    bitRate = 0;
    sampleRate = 0;
    stereo = false;
    duration = 0;
    audioSha = null;
    frames = 0;
    mpegVer = 0;
    avgBitRate = 0;

    skipSize = 0;
    spanningHeader = new byte[3];
    spanningSize = 0;
    sha = new Sha1();
    goodBytes = 0;
    badBytes = 0;
    startBuffer = null;
    startBytes = 0;
    audioShaBuffer = null;
    audioShaExtra = new byte[3];
    audioShaBytes = 0;
  }

  /**
   * Resets all detected metrics and prepares the handler for a new analysis cycle.
   *
   * <p>Call this before supplying any data buffers. It clears prior counters, SHA state, cached
   * frame headers, and sliding windows so subsequent calls to {@link #analyzeUpdate(byte[], int,
   * int)} operate on a clean slate.
   */
  public void analyzeInit() {

    resetValues();
  }

  /**
   * Convenience overload that analyzes a full buffer from offset {@code 0}.
   *
   * @param buffer byte array containing MP3 data or partial frames
   * @param len number of bytes from {@code buffer} to process from index zero
   */
  public void analyzeUpdate(byte[] buffer, int len) {

    analyzeUpdate(buffer, 0, len);
  }

  /**
   * Consumes a slice of the provided buffer, updating detection state and the audio SHA.
   *
   * <p>The method tolerates fragmented frames and will cache spanning headers when a frame crosses
   * buffer boundaries. On first invocation it searches past ID3 tags and other leading data until a
   * sequence of three coherent frames is confirmed. Subsequent calls continue parsing, counting
   * frames, updating bitrate and stereo flags, and extending the sliding SHA window. No data is
   * retained beyond the minimal window needed for trailing tag exclusion.
   *
   * @param buffer source buffer holding MP3 data and possible leading noise
   * @param ofs starting offset within {@code buffer}; must be zero or positive
   * @param len number of bytes to analyze from {@code buffer} starting at {@code ofs}
   */
  public void analyzeUpdate(byte[] buffer, int ofs, int len) {

    /* If this is the first time in the update function, then seek to
    find the actual start of the mp3 and skip over any ID3 tags or garbage
    that might be at the beginning of the file */
    if ((0 == badBytes) && (0 == goodBytes)) {

      int offset = findStart(buffer, ofs, len);
      if (offset < 0) {
        return;
      }

      /* If it took more than one block to determine the start of the mp3
      file, then use the buffer that was created by the find_mp3_start
      routine, rather than the buffer that was passed in. */
      if (null != startBuffer) {
        buffer = startBuffer;
        len = startBytes;
        ofs = 0;
      }

      /* Skip over the crap at the beginning of the file */
      ofs += offset;
      len -= offset;
    }

    /* If the header spanned the last block and this block, then
    allocate a larger buffer and copy the last header plus the new
    block into the new buffer and work on it. This shouldn't happen
    very often. */
    if (0 < spanningSize) {
      byte[] tempBuffer = new byte[len + spanningSize];
      System.arraycopy(spanningHeader, 0, tempBuffer, 0, spanningSize);
      System.arraycopy(buffer, ofs, tempBuffer, spanningSize, len);
      len += spanningSize;
      buffer = tempBuffer;
      ofs = 0;
    }

    /* Pass the bytes we're skipping through the sha function */
    updateAudioSha1(buffer, ofs, skipSize);

    /* Save the three bytes immediately following the last audio sha
    block for later. These bytes will be used to check for ID3
    tags at the end of truncated audio frames. See mp3_final for
    more details. */
    System.arraycopy(buffer, ofs + skipSize, audioShaExtra, 0, 3);

    /* Loop through the buffer trying to find frames */
    int i = ofs + skipSize;
    int max = ofs + len;
    while (i < max) {

      if (hasInsufficientHeaderBytes(i, max)) {
        saveSpanningHeader(buffer, i, max);
        return;
      }

      FrameInfo frameInfo = parseFrame(buffer, i);
      if (frameInfo == null) {
        i++;
      } else if (isSampleRateMismatch(frameInfo.sampleRate())) {
        badBytes++;
        i++;
      } else {
        updateOnFrame(buffer, i, max, frameInfo);
        i += frameInfo.size();
      }
    }

    skipSize = i - max;
    spanningSize = 0;
  }

  private boolean hasInsufficientHeaderBytes(int index, int max) {
    return (max - index) < 4;
  }

  private void saveSpanningHeader(byte[] buffer, int index, int max) {
    spanningSize = max - index;
    System.arraycopy(buffer, index, spanningHeader, 0, spanningSize);
    skipSize = 0;
  }

  private FrameInfo parseFrame(byte[] buffer, int index) {
    if (isNotFrameMarker(buffer, index)) {
      badBytes++;
      return null;
    }

    int sampleRateValue = extractSampleRate(buffer, index);
    if (0 == sampleRateValue) {
      badBytes++;
      return null;
    }

    int bitRateValue = extractBitRate(buffer, index);
    int padding = extractPadding(buffer, index);
    int version = extractMpegVer(buffer, index);
    int size =
        (1 == version)
            ? (144000 * bitRateValue) / sampleRateValue + padding
            : (72000 * bitRateValue) / sampleRateValue + padding;

    if (isInvalidFrameSize(size)) {
      badBytes++;
      return null;
    }

    boolean stereoFlag = extractStereo(buffer, index);
    return new FrameInfo(size, sampleRateValue, bitRateValue, version, stereoFlag);
  }

  private boolean isSampleRateMismatch(int frameSampleRate) {
    return (0 != frames) && (sampleRate != frameSampleRate);
  }

  private void updateOnFrame(byte[] buffer, int index, int max, FrameInfo frameInfo) {
    if (0 == frames) {
      sampleRate = frameInfo.sampleRate();
      bitRate = frameInfo.bitRate();
      mpegVer = frameInfo.mpegVer();
      stereo = frameInfo.stereo();
    } else if ((0 != bitRate) && (bitRate != frameInfo.bitRate())) {
      bitRate = 0;
    }

    int bytesLeft = max - index;
    int frameSize = Math.min(frameInfo.size(), bytesLeft);
    updateAudioSha1(buffer, index, frameSize);

    if (index + frameSize + 3 < buffer.length) {
      System.arraycopy(buffer, index + frameSize, audioShaExtra, 0, 3);
    }

    frames++;
    goodBytes += frameInfo.size();
    avgBitRate += frameInfo.bitRate();
  }

  private int calculateDuration() {
    if (1 == mpegVer) {
      return frames * 1152 / (sampleRate / 1000);
    }
    return frames * 576 / (sampleRate / 1000);
  }

  private boolean shouldResetResults() {
    return (goodBytes < badBytes) || (0 == goodBytes);
  }

  private void updateAudioShaWithTrailingTag() {
    if (null == audioShaBuffer) {
      return;
    }

    System.arraycopy(audioShaExtra, 0, audioShaBuffer, ID3_TAG_LEN, 3);
    int i;
    for (i = 0; i < ID3_TAG_LEN; i++) {

      if ("TAG".equals(new String(audioShaBuffer, i, 3, StandardCharsets.ISO_8859_1))) {
        break;
      }
    }

    if (ID3_TAG_LEN < i) {
      i = ID3_TAG_LEN;
    }

    sha.engineUpdate(audioShaBuffer, 0, i);
  }

  private static final class StartSearchResult {
    private final int nextIndex;
    private final int goodFrames;
    private final int goodFrameOffset;
    private final boolean needMoreData;
    private final int foundOffset;

    private StartSearchResult(
        int nextIndex, int goodFrames, int goodFrameOffset, boolean needMoreData, int foundOffset) {
      this.nextIndex = nextIndex;
      this.goodFrames = goodFrames;
      this.goodFrameOffset = goodFrameOffset;
      this.needMoreData = needMoreData;
      this.foundOffset = foundOffset;
    }

    private static StartSearchResult advance(int nextIndex, int goodFrames, int goodFrameOffset) {
      return new StartSearchResult(nextIndex, goodFrames, goodFrameOffset, false, -1);
    }

    private static StartSearchResult needMoreData() {
      return new StartSearchResult(-1, 0, -1, true, -1);
    }

    private static StartSearchResult found(int offset) {
      return new StartSearchResult(-1, 0, -1, false, offset);
    }
  }

  private record FrameInfo(int size, int sampleRate, int bitRate, int mpegVer, boolean stereo) {}

  /**
   * Finalizes analysis, producing the audio SHA digest and computed metrics.
   *
   * <p>This method discards any buffered start data, validates that more good bytes than bad were
   * observed, and updates the SHA to exclude trailing ID3 metadata when present. It then calculates
   * duration and average bitrate from counted frames. If the input was too noisy or empty, all
   * public fields are reset to their default values.
   */
  public void analyzeFinal() {

    startBuffer = null;

    if (shouldResetResults()) {
      resetValues();
      return;
    }

    updateAudioShaWithTrailingTag();
    audioSha = sha.engineDigest();
    duration = calculateDuration();
    avgBitRate /= frames;
  }

  /**
   * Updates the sliding SHA-1 digest with the supplied audio bytes while preserving the last
   * {@value #ID3_TAG_LEN} bytes to detect trailing ID3 tags.
   *
   * <p>The method streams data directly into the digest whenever the sliding window grows beyond
   * the preserved tag length. It ensures at most {@value #ID3_TAG_LEN} bytes remain buffered so
   * {@link #analyzeFinal()} can exclude metadata appended after the audio payload.
   *
   * @param buf source buffer containing raw audio bytes; must not be {@code null}
   * @param ofs starting offset into {@code buf} from which to read
   * @param bufLen number of bytes to feed into the digest window
   */
  public void updateAudioSha1(byte[] buf, int ofs, int bufLen) {

    /* Allocate the space for the audiosha sliding window. Allocate three
    extra bytes to allow for the possibility that the ID3 tag spans
    the outer boundary of the audiosha sliding window */
    if (null == audioShaBuffer) {
      audioShaBuffer = new byte[ID3_TAG_LEN + 3];
    }

    /* Save the last 128 bytes of the given buffer and audio sha all the
    bytes passed through the sliding window */
    if (ID3_TAG_LEN < bufLen + audioShaBytes) {
      if (ID3_TAG_LEN <= bufLen) {
        sha.engineUpdate(audioShaBuffer, 0, audioShaBytes);
        sha.engineUpdate(buf, ofs, bufLen - ID3_TAG_LEN);
        System.arraycopy(buf, ofs + bufLen - ID3_TAG_LEN, audioShaBuffer, 0, ID3_TAG_LEN);
        audioShaBytes = ID3_TAG_LEN;
      } else {
        int bytesToRemove = audioShaBytes + bufLen - ID3_TAG_LEN;
        sha.engineUpdate(audioShaBuffer, 0, bytesToRemove);
        System.arraycopy(
            audioShaBuffer, bytesToRemove, audioShaBuffer, 0, audioShaBytes - bytesToRemove);
        System.arraycopy(buf, ofs, audioShaBuffer, audioShaBytes - bytesToRemove, bufLen);
        audioShaBytes = audioShaBytes - bytesToRemove + bufLen;
      }
    } else {
      System.arraycopy(buf, ofs, audioShaBuffer, audioShaBytes, bufLen);
      audioShaBytes += bufLen;
    }
  }
}
