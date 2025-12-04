/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Submission.java,v 1.3 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.bitpedia.util.ArrayUtils;
import org.bitpedia.util.Base32;

/**
 * Orchestrates collection, hashing, and formatting of file metadata for Bitzi submissions. A {@code
 * Submission} instance accumulates attributes across one or more files, computes multiple hashes,
 * and can render the resulting payload as an auto-submitting HTML form. The class maintains mutable
 * state as files are analyzed, so callers should create one instance per end-to-end submission
 * rather than sharing across threads.
 *
 * <p>Typical usage is: construct with a {@link Bitcollider} context, call {@link
 * #analyzeFile(String, boolean)} for each file to hash and tag, then emit the HTML via {@link
 * #makeHtml(PrintWriter, String)}. Progress and warning callbacks are delegated to the supplied
 * {@link Bitcollider} instance. File attributes are automatically prefixed to keep multi-file
 * submissions consistent with the Bitzi wire format.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Coordinating hash calculators (bitprint, CRC32, MD5, ED2K, Kazaa tree).
 *   <li>Capturing format-specific attributes from registered {@link FormatHandler} implementations.
 *   <li>Deriving MP3 metadata when requested and merging it into the attribute map.
 *   <li>Generating an HTML submission compatible with Bitzi web endpoints.
 * </ul>
 *
 * <p>Instances are not thread-safe; concurrent callers should synchronize externally or prefer
 * separate instances. Attribute maps are preserved in insertion order to match user-visible output,
 * and header handling automatically transitions from single-file to multi-file keys when a second
 * bitprint is added.
 *
 * @see Bitcollider
 * @see FormatHandler
 */
public class Submission {

  private static final String SUBMIT_URL = "http://bitzi.com/lookup/";

  private static final int FIRST_N_HEX = 20;

  private final Bitcollider bc;

  private Map<String, String> attrs = new LinkedHashMap<>();

  private int numBitprints = 0;

  private String fileName;

  private long fileSize;

  private boolean autoSubmit;

  private String checkAsExt;

  private int percentComplete = 0;

  /**
   * Container for the computed digests and derived metadata for a single analyzed file. Each field
   * mirrors one hashing algorithm or supplementary attribute collected during the analysis pass.
   * Instances are populated by {@link Submission#getBitprintData(String, Hashes, Mp3Handler,
   * FormatHandler)} and then read during attribute emission; callers should treat fields as
   * read-only after population. The map {@link #attrs} carries additional format-specific values
   * provided by {@link FormatHandler#analyzeFinal()} when in-memory analysis is supported.
   */
  public static class Hashes {
    String bitprint;

    String crc32Hex;

    String md5Sum;

    String ed2Kmd4Sum;

    String kzHashSum;

    String firstHex;

    Map<String, String> attrs;

    /**
     * Creates an empty container ready to receive hash outputs for a single file. All fields remain
     * {@code null} until {@link Submission#getBitprintData(String, Hashes, Mp3Handler,
     * FormatHandler)} populates them during analysis, at which point callers should treat the
     * instance as read-only.
     */
    public Hashes() {
      // Intentionally empty: fields stay null until analysis populates them.
    }
  }

  private static class AnalysisInputs {
    boolean mp3Check;
    FormatHandler fmtHandler;
  }

  private static class HashAlgorithms {
    final Bitprint bitprint = new Bitprint();
    int crc32 = 0xffffffff;
    final Md5Handler md5 = new Md5Handler();
    final Ed2Handler ed2 = new Ed2Handler();
    final FtuuHandler ftuu = new FtuuHandler();
    final KzTreeHandler kz = new KzTreeHandler();
  }

  /**
   * Creates a new submission context bound to a {@link Bitcollider} instance. The constructor sets
   * the initial extension override and whether generated HTML should auto-submit. Callers typically
   * allocate one {@code Submission} per batch of files so that accumulated attributes and header
   * handling remain consistent. The provided {@link Bitcollider} supplies progress callbacks,
   * hashing feature toggles, and format handlers. No I/O is performed here; hashing begins only
   * after {@link #analyzeFile(String, boolean)} is invoked. Instances remain mutable so the caller
   * can adjust submission flags before analysis starts.
   *
   * @param bc owning {@link Bitcollider} used for configuration, progress reporting, and errors.
   * @param checkAsExt explicit extension override applied before format detection when non-null.
   * @param autoSubmit whether rendered HTML should include on-load form submission semantics.
   */
  public Submission(Bitcollider bc, String checkAsExt, boolean autoSubmit) {

    this.bc = bc;
    this.checkAsExt = checkAsExt;
    this.autoSubmit = autoSubmit;
  }

  /**
   * Indicates whether the HTML generated by this submission should auto-submit when loaded in a
   * browser. This flag is set at construction time but can be toggled via {@link
   * #setAutoSubmit(boolean)} before emitting the form. Clients can use it to opt into manual review
   * flows when batching many files or to enable zero-click submission in trusted contexts. The
   * value does not influence hashing; it is consulted only when building the HTML payload inside
   * {@link #makeHtml(PrintWriter, String)}.
   *
   * @return {@code true} when an on-load handler should submit the form without user interaction.
   */
  public boolean isAutoSubmit() {
    return autoSubmit;
  }

  /**
   * Updates whether the generated HTML form should auto-submit on page load. Call this before
   * invoking {@link #makeHtml(PrintWriter, String)} to switch between hands-free submissions and
   * user-driven review. Changing the flag does not alter any collected attributes or hashes and can
   * be performed multiple times; the most recent value is applied during HTML generation.
   *
   * @param autoSubmit {@code true} to emit an {@code onLoad} submit hook; {@code false} to require
   *     explicit user action.
   */
  @SuppressWarnings("unused")
  public void setAutoSubmit(boolean autoSubmit) {
    this.autoSubmit = autoSubmit;
  }

  /**
   * Returns the extension override configured for forthcoming analyses. When non-null, this value
   * is substituted for the file's natural extension so the associated {@link FormatHandler} is used
   * even if the filename suggests a different type. The value is read during {@link
   * #resolveInputs(String)} and does not affect previously processed files.
   *
   * @return current extension override or {@code null} when automatic detection is preferred.
   */
  @SuppressWarnings("unused")
  public String getCheckAsExt() {
    return checkAsExt;
  }

  /**
   * Sets an explicit extension to use for subsequent file analyses. Supply a lowercase extension
   * such as {@code "mp3"} or {@code "ogg"} to force a particular {@link FormatHandler}, or {@code
   * null} to resume deriving the extension from each filename. The chosen value is consumed when
   * {@link #resolveInputs(String)} runs and will not retroactively alter completed analyses.
   *
   * @param checkAsExt extension string to force during format detection, or {@code null} to reset.
   */
  @SuppressWarnings("unused")
  public void setCheckAsExt(String checkAsExt) {
    this.checkAsExt = checkAsExt;
  }

  /**
   * Retrieves a previously recorded attribute by its submission key. Keys for secondary files are
   * automatically prefixed with an index (for example {@code "1.tag.file.length"}); callers must
   * supply the fully qualified key to retrieve those entries. The returned string is immutable and
   * owned by this submission, so callers should not attempt to modify shared state through it.
   *
   * @param key fully qualified attribute key including any multi-file prefix.
   * @return attribute value when present; otherwise {@code null} if the key is unknown.
   */
  public String getAttribute(String key) {

    return attrs.get(key);
  }

  /**
   * Adds a new attribute to the submission if it has not already been set. When multiple files are
   * processed, keys are auto-prefixed with the current bitprint index to preserve multi-file
   * grouping. Null values are ignored to avoid emitting empty fields, and duplicate keys are not
   * overwritten to keep earlier results stable. This method should be called only from analysis
   * helpers to maintain consistent ordering for HTML output.
   *
   * @param key attribute name; will be prefixed with the file index when applicable.
   * @param value non-null attribute value; null inputs are skipped silently.
   */
  public void addAttribute(String key, String value) {

    if (null == value) {
      return;
    }

    if (numBitprints > 0) {
      key = numBitprints + "." + key;
    }

    if (attrs.containsKey(key)) {
      return;
    }

    attrs.put(key, value);
  }

  private void toMultiple() {

    Map<String, String> newAttrs = new LinkedHashMap<>();

    for (Map.Entry<String, String> entry : attrs.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();

      if ("head.".equals(key.substring(0, 5))) {
        if ("head.version".equals(key)) {
          value = "M" + value.substring(1);
        }
      } else {
        key = "0." + key;
      }

      newAttrs.put(key, value);
    }

    attrs = newAttrs;
  }

  private boolean calculateHashes(
      InputStream stm, Hashes hashes, Mp3Handler mp3, FormatHandler fmt) {

    HashAlgorithms algos = initAlgorithms(mp3, fmt);
    if (algos == null) {
      return false;
    }

    byte[] buffer = new byte[Bitprint.BUFFER_LEN];
    long bytesRead = 0;

    resetProgress();

    for (; ; ) {
      if (bc.isExitNow()) {
        return false;
      }

      int bytes = readChunk(stm, buffer);
      if (bytes == Integer.MIN_VALUE) {
        return false;
      }
      if (bytes <= 0) {
        break;
      }

      bytesRead += bytes;

      updateAnalyzers(buffer, bytes, mp3, fmt, algos);
      updateProgress(bytesRead);
    }
    percentComplete = 100;

    finalizeHashes(hashes, mp3, fmt, algos);
    return true;
  }

  private HashAlgorithms initAlgorithms(Mp3Handler mp3, FormatHandler fmt) {
    HashAlgorithms algos = new HashAlgorithms();

    if (!algos.bitprint.analyzeInit()) {
      bc.setError(Bitcollider.ERROR_HASHCHECK);
      return null;
    }

    if (null != mp3) {
      mp3.analyzeInit();
    }

    if ((null != fmt) && fmt.supportsMemAnalyze()) {
      fmt.analyzeInit();
    }

    if (!bc.isCalcCrc32()) {
      algos.crc32 = 0;
    }
    if (bc.isCalcMd5()) {
      algos.md5.analyzeInit();
    }
    algos.ed2.analyzeInit();
    algos.ftuu.analyzeInit();
    algos.kz.analyzeInit();

    return algos;
  }

  private void resetProgress() {
    percentComplete = 0;
    if ((null != bc.getProgress()) && !bc.isPreview()) {
      bc.getProgress().progress(0, fileName, null);
    }
  }

  private int readChunk(InputStream stm, byte[] buffer) {
    try {
      return stm.read(buffer);
    } catch (IOException e) {
      bc.setError(Bitcollider.ERROR_HASHCHECK);
      return Integer.MIN_VALUE;
    }
  }

  private void updateAnalyzers(
      byte[] buffer, int bytes, Mp3Handler mp3, FormatHandler fmt, HashAlgorithms algos) {

    algos.bitprint.analyzeUpdate(buffer, 0, bytes);
    if (null != mp3) {
      mp3.analyzeUpdate(buffer, 0, bytes);
    }
    if ((null != fmt) && fmt.supportsMemAnalyze()) {
      fmt.analyzeUpdate(buffer, bytes);
    }

    if (bc.isCalcCrc32()) {
      algos.crc32 = FtuuHandler.hashSmallHash(buffer, 0, bytes, algos.crc32);
    }
    if (bc.isCalcMd5()) {
      algos.md5.analyzeUpdate(buffer, bytes);
    }

    algos.ed2.analyzeUpdate(buffer, 0, bytes);
    algos.ftuu.analyzeUpdate(buffer, 0, bytes);
    algos.kz.analyzeUpdate(buffer, 0, bytes);
  }

  private void updateProgress(long bytesRead) {
    if ((null != bc.getProgress()) && !bc.isPreview()) {
      int percent = (int) ((bytesRead * 100) / fileSize);
      if (percent != percentComplete) {
        bc.getProgress().progress(percent, null, null);
        percentComplete = percent;
      }
    }
  }

  private void finalizeHashes(
      Hashes hashes, Mp3Handler mp3, FormatHandler fmt, HashAlgorithms algos) {

    byte[] bitprintRaw = algos.bitprint.analyzeFinal();
    String tmp = Base32.encode(bitprintRaw);
    hashes.bitprint =
        tmp.substring(0, Bitprint.SHA_BASE32SIZE) + '.' + tmp.substring(Bitprint.SHA_BASE32SIZE);

    if (null != mp3) {
      mp3.analyzeFinal();
    }

    if ((null != fmt) && fmt.supportsMemAnalyze()) {
      hashes.attrs = castStringMap(fmt.analyzeFinal());
    }

    if (bc.isCalcCrc32()) {
      int crc32 = ~algos.crc32;
      hashes.crc32Hex = String.format("%08x", crc32);
    }

    if (bc.isCalcMd5()) {
      byte[] md5Digest = algos.md5.analyzeFinal();
      hashes.md5Sum = ArrayUtils.byteArrayToHex(md5Digest, 0, md5Digest.length);
    }

    byte[] ed2Digest = algos.ed2.analyzeFinal();
    byte[] ftuuDigest = algos.ftuu.analyzeFinal();
    byte[] kzDigest = algos.kz.analyzeFinal();

    hashes.ed2Kmd4Sum = ArrayUtils.byteArrayToHex(ed2Digest, 0, ed2Digest.length);
    hashes.kzHashSum =
        ArrayUtils.byteArrayToHex(ftuuDigest, 0, ftuuDigest.length)
            + ArrayUtils.byteArrayToHex(kzDigest, 0, kzDigest.length);
  }

  private String generateFirstHex(InputStream stm) {

    byte[] buf = new byte[FIRST_N_HEX];
    try {
      int bytesRead = stm.read(buf);
      if (bytesRead < 0) {
        return "";
      }

      return ArrayUtils.byteArrayToHex(buf, 0, bytesRead);

    } catch (IOException e) {
      return null;
    }
  }

  /**
   * Computes the full set of hashes and derived attributes for a single file. The method streams
   * the file twice: once to feed the hashing algorithms and again to capture the first twenty bytes
   * for display. It populates the supplied {@link Hashes} instance with bitprint, CRC32, MD5, ED2K,
   * Kazaa tree, and optional format-specific metadata. Any read or hashing failures are surfaced
   * through the {@link Bitcollider} error channel and result in {@code false}.
   *
   * @param fileName path to the file that will be opened and read sequentially.
   * @param hashes mutable container that receives computed digests and derived attributes.
   * @param mp3 optional MP3 handler used when MP3-specific parsing is enabled; may be {@code null}.
   * @param fmt optional format handler that can provide additional metadata during analysis.
   * @return {@code true} when all hashes and the leading hex snippet are produced successfully;
   *     {@code false} if I/O errors occur or the user cancels via {@link Bitcollider#isExitNow()}.
   */
  public boolean getBitprintData(
      String fileName, Hashes hashes, Mp3Handler mp3, FormatHandler fmt) {

    boolean ret;

    try {
      File file = new File(fileName);
      fileSize = file.length();
      try (InputStream stm = new FileInputStream(file)) {
        ret = calculateHashes(stm, hashes, mp3, fmt);
      }
      if (ret) {
        try (InputStream stm = new FileInputStream(fileName)) {
          hashes.firstHex = generateFirstHex(stm);
          ret = null != hashes.firstHex;
        }
      }
      return ret;

    } catch (FileNotFoundException e) {
      bc.setError(Bitcollider.ERROR_FILENOTFOUND);
      return false;
    } catch (IOException e) {
      bc.setError(Bitcollider.ERROR_HASHCHECK);
      return false;
    }
  }

  /**
   * Extracts the terminal path component from a filesystem path. The method relies solely on the
   * platform separator reported by {@link File#separatorChar} and does not attempt URI decoding or
   * normalization. Use this helper when constructing user-visible filenames for submission payloads
   * or for extension parsing elsewhere in this class.
   *
   * @param fileName full path or relative path whose trailing component should be returned.
   * @return filename segment without parent directories; identical input when no separator exists.
   */
  public static String extractName(String fileName) {

    int sepPos = fileName.lastIndexOf(File.separatorChar);
    if (-1 != sepPos) {
      fileName = fileName.substring(sepPos + 1);
    }
    return fileName;
  }

  /**
   * Extracts the extension (characters after the final dot) from the provided filename. Directory
   * components are stripped first via {@link #extractName(String)}. The returned string is empty
   * when no dot is present, enabling callers to distinguish between missing and explicit
   * extensions. The helper performs no case normalization; callers may lower-case as needed for
   * format lookup.
   *
   * @param fileName filename or path from which to derive the extension segment.
   * @return substring following the last dot, or an empty string when none is found.
   */
  public static String extractExt(String fileName) {

    fileName = extractName(fileName);

    String ext = "";
    int extPos = fileName.lastIndexOf('.');
    if (-1 != extPos) {
      ext = fileName.substring(extPos + 1);
    }

    return ext;
  }

  /**
   * Analyzes a single file by computing configured hashes, extracting format metadata, and merging
   * the results into the submission attribute map. The method respects the {@code matchingExtsOnly}
   * flag to skip files whose extensions lack a registered {@link FormatHandler}, while still
   * honoring MP3 detection. During execution, it streams the file, updates progress callbacks, and
   * may short-circuit if the user requests cancellation via {@link Bitcollider#isExitNow()}.
   * Preview mode increments counters without touching the filesystem, enabling UI dry-runs.
   *
   * @param fileName path of the file to analyze; must be readable when not in preview mode.
   * @param matchingExtsOnly {@code true} to skip files without matching handlers; {@code false} to
   *     process any readable file.
   * @return {@code true} when hashing and attribute collection completed; {@code false} on skips,
   *     I/O failures, or user-initiated cancellation.
   */
  public boolean analyzeFile(String fileName, boolean matchingExtsOnly) {

    if (!prepareAnalysis(fileName)) {
      return false;
    }

    AnalysisInputs inputs = resolveInputs(fileName);
    if (shouldSkipUnknownExtension(fileName, matchingExtsOnly, inputs)) {
      return false;
    }

    if (bc.isPreview()) {
      numBitprints++;
      return true;
    }

    Mp3Handler mp3 = inputs.mp3Check ? new Mp3Handler() : null;

    Hashes hashes = new Hashes();
    if (!getBitprintData(fileName, hashes, mp3, inputs.fmtHandler)) {
      return false;
    }

    addHeaderIfFirstBitprint();
    addCoreAttributes(fileName, hashes);
    handleMp3Attributes(fileName, inputs.mp3Check, mp3);
    addFormatAttributes(hashes);
    analyzeWithFileHandler(fileName, inputs.fmtHandler);
    finalizeProgress();

    numBitprints++;

    return true;
  }

  private boolean prepareAnalysis(String fileName) {
    bc.setError(null);
    bc.setWarning(null);
    this.fileName = fileName;
    return !bc.isExitNow();
  }

  private AnalysisInputs resolveInputs(String fileName) {
    AnalysisInputs inputs = new AnalysisInputs();
    String ext = extractExt(fileName);
    inputs.mp3Check = (null == checkAsExt) && ("mp3".equalsIgnoreCase(ext));
    ext = null == checkAsExt ? ext : checkAsExt;
    inputs.fmtHandler = bc.getFormatHandler(ext);
    return inputs;
  }

  private boolean shouldSkipUnknownExtension(
      String fileName, boolean matchingExtsOnly, AnalysisInputs inputs) {
    if (matchingExtsOnly && (null == inputs.fmtHandler) && !inputs.mp3Check) {
      if ((null != bc.getProgress()) && !bc.isPreview()) {
        bc.getProgress().progress(0, fileName, "skipped.");
      }
      return true;
    }
    return false;
  }

  private void addHeaderIfFirstBitprint() {
    if (0 == numBitprints) {
      addAttribute("head.agent", Bitcollider.getAgentString());
      addAttribute("head.version", "S" + Bitcollider.BC_SUBMITSPECVER);
    }

    if (1 == numBitprints) {
      toMultiple();
    }
  }

  private void addCoreAttributes(String fileName, Hashes hashes) {
    addAttribute("bitprint", hashes.bitprint);

    addAttribute("tag.file.length", "" + (new File(fileName).length()));
    addAttribute("tag.file.first20", hashes.firstHex);
    addAttribute("tag.filename.filename", extractName(fileName));

    if (bc.isCalcCrc32()) {
      addAttribute("tag.crc32.crc32", hashes.crc32Hex);
    }
    if (bc.isCalcMd5()) {
      addAttribute("tag.md5.md5", hashes.md5Sum);
    }

    addAttribute("tag.ed2k.ed2khash", hashes.ed2Kmd4Sum);
    addAttribute("tag.kzhash.kzhash", hashes.kzHashSum);
  }

  private void handleMp3Attributes(String fileName, boolean mp3Check, Mp3Handler mp3) {
    if (!mp3Check || (null == mp3)) {
      return;
    }

    if (0 == mp3.getSampleRate()) {
      bc.setWarning(Bitcollider.WARNING_NOTMP3);
      return;
    }

    addAttribute("tag.mp3.duration", "" + mp3.getDuration());
    if (0 == mp3.getBitRate()) {
      addAttribute("tag.mp3.bitrate", "" + mp3.getAvgBitRate());
      addAttribute("tag.mp3.vbr", "y");
    } else {
      addAttribute("tag.mp3.bitrate", "" + mp3.getBitRate());
    }

    addAttribute("tag.mp3.samplerate", "" + mp3.getSampleRate());
    addAttribute("tag.mp3.stereo", mp3.isStereo() ? "y" : "n");
    byte[] audioSha = mp3.getAudioSha();
    if (audioSha != null) {
      addAttribute("tag.mp3.audio_sha1", Base32.encode(audioSha));
    }

    Id3Handler.Id3Info info = Id3Handler.readId3Tags(fileName);
    if (null != info) {
      addAttribute("tag.mp3.encoder", info.encoder);
      addAttribute("tag.audiotrack.title", info.title);
      addAttribute("tag.audiotrack.artist", info.artist);
      addAttribute("tag.audiotrack.album", info.album);
      addAttribute("tag.audiotrack.tracknumber", info.trackNumber);
      addAttribute("tag.id3genre.genre", info.genre);
      addAttribute("tag.audiotrack.year", info.year);
    }
  }

  private void addFormatAttributes(Hashes hashes) {
    if (null == hashes.attrs) {
      return;
    }
    for (Map.Entry<String, String> entry : hashes.attrs.entrySet()) {
      addAttribute(entry.getKey(), entry.getValue());
    }
  }

  private void analyzeWithFileHandler(String fileName, FormatHandler fmtHandler) {
    if ((null == fmtHandler)
        || fmtHandler.supportsMemAnalyze()
        || !fmtHandler.supportsFileAnalyze()
        || bc.isExitNow()) {
      return;
    }

    Map<String, String> fileAttrs = castStringMap(fmtHandler.analyzeFile(fileName));
    if ((null != fileAttrs) && !fileAttrs.isEmpty()) {
      for (Map.Entry<String, String> entry : fileAttrs.entrySet()) {
        addAttribute(entry.getKey(), entry.getValue());
      }
      return;
    }

    bc.setWarning(fmtHandler.getError());
  }

  private void finalizeProgress() {
    if ((null != bc.getProgress()) && !bc.isPreview() && !bc.isExitNow()) {
      bc.getProgress().progress(100, null, "ok.");
    }
  }

  /**
   * Walks a directory and submits each eligible file for analysis. The traversal may operate in
   * shallow mode or recursive mode based on {@code recurseDeep}. Non-regular files trigger a
   * progress callback indicating they were skipped. Only files that successfully pass {@link
   * #analyzeFile(String, boolean)} increment the returned count, so callers can detect how many
   * records were added to the submission.
   *
   * @param path root directory path to scan for files.
   * @param analyzeAll {@code true} to attempt every file; {@code false} to honor extension
   *     filtering by passing {@code true} for {@code matchingExtsOnly} when delegating to {@link
   *     #analyzeFile(String, boolean)}.
   * @param recurseDeep {@code true} to descend into subdirectories; {@code false} to stay shallow.
   * @return number of files successfully analyzed and merged into the submission.
   */
  public int recurseDir(String path, boolean analyzeAll, boolean recurseDeep) {

    File dir = new File(path);
    File[] files = dir.listFiles();
    if (files == null) {
      if (null != bc.getProgress()) {
        bc.getProgress().progress(0, path, "skipped. (unreadable directory)");
      }
      return 0;
    }
    int count = 0;
    for (File file : files) {
      count += handleDirEntry(file, analyzeAll, recurseDeep);
    }

    return count;
  }

  private int handleDirEntry(File file, boolean analyzeAll, boolean recurseDeep) {
    if (file.isFile()) {
      return analyzeFile(file.getPath(), !analyzeAll) ? 1 : 0;
    }
    if (file.isDirectory() && recurseDeep) {
      return recurseDir(file.getPath(), analyzeAll, true);
    }
    if (null != bc.getProgress()) {
      bc.getProgress().progress(0, file.getName(), "skipped. (not a regular file)");
    }
    return 0;
  }

  /**
   * Converts a raw Map to a Map<String,String> with runtime checks. When the input is null, returns
   * null. If any key or value is not a String, throws ClassCastException.
   */
  @SuppressWarnings("unchecked")
  private static Map<String, String> castStringMap(Map<?, ?> raw) {
    if (raw == null || raw.isEmpty()) {
      return Collections.emptyMap();
    }
    if (allEntriesAreStrings(raw)) {
      return (Map<String, String>) raw;
    }
    return copyValidatedEntries(raw);
  }

  private static boolean allEntriesAreStrings(Map<?, ?> raw) {
    for (Map.Entry<?, ?> e : raw.entrySet()) {
      if (!(e.getKey() instanceof String) || !(e.getValue() instanceof String)) {
        return false;
      }
    }
    return true;
  }

  private static Map<String, String> copyValidatedEntries(Map<?, ?> raw) {
    Map<String, String> out = new LinkedHashMap<>();
    for (Map.Entry<?, ?> e : raw.entrySet()) {
      Object k = e.getKey();
      Object v = e.getValue();
      if (!(k instanceof String) || !(v instanceof String)) {
        throw new ClassCastException(
            "Expected Map<String,String>, found entry key="
                + (k == null ? "null" : k.getClass().getName())
                + ", value="
                + (v == null ? "null" : v.getClass().getName()));
      }
      out.put((String) k, (String) v);
    }
    return out;
  }

  private static String toEscaped(String value) {

    int valueLength = value.length();
    int extraLength = 0;

    for (int i = 0; i < valueLength; i++) {

      switch (value.charAt(i)) {
        case '"' -> extraLength += 5;
        case '&' -> extraLength += 4;
        case '<', '>' -> extraLength += 3;
        default -> {
          /* no extra space needed */
        }
      }
    }

    if (0 == extraLength) {
      return value;
    }

    StringBuilder escaped = new StringBuilder();
    for (int i = 0; i < valueLength; i++) {
      switch (value.charAt(i)) {
        case '"' -> escaped.append("&quot;");
        case '&' -> escaped.append("&amp;");
        case '<' -> escaped.append("&lt;");
        case '>' -> escaped.append("&gt;");
        default -> escaped.append(value.charAt(i));
      }
    }

    return escaped.toString();
  }

  /**
   * Renders the accumulated submission as a complete HTML document containing a POST form. Each
   * collected attribute is echoed for readability and written as a hidden field so web endpoints
   * receive the data unchanged. When {@link #isAutoSubmit()} is true the body includes an {@code
   * onLoad} handler that immediately submits the form. Callers may override the default Bitzi URL
   * to target alternate receivers without mutating any other submission state.
   *
   * @param dest {@link PrintWriter} that receives the generated HTML markup.
   * @param url destination endpoint for the POST action; {@code null} selects the default lookup
   *     URL.
   * @return {@code true} after HTML is written successfully; {@code false} when no bitprints are
   *     present or earlier analysis errors were recorded.
   */
  public boolean makeHtml(PrintWriter dest, String url) {

    if (0 == numBitprints) {
      bc.setError("The submission contained no bitprints.");
      return false;
    }

    url = (null == url) ? SUBMIT_URL : url;

    dest.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    dest.print("<HTML><HEAD><TITLE>");

    if (1 == numBitprints) {
      dest.println("Bitprint Submission " + fileName);
    } else {
      dest.println("Multiple [" + numBitprints + "] Bitprint Submission");
    }
    dest.println("</TITLE>\n</HEAD>");
    if (autoSubmit) {
      dest.println("<BODY onLoad=\"document.forms[0].submit()\">");
    } else {
      dest.println("<BODY>");
    }

    if (1 == numBitprints) {
      dest.println("<h3>Bitprint Submission " + fileName + "</h3><p>");
    } else {
      dest.println("<h3>Multiple [" + numBitprints + "] Bitprint Submission</h3><p>");
    }

    dest.println(
        "You are submitting the following bitprint and tag data to the web "
            + "location <i>"
            + url
            + "</i>. For more information see <a "
            + "href=\"http://bitzi.com/bitcollider/websubmit\">the Bitzi website.</a>"
            + "<p>\nIf you are submitting more than a handful of files at once, it "
            + "may take a while for this page to load and submit.<p>\n"
            + "This submission should occur automatically. If it does not, you "
            + "may press the \"submit\" button which will appear at the bottom of "
            + "the page.<p><HR>");

    dest.println("<FORM method=post action=\"" + url + "\">");
    dest.println("<PRE>");

    int i = 0;
    int attrInd;
    int lastAttrInd = -1;
    for (Map.Entry<String, String> entry : attrs.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();

      try {
        attrInd = Integer.parseInt(key.substring(0, key.indexOf(".")));
      } catch (Exception e) {
        attrInd = -1;
      }

      if ((attrInd != lastAttrInd) || (2 == i)) {
        lastAttrInd = attrInd;
        dest.println();
      }
      i++;

      dest.print(key + "=<INPUT TYPE=\"hidden\" ");
      String escaped = toEscaped(value);
      dest.println("NAME=\"" + key + "\" VALUE=\"" + escaped + "\">" + value);
    }
    dest.println("\n<INPUT TYPE=\"submit\" NAME=\"Submit\" VALUE=\"Submit\">");
    dest.println("</PRE>\n</FORM>\n</BODY>\n</HTML>");

    return true;
  }

  /**
   * Reports how many bitprints have been analyzed and stored in this submission. The counter
   * advances only after {@link #analyzeFile(String, boolean)} completes successfully, so skipped or
   * failed files are excluded. Clients often use this value to determine whether to emit
   * single-file or multi-file headers when building output or to confirm that at least one file was
   * processed before calling {@link #makeHtml(PrintWriter, String)}.
   *
   * @return non-negative count of bitprints currently present in the submission.
   */
  public int getNumBitprints() {
    return numBitprints;
  }
}
