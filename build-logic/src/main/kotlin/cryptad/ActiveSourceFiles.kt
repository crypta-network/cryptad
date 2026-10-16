package cryptad

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.TRUNCATE_EXISTING
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream
import org.gradle.api.Project

/** Selects active source and packaging inputs without recursively admitting local history. */
internal object ActiveSourceFiles {
  private const val MAX_BYTES = 16 * 1024 * 1024
  private const val MAX_TOTAL = 512L * 1024 * 1024
  private const val GIT_LS_FILES = "ls-files"
  private const val GIT_SHA1_PATTERN = "[0-9a-f]{40}"
  private const val INVALID_EXPORT_ROSTER = "Invalid source export roster"
  private const val SOURCE_ROSTER_LIMIT = "Source roster exceeds limit"
  private val history = setOf(".stversions", ".git", "build", ".gradle", "__pycache__", ".cache")
  const val SOURCE_ROSTER = ".cryptad-source-roster.json"

  /** Portable mode bits are unavailable on ACL-only providers; execute access is not a mode. */
  fun executableBit(path: Path): Boolean? {
    if (!Files.getFileStore(path).supportsFileAttributeView("posix")) return null
    val permissions = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS).toSet()
    return permissions.any {
      it in
        setOf(
          PosixFilePermission.OWNER_EXECUTE,
          PosixFilePermission.GROUP_EXECUTE,
          PosixFilePermission.OTHERS_EXECUTE,
        )
    }
  }

  /** Git's index retains portable execute metadata when the checkout provider cannot store it. */
  fun trackedExecutableModes(raw: ByteArray): Map<String, Boolean> {
    require(raw.size <= MAX_BYTES && (raw.isEmpty() || raw.last() == 0.toByte())) {
      "Invalid source modes"
    }
    val text =
      Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(raw))
        .toString()
    val rows = text.split('\u0000').dropLast(1)
    require(rows.size <= 100000) { "Source modes exceed limit" }
    val result = mutableMapOf<String, Boolean>()
    for (row in rows) {
      val separator = row.indexOf('\t')
      require(separator >= 0) { "Invalid source modes" }
      val metadata =
        Regex("(100644|100755) [0-9a-f]{40}(?:[0-9a-f]{24})? 0")
          .matchEntire(row.substring(0, separator))
      require(metadata != null) { "Unresolved source modes" }
      val name = row.substring(separator + 1)
      require(name.isNotEmpty() && result.put(name, metadata.groupValues[1] == "100755") == null) {
        "Duplicate source modes"
      }
    }
    return result
  }

  /** Shares one lazy metadata snapshot between source sets and formatter targets. */
  fun selectedRoster(project: Project): Lazy<Set<String>> =
    synchronized(project.rootProject) {
      val root = project.rootProject
      val key = "cryptad.selectedSourceRoster"
      val extra = root.extensions.extraProperties
      if (!extra.has(key)) extra.set(key, lazy { repository(root.rootDir) })
      @Suppress("UNCHECKED_CAST") (extra.get(key) as Lazy<Set<String>>)
    }

  /**
   * Selects every static source from metadata, preserving explicitly configured generated roots.
   */
  fun excludeUnselected(
    root: File,
    file: File,
    generatedRoots: Set<File> = emptySet(),
    selected: () -> Set<String>,
  ): Boolean {
    val base = root.toPath().toAbsolutePath().normalize()
    val realBase = base.toRealPath()
    val path = file.toPath().toAbsolutePath().normalize()
    val ownedBase = if (path.startsWith(base)) base else realBase
    require(path.startsWith(ownedBase)) { "Source outside repository" }
    if (generatedRoots.any { path.startsWith(it.toPath().toAbsolutePath().normalize()) })
      return false
    val name = ownedBase.relativize(path).toString().replace(File.separatorChar, '/')
    val names = selected()
    // Source sets visit directories as well as members; retain a directory only for selected
    // descendants.
    return if (Files.isDirectory(path, NOFOLLOW_LINKS)) {
      val prefix = "$name/"
      if (names is java.util.SortedSet<String>)
        names.tailSet(prefix).firstOrNull()?.startsWith(prefix) != true
      else names.none { it.startsWith(prefix) }
    } else name !in names
  }

  fun repository(root: File): Set<String> {
    val base = root.canonicalFile
    if (!base.resolve(".git").exists()) return sourceExport(base)
    val tracked = git(base, GIT_LS_FILES, "--cached", "-z")
    val deleted = git(base, GIT_LS_FILES, "--deleted", "-z")
    val exclusions = history.flatMap { listOf(":(exclude,glob)**/$it/**", ":(exclude,glob)$it/**") }
    val untracked =
      git(
        base,
        GIT_LS_FILES,
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        ".",
        *exclusions.toTypedArray(),
      )
    val selected = select(base, tracked, untracked, deleted)
    require(SOURCE_ROSTER !in selected) { "Reserved source export roster in Git selection" }
    return selected
  }

  private fun git(root: File, vararg arguments: String, index: Path? = null): ByteArray {
    val builder =
      ProcessBuilder(
          listOf(
            "git",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
          ) + arguments
        )
        .directory(root)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
    builder.environment().keys.removeIf { it.startsWith("GIT_") }
    builder.environment()["GIT_NO_REPLACE_OBJECTS"] = "1"
    builder.environment()["GIT_CONFIG_NOSYSTEM"] = "1"
    builder.environment()["GIT_CONFIG_GLOBAL"] =
      if (File.separatorChar == '\\') "NUL" else "/dev/null"
    if (index != null) builder.environment()["GIT_INDEX_FILE"] = index.toString()
    val process = builder.start()
    val reader = Executors.newVirtualThreadPerTaskExecutor()
    try {
      val bytes =
        reader.submit<ByteArray> { process.inputStream.use { it.readNBytes(MAX_BYTES + 1) } }
      val output = bytes.get(12, TimeUnit.SECONDS)
      require(
        output.size <= MAX_BYTES && process.waitFor(3, TimeUnit.SECONDS) && process.exitValue() == 0
      ) {
        "Selected source roster unavailable"
      }
      return output
    } finally {
      if (process.isAlive) process.destroyForcibly()
      reader.shutdownNow()
    }
  }

  // Explicit transform attributes cannot establish committed bytes. Include negations because
  // check-attr's state text also names valid filter drivers (unset/unspecified).
  private fun customSourceTransforms(base: File, selected: Set<String>): Boolean =
    selected.toList().chunked(128).any { names ->
      val fields =
        git(base, "check-attr", "-z", "--all", "--", *names.toTypedArray())
          .toString(Charsets.UTF_8)
          .split('\u0000')
      require(fields.last() == "" && fields.size % 3 == 1) {
        "Source transform attributes unavailable"
      }
      fields.dropLast(1).chunked(3).any {
        it[1] in setOf("filter", "ident", "working-tree-encoding")
      }
    }

  private fun workingBytesChanged(base: File, commit: String): Boolean {
    // No cached stat records: compare contents with Git's checkout attribute normalization.
    val directory = Files.createTempDirectory("cryptad-source-index-").toRealPath()
    val index = directory.resolve("index")
    val options =
      arrayOf(
        "-c",
        "core.splitIndex=false",
        "-c",
        "core.sparseCheckout=false",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.fileMode=false",
      )
    try {
      git(base, *options, "read-tree", commit, index = index)
      return git(
          base,
          *options,
          "diff",
          "--raw",
          "-z",
          "--no-ext-diff",
          "--no-textconv",
          index = index,
        )
        .isNotEmpty()
    } finally {
      Files.deleteIfExists(directory.resolve("index.lock"))
      Files.deleteIfExists(index)
      Files.delete(directory)
    }
  }

  private fun workingModesChanged(
    base: File,
    selected: Set<String>,
    indexed: Map<String, Boolean>,
  ): Boolean = selected.any { name ->
    val actual = executableBit(base.resolve(name).toPath())
    name !in indexed || (actual != null && actual != indexed[name])
  }

  fun select(
    root: File,
    tracked: ByteArray,
    untracked: ByteArray,
    deleted: ByteArray = byteArrayOf(),
  ): Set<String> {
    fun parse(raw: ByteArray): List<String> {
      require(raw.size <= MAX_BYTES && (raw.isEmpty() || raw.last() == 0.toByte())) {
        "Invalid source roster"
      }
      val decoder =
        Charsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
      val values = decoder.decode(ByteBuffer.wrap(raw)).toString().split('\u0000').dropLast(1)
      require(values.size <= 100000 && values.distinct().size == values.size) {
        "Invalid source roster"
      }
      return values.onEach { name ->
        require(
          name.isNotEmpty() &&
            !name.startsWith('/') &&
            '\\' !in name &&
            ':' !in name &&
            name.none { it.code < 32 } &&
            name.split('/').none { it in setOf("", ".", "..") }
        ) {
          "Unsafe source name"
        }
      }
    }
    val currentTracked = parse(tracked).toSet() - parse(deleted).toSet()
    val selected =
      (currentTracked + parse(untracked).filter { name -> name.split('/').none { it in history } })
        .toSortedSet()
    require(selected.isNotEmpty() && selected.size <= 100000) { "Empty or oversized source roster" }
    val base = root.toPath().toRealPath()
    selected.forEach { name ->
      var path = base
      name.split('/').forEach { part ->
        path = path.resolve(part)
        require(!Files.isSymbolicLink(path)) { "Linked source member" }
      }
      require(Files.isRegularFile(path, NOFOLLOW_LINKS) && path.toRealPath() == path) {
        "Missing or aliased source member"
      }
      if (Files.getFileStore(path).supportsFileAttributeView("unix")) {
        require((Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L) {
          "Linked source member"
        }
      }
    }
    return selected
  }

  private fun sourceExport(root: File): Set<String> {
    val manifestFile =
      if (root.resolve(SOURCE_ROSTER).exists()) root.resolve(SOURCE_ROSTER)
      else root.resolve(".restricted-manifest.json")
    require(
      Files.isRegularFile(manifestFile.toPath(), NOFOLLOW_LINKS) &&
        manifestFile.length() <= MAX_BYTES
    ) {
      "Approved source export roster required"
    }
    val raw =
      Files.newInputStream(manifestFile.toPath(), NOFOLLOW_LINKS).use {
        it.readNBytes(MAX_BYTES + 1)
      }
    require(raw.size <= MAX_BYTES) { "Source export roster exceeds limit" }
    val text =
      Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(raw))
        .toString()
    val manifest = JsonSlurper().parseText(text) as? Map<*, *> ?: error(INVALID_EXPORT_ROSTER)
    val fullSource = manifestFile.name == SOURCE_ROSTER
    // Preserve each producer's identity-bound encoding: installation.encode() has no newline;
    // the full-source archive writer includes one. Exact comparison also refuses duplicate keys.
    val canonical = JsonOutput.toJson(manifest) + if (fullSource) "\n" else ""
    require(text == canonical) { "Noncanonical source export roster" }
    if (fullSource) {
      require(
        manifest.keys ==
          setOf("schemaVersion", "kind", "sourceCommit", "sourceTree", "sourceClass", "files") &&
          manifest["schemaVersion"] == 1 &&
          manifest["kind"] == "cryptad-source-export" &&
          manifest["sourceClass"] in setOf("committed-source", "working-source") &&
          (manifest["sourceTree"] as? String)?.matches(Regex(GIT_SHA1_PATTERN)) == true
      ) {
        INVALID_EXPORT_ROSTER
      }
    } else {
      require(
        manifest.keys == setOf("schemaVersion", "kind", "exportPolicy", "sourceCommit", "files") &&
          manifest["schemaVersion"] == 2 &&
          manifest["kind"] == "cryptad-restricted-installation" &&
          manifest["exportPolicy"] == "production-without-test-seams-v1"
      ) {
        INVALID_EXPORT_ROSTER
      }
    }
    require(
      (manifest["sourceCommit"] as? String)?.matches(
        Regex(if (fullSource) GIT_SHA1_PATTERN else "$GIT_SHA1_PATTERN|[0-9a-f]{64}")
      ) == true
    ) {
      "Invalid source export identity"
    }
    val entries = manifest["files"] as? Map<*, *> ?: error("Invalid source export members")
    val names = entries.keys.map { it as? String ?: error("Invalid source export name") }
    require(SOURCE_ROSTER !in names && (fullSource || ".restricted-manifest.json" !in names)) {
      "Self-referential source roster"
    }
    val selected =
      select(
        root,
        (names.joinToString("\u0000") + "\u0000").toByteArray(Charsets.UTF_8),
        byteArrayOf(),
      )
    var total = 0L
    for (name in selected) {
      val record = entries[name] as? Map<*, *> ?: error("Invalid source export member")
      val file = root.resolve(name)
      val executable = executableBit(file.toPath())
      require(
        record.keys == setOf("sha256", "size", "executable") &&
          (record["size"] is Int || record["size"] is Long) &&
          (record["size"] as Number).toLong() == file.length() &&
          file.length() <= MAX_BYTES &&
          record["executable"] is Boolean &&
          (executable == null || record["executable"] == executable)
      ) {
        "Invalid source export member"
      }
      total += file.length()
      require(total <= MAX_TOTAL) { "Source export exceeds limit" }
      val fingerprint = Phase12TaskEvidence.fingerprint(root, file)
      require(
        fingerprint["size"] == (record["size"] as Number).toLong() &&
          fingerprint["digest"] == "sha256:" + record["sha256"]
      ) {
        "Source export member changed"
      }
    }
    return selected
  }

  /** Writes the exact source archive roster. It records consistency, not release authority. */
  fun writeRoster(root: File, selected: Set<String>, output: File) {
    val base = root.canonicalFile
    require(repository(base) == selected) { "Source selection changed before packaging" }
    if (!base.resolve(".git").exists()) {
      val previous = base.resolve(SOURCE_ROSTER)
      require(previous.isFile) { "Full source export roster required for source repackaging" }
      val raw =
        Files.newInputStream(previous.toPath(), NOFOLLOW_LINKS).use { it.readNBytes(MAX_BYTES + 1) }
      require(raw.size <= MAX_BYTES) { SOURCE_ROSTER_LIMIT }
      writeOutput(output, raw)
      return
    }
    // Status trusts assume-unchanged/skip-worktree entries, so their state cannot establish
    // a committed-source claim even when their bytes happen to match at this observation.
    val tagged = git(base, GIT_LS_FILES, "--cached", "-v", "-z").toString(Charsets.UTF_8)
    require(tagged.split('\u0000').filter { it.isNotEmpty() }.all { it.startsWith("H ") }) {
      "Hidden source index flags are unsupported"
    }
    val commit = git(base, "rev-parse", "HEAD").toString(Charsets.US_ASCII).trim()
    val tree = git(base, "rev-parse", "HEAD^{tree}").toString(Charsets.US_ASCII).trim()
    require(commit.matches(Regex(GIT_SHA1_PATTERN)) && tree.matches(Regex(GIT_SHA1_PATTERN))) {
      "Source identity unavailable"
    }
    val trackedModes by lazy { trackedExecutableModes(git(base, GIT_LS_FILES, "--stage", "-z")) }
    val committed =
      git(base, "ls-tree", "-r", "--name-only", "-z", commit)
        .toString(Charsets.UTF_8)
        .split('\u0000')
        .dropLast(1)
        .toSet()
    val dirty =
      git(base, "diff", "--cached", "--raw", "-z", "--no-ext-diff", "--no-textconv", commit)
        .isNotEmpty() ||
        selected.any { it !in committed } ||
        workingModesChanged(base, selected, trackedModes) ||
        customSourceTransforms(base, selected) ||
        workingBytesChanged(base, commit)
    var total = 0L
    val files =
      selected
        .sorted()
        .associateWith { name ->
          val file = base.resolve(name)
          total += file.length()
          require(file.length() <= MAX_BYTES && total <= MAX_TOTAL) {
            "Source export exceeds limit"
          }
          val fingerprint = Phase12TaskEvidence.fingerprint(base, file)
          sortedMapOf(
            "sha256" to (fingerprint.getValue("digest") as String).removePrefix("sha256:"),
            "size" to fingerprint.getValue("size"),
            "executable" to
              (executableBit(file.toPath()) ?: trackedModes.getOrDefault(name, false)),
          )
        }
        .toSortedMap()
    val manifest =
      sortedMapOf(
        "schemaVersion" to 1,
        "kind" to "cryptad-source-export",
        "sourceCommit" to commit,
        "sourceTree" to tree,
        "sourceClass" to if (dirty) "working-source" else "committed-source",
        "files" to files,
      )
    val bytes = (JsonOutput.toJson(manifest) + "\n").toByteArray(Charsets.UTF_8)
    require(bytes.size <= MAX_BYTES) { SOURCE_ROSTER_LIMIT }
    writeOutput(output, bytes)
  }

  private fun writeOutput(output: File, bytes: ByteArray) {
    val target = output.toPath().toAbsolutePath().normalize()
    require(generateSequence(target) { it.parent }.none { Files.isSymbolicLink(it) }) {
      "Unsafe source roster output"
    }
    Files.createDirectories(target.parent)
    Files.newOutputStream(target, CREATE, TRUNCATE_EXISTING, NOFOLLOW_LINKS).use { it.write(bytes) }
  }

  /** Rechecks copied archive bytes against the exact roster, including unexpected members. */
  fun verifyArchive(archive: File, roster: File, prefix: String) {
    val rosterBytes = roster.readBytes()
    require(rosterBytes.size <= MAX_BYTES) { SOURCE_ROSTER_LIMIT }
    val manifest = JsonSlurper().parse(rosterBytes) as Map<*, *>
    val entries = manifest["files"] as Map<*, *>
    val expected = entries.keys.map { it as String }.toSet() + SOURCE_ROSTER
    val directories =
      expected
        .flatMap { name ->
          val parts = name.split('/')
          (1 until parts.size).map { parts.take(it).joinToString("/") }
        }
        .toSet() + ""
    val seen = mutableSetOf<String>()
    val seenDirectories = mutableSetOf<String>()
    var total = 0L
    val compressed = BZip2CompressorInputStream(archive.inputStream().buffered())
    TarArchiveInputStream(compressed).use { input ->
      while (true) {
        val entry = input.nextEntry ?: break
        require(entry.name.startsWith("$prefix/") && !entry.isSymbolicLink && !entry.isLink) {
          "Unsafe source archive member"
        }
        val name = entry.name.removePrefix("$prefix/").removeSuffix("/")
        if (entry.isDirectory) {
          require(name in directories && seenDirectories.add(name)) {
            "Unexpected source archive directory"
          }
          continue
        }
        require(
          entry.isFile && name in expected && seen.add(name) && entry.size in 0L..MAX_BYTES.toLong()
        ) {
          "Unexpected source archive member"
        }
        total += entry.size
        require(total <= MAX_TOTAL + MAX_BYTES) { "Source archive exceeds limit" }
        verifyArchiveContent(input, entry, name, rosterBytes, entries)
      }
      verifyArchiveTrailer(compressed, archive)
    }
    require(seen == expected) { "Incomplete source archive" }
  }

  private fun verifyArchiveContent(
    input: TarArchiveInputStream,
    entry: TarArchiveEntry,
    name: String,
    rosterBytes: ByteArray,
    entries: Map<*, *>,
  ) {
    if (name == SOURCE_ROSTER) {
      val copied = input.readNBytes(MAX_BYTES + 1)
      require(copied.contentEquals(rosterBytes)) { "Source archive roster changed" }
      return
    }
    val record = entries[name] as Map<*, *>
    require(
      entry.size == (record["size"] as Number).toLong() &&
        (entry.mode and 73 != 0) == record["executable"]
    ) {
      "Source archive metadata changed"
    }
    val digest = MessageDigest.getInstance("SHA-256")
    val count =
      readArchiveMember(input, entry.size) { buffer, length -> digest.update(buffer, 0, length) }
    require(
      count == entry.size &&
        digest.digest().joinToString("") { "%02x".format(it) } == record["sha256"]
    ) {
      "Source archive bytes changed"
    }
  }

  private fun verifyArchiveTrailer(compressed: BZip2CompressorInputStream, archive: File) {
    var padding = 0
    while (true) {
      val value = compressed.read()
      if (value < 0) break
      require(value == 0 && ++padding <= 16384) { "Unexpected source archive trailer" }
    }
    require(compressed.compressedCount == archive.length()) { "Appended source archive bytes" }
  }

  private fun readArchiveMember(
    input: InputStream,
    size: Long,
    consume: (ByteArray, Int) -> Unit,
  ): Long {
    val buffer = ByteArray(65536)
    var count = 0L
    while (true) {
      val length = input.read(buffer)
      if (length < 0) break
      count += length
      require(count <= size) { "Growing source archive member" }
      consume(buffer, length)
    }
    return count
  }

  /** Writes selected regular files directly so generic tree exclusions cannot omit dotfiles. */
  fun writeArchive(root: File, selected: Set<String>, roster: File, output: File, prefix: String) {
    val base = root.canonicalFile
    val rosterBytes =
      Files.newInputStream(roster.toPath(), NOFOLLOW_LINKS).use { it.readNBytes(MAX_BYTES + 1) }
    require(rosterBytes.size <= MAX_BYTES) { SOURCE_ROSTER_LIMIT }
    val entries = (JsonSlurper().parse(rosterBytes) as Map<*, *>)["files"] as Map<*, *>
    require(entries.keys == selected) { "Source archive roster changed" }
    val target = output.toPath().toAbsolutePath().normalize()
    require(generateSequence(target) { it.parent }.none { Files.isSymbolicLink(it) }) {
      "Unsafe source archive output"
    }
    Files.createDirectories(target.parent)
    TarArchiveOutputStream(
        BZip2CompressorOutputStream(
          Files.newOutputStream(target, CREATE, TRUNCATE_EXISTING, NOFOLLOW_LINKS)
        )
      )
      .use { archive ->
        archive.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
        archive.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX)
        for (name in (selected + SOURCE_ROSTER).sorted()) {
          val file = if (name == SOURCE_ROSTER) roster else base.resolve(name)
          val entry = archiveEntry(prefix, name, file, entries)
          archive.putArchiveEntry(entry)
          Files.newInputStream(file.toPath(), NOFOLLOW_LINKS).use { input ->
            val count =
              readArchiveMember(input, entry.size) { buffer, length ->
                archive.write(buffer, 0, length)
              }
            require(count == entry.size) { "Truncated source archive member" }
          }
          archive.closeArchiveEntry()
        }
      }
    verifyArchive(output, roster, prefix)
  }

  private fun archiveEntry(
    prefix: String,
    name: String,
    file: File,
    entries: Map<*, *>,
  ): TarArchiveEntry {
    val entry = TarArchiveEntry("$prefix/$name")
    entry.size = file.length()
    require(entry.size in 0L..MAX_BYTES.toLong()) { "Source archive member exceeds limit" }
    val executable =
      if (name == SOURCE_ROSTER) false
      else {
        val record = entries[name] as? Map<*, *> ?: error("Invalid source archive member")
        record["executable"] as? Boolean ?: error("Invalid source archive mode")
      }
    entry.mode = if (executable) 493 else 420
    entry.modTime = java.util.Date(file.lastModified())
    return entry
  }
}
