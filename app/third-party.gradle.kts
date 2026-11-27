// The About page's third-party list (third-party/README.md), generated for each platform from what the build packages:
// the Maven libraries of the release runtime class path with their POM licenses and the license and notice files in
// their jars, the Rust crates of every packaged native library (the <library>.third-party.json lists that
// native/build.sh writes) and the curated entries of third-party/components.json whose conditions hold. Every license
// must be in components.json with its full text in third-party/licenses, so a new dependency under an unknown license
// fails the build until it is added. Writes files/third-party.json, files/NOTICE.txt and files/LICENSE.txt, which the
// app reads as Compose resources (androidMain and desktopMain).
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.maven.MavenModule
import org.gradle.maven.MavenPomArtifact
import org.w3c.dom.Element
import java.security.MessageDigest
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

val thirdPartyDir = rootProject.file("third-party")

@Suppress("UNCHECKED_CAST")
fun readJson(file: File): Map<String, Any?> = JsonSlurper().parse(file, "UTF-8") as Map<String, Any?>

fun textKey(body: String): String =
    "h:" + MessageDigest.getInstance("SHA-256").digest(body.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }.take(16)

fun normalizeText(raw: String): String = raw.replace("\r\n", "\n").replace('\r', '\n').trim() + "\n"

class PomInfo(
    val name: String?, val url: String?, val organization: String?,
    val licenses: List<String>, val parent: Triple<String, String, String>?,
)

fun Element.child(tag: String): Element? {
    val nodes = childNodes
    for (i in 0 until nodes.length) (nodes.item(i) as? Element)?.takeIf { it.tagName == tag }?.let { return it }
    return null
}

fun Element.children(tag: String): List<Element> {
    val nodes = childNodes
    return (0 until nodes.length).mapNotNull { nodes.item(it) as? Element }.filter { it.tagName == tag }
}

fun Element.text(tag: String): String? = child(tag)?.textContent?.trim()?.takeIf { it.isNotEmpty() && !it.contains("\${") }

fun parsePom(file: File): PomInfo {
    val factory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = false
        isExpandEntityReferences = false
        setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
    }
    val project = factory.newDocumentBuilder().parse(file).documentElement
    val licenses = project.child("licenses")?.children("license").orEmpty().map { l ->
        listOfNotNull(l.text("name"), l.text("url")).joinToString(" | ")
    }.filter { it.isNotBlank() }
    val parent = project.child("parent")?.let { p ->
        val g = p.text("groupId"); val a = p.text("artifactId"); val v = p.text("version")
        if (g != null && a != null && v != null) Triple(g, a, v) else null
    }
    return PomInfo(project.text("name"), project.text("url"), project.child("organization")?.text("name"), licenses, parent)
}

val pomCache = mutableMapOf<String, PomInfo?>()

fun pomOf(group: String, name: String, version: String): PomInfo? = pomCache.getOrPut("$group:$name:$version") {
    dependencies.createArtifactResolutionQuery().forModule(group, name, version)
        .withArtifacts(MavenModule::class.java, MavenPomArtifact::class.java).execute()
        .resolvedComponents.firstOrNull()?.getArtifacts(MavenPomArtifact::class.java)
        ?.filterIsInstance<ResolvedArtifactResult>()?.firstOrNull()?.file?.let { parsePom(it) }
}

/** The POM's licenses, URL and organization, taken from the nearest parent POM where the module's own has none. */
fun effectivePom(group: String, name: String, version: String): PomInfo? {
    val own = pomOf(group, name, version) ?: return null
    var licenses = own.licenses; var url = own.url; var organization = own.organization
    var parent = own.parent
    var depth = 0
    while (parent != null && depth++ < 8 && (licenses.isEmpty() || organization == null)) {
        val p = pomOf(parent.first, parent.second, parent.third) ?: break
        if (licenses.isEmpty()) licenses = p.licenses
        if (url == null) url = p.url
        if (organization == null) organization = p.organization
        parent = p.parent
    }
    return PomInfo(own.name, url, organization, licenses, own.parent)
}

val archiveText = Regex("(?i)^(META-INF/)?(LICEN[CS]E|NOTICE|COPYING|COPYRIGHT)([-_.][^/]*)?$")

/** License and notice files inside a jar, or inside an AAR and its classes.jar. */
fun archiveTexts(file: File): List<Pair<String, String>> {
    val found = mutableListOf<Pair<String, String>>()
    if (!file.isFile || file.extension !in setOf("jar", "aar")) return found
    ZipFile(file).use { zip ->
        for (entry in zip.entries()) {
            if (entry.isDirectory || entry.size > 256 * 1024) continue
            if (archiveText.matches(entry.name)) {
                found += entry.name to zip.getInputStream(entry).use { it.readBytes() }.toString(Charsets.UTF_8)
            } else if (file.extension == "aar" && entry.name == "classes.jar") {
                ZipInputStream(zip.getInputStream(entry)).use { nested ->
                    generateSequence { nested.nextEntry }.forEach { e ->
                        if (!e.isDirectory && archiveText.matches(e.name)) {
                            val bytes = nested.readBytes()
                            if (bytes.size <= 256 * 1024) found += e.name to bytes.toString(Charsets.UTF_8)
                        }
                    }
                }
            }
        }
    }
    return found
}

/**
 * The Maven libraries of [configurationName] (those that contribute files), as JSON: coordinates, POM name, URL,
 * organization and licenses (mapped with mavenLicenseAliases or mavenOverrides) and the texts found in the archive.
 */
@Suppress("UNCHECKED_CAST")
fun collectMaven(configurationName: String): String {
    val data = readJson(thirdPartyDir.resolve("components.json"))
    val aliases = (data["mavenLicenseAliases"] as List<Map<String, String>>).map { Regex(it.getValue("match"), RegexOption.IGNORE_CASE) to it.getValue("license") }
    val overrides = data["mavenOverrides"] as Map<String, String>
    val artifacts = configurations.getByName(configurationName).incoming.artifactView { componentFilter { it is ModuleComponentIdentifier } }.artifacts.artifacts
    val byComponent = artifacts.filter { it.id.componentIdentifier is ModuleComponentIdentifier }
        .groupBy { it.id.componentIdentifier as ModuleComponentIdentifier }
    val problems = mutableListOf<String>()
    val texts = sortedMapOf<String, String>()
    val entries = byComponent.entries.sortedBy { "${it.key.group}:${it.key.module}" }.map { (id, files) ->
        val coordinates = "${id.group}:${id.module}"
        val pom = effectivePom(id.group, id.module, id.version)
        val license = overrides[coordinates] ?: overrides["${id.group}:*"] ?: pom?.licenses?.takeIf { it.isNotEmpty() }?.map { raw ->
            aliases.firstOrNull { it.first.containsMatchIn(raw) }?.second ?: run { problems += "$coordinates:${id.version}: \"$raw\""; raw }
        }?.distinct()?.joinToString(", ") ?: run { problems += "$coordinates:${id.version}: no license in its POM"; "" }
        val keys = files.flatMap { archiveTexts(it.file) }.map { (_, body) ->
            val text = normalizeText(body)
            textKey(text).also { texts[it] = text }
        }.distinct()
        mapOf(
            "id" to "maven:$coordinates", "kind" to "library", "name" to (pom?.name ?: id.module), "coordinates" to coordinates,
            "version" to id.version, "license" to license, "url" to pom?.url, "copyright" to pom?.organization, "texts" to keys,
        )
    }
    if (problems.isNotEmpty()) {
        throw GradleException("Third-party list: licenses not in third-party/components.json (add a mavenLicenseAliases or mavenOverrides entry):\n  " + problems.joinToString("\n  "))
    }
    return JsonOutput.toJson(mapOf("entries" to entries, "texts" to texts))
}

abstract class GenerateThirdParty : DefaultTask() {
    @get:Input abstract val platform: Property<String>
    @get:Input abstract val maven: Property<String>
    @get:Input abstract val requireNativeLists: Property<Boolean>
    @get:InputDirectory @get:PathSensitive(PathSensitivity.RELATIVE) abstract val dataDir: DirectoryProperty
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val nativeDirs: ConfigurableFileCollection
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val attachedFiles: ConfigurableFileCollection
    @get:Internal abstract val repoDir: DirectoryProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val noticeFile: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val licenseFile: RegularFileProperty
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    private fun hash(body: String) =
        "h:" + java.security.MessageDigest.getInstance("SHA-256").digest(body.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }.take(16)

    private fun clean(raw: String) = raw.replace("\r\n", "\n").replace('\r', '\n').trim() + "\n"

    /** SPDX license identifiers of an expression ("MIT/Apache-2.0" is read as "MIT OR Apache-2.0"). */
    private fun ids(expression: String): List<String> =
        expression.replace("/", " OR ").replace("(", " ").replace(")", " ").replace(",", " ")
            .split(Regex("\\s+")).filter { it.isNotEmpty() && it !in setOf("AND", "OR", "WITH") }.distinct()

    private fun normalized(expression: String) = expression.trim().replace(Regex("\\s*/\\s*"), " OR ")

    @Suppress("UNCHECKED_CAST")
    @TaskAction
    fun generate() {
        val slurper = groovy.json.JsonSlurper()
        val data = slurper.parse(dataDir.file("components.json").get().asFile, "UTF-8") as Map<String, Any?>
        val licenseTable = data["licenses"] as Map<String, Map<String, String>>
        val crateOverrides = data["crateOverrides"] as Map<String, String>
        val texts = sortedMapOf<String, String>()
        val problems = mutableListOf<String>()
        val entries = mutableListOf<Map<String, Any?>>()
        val usedLicenses = sortedSetOf<String>()
        fun use(owner: String, expression: String): List<String> = ids(expression).also { list ->
            if (list.isEmpty()) problems += "$owner: no license"
            list.filterNot { it in licenseTable }.forEach { problems += "$owner: license $it is not in third-party/components.json" }
            usedLicenses += list
        }

        val maven = slurper.parseText(maven.get()) as Map<String, Any?>
        texts += maven["texts"] as Map<String, String>
        for (e in maven["entries"] as List<Map<String, Any?>>) {
            val list = use(e["coordinates"] as String, e["license"] as String)
            entries += e + mapOf("licenses" to list)
        }

        // Rust crates of the packaged native libraries.
        val runtimes = mutableSetOf<String>()
        val features = mutableSetOf<String>()
        class Crate(val name: String, val version: String, var license: String, val url: String?, val texts: MutableSet<String> = sortedSetOf(), val scopes: MutableMap<String, MutableSet<String>> = sortedMapOf())
        val crates = sortedMapOf<String, Crate>()
        val lists = nativeDirs.asFileTree.matching { include("*/*.third-party.json") }.files.sortedBy { it.path }
        val libraries = nativeDirs.asFileTree.matching { include("*/*.so", "*/*.dll", "*/*.dylib") }.files
        for (library in libraries) {
            if (!library.resolveSibling(library.name + ".third-party.json").isFile) {
                val message = "Third-party list: ${library.parentFile.name}/${library.name} has no ${library.name}.third-party.json (rebuild it with native/build.sh)"
                if (requireNativeLists.get()) problems += message else logger.warn(message)
            }
        }
        for (file in lists) {
            val library = file.resolveSibling(file.name.removeSuffix(".third-party.json"))
            if (!library.isFile) continue // a list left behind without its library is not packaged
            val list = slurper.parse(file, "UTF-8") as Map<String, Any?>
            runtimes += list["runtime"] as List<String>
            features += list["features"] as List<String>
            texts += list["texts"] as Map<String, String>
            for (c in list["crates"] as List<Map<String, Any?>>) {
                val name = c["name"] as String
                val version = c["version"] as String
                val crate = crates.getOrPut("$name $version") { Crate(name, version, normalized(c["license"] as String), (c["url"] as String?)?.takeIf { it.isNotEmpty() }) }
                if (crate.license.isEmpty()) {
                    crate.license = crateOverrides.entries.firstOrNull { (pattern, _) ->
                        Regex(pattern.split("*").joinToString(".*") { Regex.escape(it) }).matches(name)
                    }?.value.orEmpty()
                }
                (c["files"] as List<Map<String, String>>).forEach { crate.texts += it.getValue("text") }
                crate.scopes.getOrPut(library.name) { sortedSetOf() } += library.parentFile.name
            }
        }
        for (c in crates.values) {
            entries += mapOf(
                "id" to "crate:${c.name}:${c.version}", "kind" to "crate", "name" to c.name, "version" to c.version,
                "license" to c.license, "licenses" to use("crate ${c.name} ${c.version}", c.license), "url" to c.url,
                "scope" to mapOf("en" to c.scopes.entries.joinToString("; ") { (lib, where) -> "$lib (${where.joinToString(", ")})" }),
                "texts" to c.texts.toList(),
            )
        }

        // Curated components whose platform and conditions hold.
        val platformName = platform.get()
        for (c in data["components"] as List<Map<String, Any?>>) {
            val platforms = c["platforms"] as List<String>? ?: listOf("android", "desktop")
            if (platformName !in platforms) continue
            val condition = c["when"] as Map<String, List<String>>?
            if (condition != null) {
                val needRuntime = condition["runtime"]
                val needFeature = condition["feature"]
                if (needRuntime != null && needRuntime.none { it in runtimes }) continue
                if (needFeature != null && needFeature.none { it in features }) continue
            }
            val id = c["id"] as String
            val attached = (c["files"] as List<String>?).orEmpty().map { path ->
                val f = repoDir.get().asFile.resolve(path)
                if (!f.isFile) { problems += "component $id: missing file $path"; return@map null }
                val body = clean(f.readText(Charsets.UTF_8))
                hash(body).also { texts[it] = body }
            }.filterNotNull()
            val license = c["license"] as String
            entries += mapOf(
                "id" to "component:$id", "kind" to c["kind"], "name" to c["name"], "version" to c["version"],
                "license" to license, "licenses" to use("component $id", license), "url" to (c["url"] as String?)?.takeIf { it.isNotEmpty() },
                "copyright" to c["copyright"], "description" to c["description"], "scope" to c["scope"], "texts" to attached,
            )
        }

        val licenses = usedLicenses.filter { it in licenseTable }.map { id ->
            val f = dataDir.get().asFile.resolve("licenses/$id.txt")
            if (!f.isFile) problems += "license $id: missing third-party/licenses/$id.txt"
            val key = "license:$id"
            if (f.isFile) texts[key] = clean(f.readText(Charsets.UTF_8))
            mapOf("id" to id, "name" to licenseTable.getValue(id)["name"], "url" to licenseTable.getValue(id)["url"]?.takeIf { it.isNotEmpty() }, "text" to key)
        }
        if (problems.isNotEmpty()) throw GradleException("Third-party list ($platformName):\n  " + problems.distinct().joinToString("\n  "))

        val kinds = listOf("library", "crate", "native", "model", "circuit", "data", "downloaded", "runtime")
        val sorted = entries.sortedWith(compareBy({ kinds.indexOf(it["kind"] as String) }, { (it["name"] as String).lowercase() }, { it["id"] as String }))
        val usedTexts = sorted.flatMap { it["texts"] as List<String> }.toSet() + licenses.map { it["text"] as String }
        val out = outputDir.get().asFile.resolve("files").apply { deleteRecursively(); mkdirs() }
        out.resolve("third-party.json").writeText(
            groovy.json.JsonOutput.toJson(mapOf(
                "format" to 1, "platform" to platformName, "components" to sorted, "licenses" to licenses,
                "texts" to texts.filterKeys { it in usedTexts },
            )),
            Charsets.UTF_8,
        )
        out.resolve("NOTICE.txt").writeText(clean(noticeFile.get().asFile.readText(Charsets.UTF_8)), Charsets.UTF_8)
        out.resolve("LICENSE.txt").writeText(clean(licenseFile.get().asFile.readText(Charsets.UTF_8)), Charsets.UTF_8)
        logger.lifecycle("Third-party list ($platformName): ${sorted.size} components, ${licenses.size} licenses, ${usedTexts.size} texts")
    }
}

@Suppress("UNCHECKED_CAST")
val attachedPaths: List<String> = (readJson(thirdPartyDir.resolve("components.json"))["components"] as List<Map<String, Any?>>)
    .flatMap { (it["files"] as List<String>?).orEmpty() }

fun registerThirdParty(name: String, platformName: String, configurationName: String, natives: List<String>, nativeBuild: String) =
    tasks.register<GenerateThirdParty>(name) {
        // The native build writes the crate lists read here; with diw.zkNative=skip or prebuilt it does nothing.
        dependsOn(nativeBuild)
        group = "build"
        description = "Writes the About page's third-party list for $platformName"
        platform.set(platformName)
        maven.set(providers.provider { collectMaven(configurationName) })
        requireNativeLists.set(providers.environmentVariable("GITHUB_ACTIONS").map { it == "true" }.orElse(false))
        dataDir.set(thirdPartyDir)
        nativeDirs.from(natives.map { rootProject.file(it) })
        attachedFiles.from(attachedPaths.map { rootProject.file(it) })
        repoDir.set(rootProject.layout.projectDirectory)
        noticeFile.set(rootProject.file("NOTICE"))
        licenseFile.set(rootProject.file("LICENSE"))
        outputDir.set(layout.buildDirectory.dir("generated/thirdParty/$platformName"))
    }

registerThirdParty("generateThirdPartyAndroid", "android", "releaseRuntimeClasspath", listOf("native/dist/android", "native/dist/android-bb5"), "buildZkAndroid")
registerThirdParty("generateThirdPartyDesktop", "desktop", "desktopRuntimeClasspath", listOf("native/dist/resources/zk/native"), ":core:buildZkDesktop")
