package diw.wallet.app

import diw.wallet.app.res.Res
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The third-party list of this build, generated for each platform by app/third-party.gradle.kts from what the build
 * packages: Maven libraries, the Rust crates of the native libraries and the curated components of
 * third-party/components.json. [texts] holds every license text and every license or notice file, by key.
 */
@Serializable
class ThirdPartyCatalog(
    val platform: String = "",
    val components: List<ThirdPartyComponent> = emptyList(),
    val licenses: List<ThirdPartyLicense> = emptyList(),
    val texts: Map<String, String> = emptyMap(),
) {
    fun component(id: String): ThirdPartyComponent? = components.firstOrNull { it.id == id }
    fun license(id: String): ThirdPartyLicense? = licenses.firstOrNull { it.id == id }
    fun usersOf(licenseId: String): List<ThirdPartyComponent> = components.filter { licenseId in it.licenses }

    /** The components whose name, coordinates, version, license or description contain [query]. */
    fun search(query: String, kind: ThirdPartyKind?, language: String): List<ThirdPartyComponent> {
        val q = query.trim()
        return components.filter { c ->
            (kind == null || c.kind == kind.id) && (q.isEmpty() ||
                listOfNotNull(c.name, c.coordinates, c.version, c.license, c.description(language)).any { it.contains(q, ignoreCase = true) } ||
                c.licenses.any { id -> license(id)?.name?.contains(q, ignoreCase = true) == true })
        }
    }
}

@Serializable
class ThirdPartyComponent(
    val id: String,
    val kind: String,
    val name: String,
    val version: String? = null,
    /** Maven group and artifact. */
    val coordinates: String? = null,
    /** As published: an SPDX expression, or the POM's licenses joined with commas. */
    val license: String = "",
    /** SPDX identifiers of [license], each in [ThirdPartyCatalog.licenses]. */
    val licenses: List<String> = emptyList(),
    val url: String? = null,
    val copyright: String? = null,
    private val description: Map<String, String>? = null,
    /** Where it is: the native libraries that link a crate, or the distributions that carry a runtime. */
    private val scope: Map<String, String>? = null,
    /** Keys of the component's own license and notice files in [ThirdPartyCatalog.texts]. */
    val texts: List<String> = emptyList(),
) {
    fun description(language: String): String? = description.localized(language)
    fun scope(language: String): String? = scope.localized(language)
}

@Serializable
class ThirdPartyLicense(val id: String, val name: String? = null, val url: String? = null, val text: String = "")

private fun Map<String, String>?.localized(language: String): String? = this?.let { it[language] ?: it["en"] ?: it.values.firstOrNull() }

/** The groups of the list, in the order the list shows them. */
enum class ThirdPartyKind(val id: String) {
    LIBRARY("library"), CRATE("crate"), NATIVE("native"), MODEL("model"), CIRCUIT("circuit"),
    DATA("data"), DOWNLOADED("downloaded"), RUNTIME("runtime");

    companion object {
        fun of(id: String): ThirdPartyKind? = entries.firstOrNull { it.id == id }
    }
}

/** Reads the generated files once; null when the build has none (a build that skipped the generation). */
object ThirdParty {
    private val json = Json { ignoreUnknownKeys = true; coerceInputValues = true }
    private val lock = Mutex()
    private var catalog: ThirdPartyCatalog? = null

    suspend fun catalog(): ThirdPartyCatalog? = lock.withLock {
        catalog ?: runCatching { parse(Res.readBytes("files/third-party.json").decodeToString()) }.getOrNull()?.also { catalog = it }
    }

    fun parse(text: String): ThirdPartyCatalog = json.decodeFromString(ThirdPartyCatalog.serializer(), text)

    /** NOTICE or LICENSE of this repository as the build packaged it. */
    suspend fun document(name: String): String? = runCatching { Res.readBytes("files/$name.txt").decodeToString() }.getOrNull()
}
