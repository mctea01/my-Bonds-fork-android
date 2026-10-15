package diw.testservers

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Android compiles patterns with ICU, where "[:" opens a POSIX property ("[:alpha:]") and fails as
 * "Incorrect Unicode property"; the JVM accepts the same pattern, so only a source scan catches it.
 */
class RegexPortabilityTest {
    @Test
    fun noCharacterClassStartsWithColon() {
        val roots = listOf("../core/src", "../app/src").map { File(it) }.filter { it.isDirectory }
        assertTrue(roots.isNotEmpty(), "source roots not found")
        val offending = roots.flatMap { root ->
            root.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { f ->
                f.readLines().mapIndexedNotNull { i, line ->
                    val code = line.substringBefore("//")
                    if (("Regex(" in code || "toRegex" in code) && Regex("(?<!\\\\)\\[:").containsMatchIn(code)) "${f.path}:${i + 1}" else null
                }
            }
        }
        assertTrue(offending.isEmpty(), "character classes starting with ':' break on Android: $offending")
    }
}
