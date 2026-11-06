package diw.wallet.app

import org.jetbrains.compose.resources.DensityQualifier
import org.jetbrains.compose.resources.InternalResourceApi
import org.jetbrains.compose.resources.LanguageQualifier
import org.jetbrains.compose.resources.RegionQualifier
import org.jetbrains.compose.resources.ResourceEnvironment
import org.jetbrains.compose.resources.ThemeQualifier

// The constructor is internal to the library; the release builds keep it (compose-resources rules).
@OptIn(InternalResourceApi::class)
private val environmentConstructor = runCatching {
    ResourceEnvironment::class.java.getDeclaredConstructor(
        LanguageQualifier::class.java, RegionQualifier::class.java, ThemeQualifier::class.java, DensityQualifier::class.java,
    ).apply { isAccessible = true }
}.getOrNull()

@OptIn(InternalResourceApi::class)
internal actual fun languageEnvironment(language: String, region: String): ResourceEnvironment? = runCatching {
    environmentConstructor?.newInstance(LanguageQualifier(language), RegionQualifier(region), ThemeQualifier.LIGHT, DensityQualifier.MDPI)
}.getOrNull()
