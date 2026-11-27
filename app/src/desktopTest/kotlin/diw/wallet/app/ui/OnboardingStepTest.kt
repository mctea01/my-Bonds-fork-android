package diw.wallet.app.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.LinkAnnotation
import diw.wallet.app.ConsentRecord
import diw.wallet.app.LegalConsent
import diw.wallet.app.legal.Integration
import diw.wallet.app.legal.LegalTexts
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The first-start pages: only the terms and the privacy policy are required; every service statement is optional. */
class OnboardingStepTest {
    private val basics = LegalConsent(
        terms = ConsentRecord(LegalTexts.terms.version, true, 0),
        privacy = ConsentRecord(LegalTexts.privacy.version, true, 0),
    )

    private fun LegalConsent.decide(i: Integration, accepted: Boolean) =
        copy(integrations = integrations + (i.id to ConsentRecord(LegalTexts.statement(i).document.version, accepted, 0)))

    @Test
    fun theConsentPageStaysUntilEveryTextIsDecided() {
        assertEquals(OnboardingStep.WELCOME, onboardingStep(LegalConsent(), welcomed = false))
        assertEquals(OnboardingStep.CONSENT, onboardingStep(LegalConsent(), welcomed = true))
        assertEquals(OnboardingStep.CONSENT, onboardingStep(basics, welcomed = true))
        val first = basics.undecided.first()
        assertEquals(OnboardingStep.CONSENT, onboardingStep(basics.decide(first, true), welcomed = true))
    }

    @Test
    fun leavingEveryServiceUntickedCompletesTheFirstStart() {
        val shipped = Integration.entries.filter { it.available }
        val allOff = basics.undecided.fold(basics) { c, i -> c.decide(i, false) }
        assertTrue(allOff.complete)
        assertTrue(shipped.none { allOff.enabled(it) })
        assertEquals(OnboardingStep.DONE, onboardingStep(allOff, welcomed = true))
    }

    @Test
    fun documentNamesBecomeLinks() {
        var opened = ""
        val text = linkedText("A %1\$s B %2\$s C", listOf("terms" to { opened = "terms" }, "privacy" to { opened = "privacy" }), Color.Blue)
        assertEquals("A terms B privacy C", text.text)
        val links = text.getLinkAnnotations(0, text.length)
        assertEquals(listOf("terms", "privacy"), links.map { text.text.substring(it.start, it.end) })
        (links[1].item as LinkAnnotation.Clickable).linkInteractionListener!!.onClick(links[1].item)
        assertEquals("privacy", opened)
        assertEquals("only %3\$s", linkedText("only %3\$s", emptyList(), Color.Blue).text)
    }

    @Test
    fun plainPartsHaveNoLink() {
        val text = linkedText("%1\$s - %2\$s", listOf("operator" to null, "page" to {}), Color.Blue)
        assertEquals("operator - page", text.text)
        assertEquals(listOf("page"), text.getLinkAnnotations(0, text.length).map { text.text.substring(it.start, it.end) })
    }

    @Test
    fun everyServiceLinksToItsOperatorOverHttps() {
        Integration.entries.forEach { assertTrue(it.operatorUrl.startsWith("https://"), it.id) }
    }
}
