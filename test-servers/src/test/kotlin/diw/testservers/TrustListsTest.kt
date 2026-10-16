package diw.testservers

import diw.testservers.fixtures.PdfComposer
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustListException
import diw.wallet.core.trust.TrustListKind
import diw.wallet.core.trust.TrustListLoader
import diw.wallet.core.trust.TrustListSnapshot
import diw.wallet.core.trust.TrustLists
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.CertificatePolicies
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.PolicyInformation
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

/** AATL and EUTL: verifying the lists, choosing services, and trusting chains through them (synthetic test PKI). */
class TrustListsTest {
    companion object {
        private val bc = BouncyCastleProvider()
        private val now = Clock.System.now()
        private val day = 86_400_000L

        private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        private class Issued(val key: KeyPair, val cert: X509CertificateHolder) {
            val der: ByteArray get() = cert.encoded
            val x509: X509Cert get() = X509Cert(ByteString(cert.encoded))
        }

        private fun issue(
            subject: String,
            key: KeyPair = rsa(),
            issuer: Issued? = null,
            ca: Boolean,
            from: Long = System.currentTimeMillis() - day,
            until: Long = System.currentTimeMillis() + 365 * day,
            policy: String? = null,
        ): Issued {
            val b = JcaX509v3CertificateBuilder(X500Name(issuer?.cert?.subject?.toString() ?: subject), BigInteger.valueOf(System.nanoTime()),
                Date(from), Date(until), X500Name(subject), key.public)
            val ext = JcaX509ExtensionUtils()
            b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key.public))
            b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuer?.key?.public ?: key.public))
            b.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            b.addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
            policy?.let { b.addExtension(Extension.certificatePolicies, false, CertificatePolicies(PolicyInformation(ASN1ObjectIdentifier(it)))) }
            return Issued(key, b.build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build((issuer?.key ?: key).private)))
        }

        private fun signer(who: Issued, chain: List<Issued> = listOf(who)) = object : DocumentSigner {
            override val certificateChain = chain.map { it.der }
            override val keyType = SignerKeyType.RSA
            override val source = SignerSource.PKCS12
            override suspend fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run {
                initSign(who.key.private); update(data); sign()
            }
        }

        private fun b64(der: ByteArray) = Base64.getEncoder().encodeToString(der)

        // EU list signer and one national list signer, announced by the EU list.
        private val lotlSigner = issue("CN=Test LOTL Signer,C=EU", ca = false)
        private val tlSigner = issue("CN=Test TL Signer AT,C=AT", ca = false)
        private val stranger = issue("CN=Not Announced,C=AT", ca = false)

        // Services of the national list.
        private val qca = issue("CN=Test Qualified CA,O=Test TSP,C=AT", ca = true)
        private val qcaLeaf = issue("CN=Signer Of Documents,C=AT", issuer = qca, ca = false)
        private val webCa = issue("CN=Test Web Only CA,C=AT", ca = true)
        private val webLeaf = issue("CN=Web Leaf,C=AT", issuer = webCa, ca = false)
        private val tsa = issue("CN=Test QTST,C=AT", ca = true)
        private val tsaLeaf = issue("CN=Test TSU,C=AT", issuer = tsa, ca = false)
        // Granted from 2015 to 2025, withdrawn since; its certificates were valid over that period.
        private val from2015 = Instant.parse("2015-01-01T00:00:00Z").toEpochMilliseconds()
        private val oldCa = issue("CN=Test Withdrawn CA,C=AT", ca = true, from = from2015, until = System.currentTimeMillis() + 365 * day)
        private val oldLeaf = issue("CN=Old Signer,C=AT", issuer = oldCa, ca = false, from = from2015, until = System.currentTimeMillis() + 365 * day)

        private const val LOTL = "https://lotl.test/eu-lotl.xml"
        private const val TL_AT = "https://tl.test/at.xml"
        private const val TL_BE = "https://tl.test/be.xml"
        private const val SVC = "http://uri.etsi.org/TrstSvc/Svctype/"
        private const val STATUS = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/"
        private const val EXT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/"

        private fun pointer(territory: String, url: String, signers: List<Issued>) = """
            <OtherTSLPointer>
              <ServiceDigitalIdentities>${signers.joinToString("") { "<ServiceDigitalIdentity><DigitalId><X509Certificate>${b64(it.der)}</X509Certificate></DigitalId></ServiceDigitalIdentity>" }}</ServiceDigitalIdentities>
              <TSLLocation>$url</TSLLocation>
              <AdditionalInformation>
                <OtherInformation><SchemeTerritory>$territory</SchemeTerritory></OtherInformation>
                <OtherInformation><ns3:MimeType xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#">application/vnd.etsi.tsl+xml</ns3:MimeType></OtherInformation>
              </AdditionalInformation>
            </OtherTSLPointer>"""

        private fun lotlXml() = """<?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag">
              <SchemeInformation>
                <TSLVersionIdentifier>6</TSLVersionIdentifier>
                <SchemeTerritory>EU</SchemeTerritory>
                <PointersToOtherTSL>
                  ${pointer("EU", LOTL, listOf(lotlSigner))}
                  ${pointer("AT", TL_AT, listOf(tlSigner))}
                  ${pointer("BE", TL_BE, listOf(tlSigner))}
                </PointersToOtherTSL>
                <ListIssueDateTime>2026-10-01T00:00:00Z</ListIssueDateTime>
                <NextUpdate><dateTime>2027-04-01T00:00:00Z</dateTime></NextUpdate>
              </SchemeInformation>
            </TrustServiceStatusList>""".trimIndent().toByteArray()

        private fun service(type: String, name: String, cert: Issued, status: String, since: String, history: String = "", uses: List<String> = emptyList()) = """
            <TSPService>
              <ServiceInformation>
                <ServiceTypeIdentifier>$SVC$type</ServiceTypeIdentifier>
                <ServiceName><Name xml:lang="de">Dienst</Name><Name xml:lang="en">$name</Name></ServiceName>
                <ServiceDigitalIdentity><DigitalId><X509Certificate>${b64(cert.der)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                <ServiceStatus>$STATUS$status</ServiceStatus>
                <StatusStartingTime>$since</StatusStartingTime>
                ${if (uses.isEmpty()) "" else "<ServiceInformationExtensions>" + uses.joinToString("") { "<Extension Critical=\"false\"><AdditionalServiceInformation><URI xml:lang=\"en\">$EXT$it</URI></AdditionalServiceInformation></Extension>" } + "</ServiceInformationExtensions>"}
              </ServiceInformation>
              ${if (history.isEmpty()) "" else "<ServiceHistory>$history</ServiceHistory>"}
            </TSPService>"""

        private fun historyInstance(type: String, status: String, since: String) = """
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>$SVC$type</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">History</Name></ServiceName>
              <ServiceStatus>$STATUS$status</ServiceStatus>
              <StatusStartingTime>$since</StatusStartingTime>
            </ServiceHistoryInstance>"""

        private fun tlXml(territory: String) = """<?xml version="1.0" encoding="UTF-8"?>
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag">
              <SchemeInformation>
                <TSLVersionIdentifier>6</TSLVersionIdentifier>
                <SchemeTerritory>$territory</SchemeTerritory>
                <ListIssueDateTime>2026-09-15T00:00:00Z</ListIssueDateTime>
                <NextUpdate><dateTime>2027-03-15T00:00:00Z</dateTime></NextUpdate>
              </SchemeInformation>
              <TrustServiceProviderList>
                <TrustServiceProvider>
                  <TSPInformation><TSPName><Name xml:lang="en">Test TSP</Name></TSPName></TSPInformation>
                  <TSPServices>
                    ${service("CA/QC", "Test Qualified CA", qca, "granted", "2020-01-01T00:00:00Z", uses = listOf("ForeSignatures"))}
                    ${service("CA/QC", "Test Web Only CA", webCa, "granted", "2020-01-01T00:00:00Z", uses = listOf("ForWebSiteAuthentication"))}
                    ${service("TSA/QTST", "Test QTST", tsa, "granted", "2020-01-01T00:00:00Z")}
                    ${service("CA/QC", "Test Withdrawn CA", oldCa, "withdrawn", "2025-01-01T00:00:00Z",
                        history = historyInstance("CA/QC", "undersupervision", "2015-01-01T00:00:00Z") + historyInstance("CA/QC", "granted", "2016-07-01T00:00:00Z"))}
                  </TSPServices>
                </TrustServiceProvider>
              </TrustServiceProviderList>
            </TrustServiceStatusList>""".trimIndent().toByteArray()

        private val signedLotl: ByteArray by lazy { runBlocking { DocumentSigning.signXml(lotlXml(), signer(lotlSigner), null) } }
        private val signedAt: ByteArray by lazy { runBlocking { DocumentSigning.signXml(tlXml("AT"), signer(tlSigner), null) } }
        // Signed by a certificate the EU list does not name for Belgium.
        private val forgedBe: ByteArray by lazy { runBlocking { DocumentSigning.signXml(tlXml("BE"), signer(stranger), null) } }
    }

    /** Serves the lists with ETags; requests are recorded as "url conditional?". */
    private class Server {
        val requests = ArrayList<String>()
        val bodies = mapOf(LOTL to signedLotl, TL_AT to signedAt, TL_BE to forgedBe)
        val client = HttpClient(MockEngine { req ->
            val url = req.url.toString()
            val etag = "\"" + url.hashCode() + "\""
            val conditional = req.headers[HttpHeaders.IfNoneMatch] == etag
            requests.add(url + if (conditional) " 304" else "")
            val body = bodies[url] ?: return@MockEngine respond("", HttpStatusCode.NotFound)
            if (conditional) respond("", HttpStatusCode.NotModified) else respond(body, HttpStatusCode.OK, headersOf(HttpHeaders.ETag, etag))
        })
    }

    private fun loader(server: Server) = TrustListLoader(server.client, lotlUrl = LOTL, lotlSignerPins = setOf(TrustLists.pin(lotlSigner.der)))

    private fun registry(snapshot: TrustListSnapshot, lists: Set<TrustListKind> = setOf(TrustListKind.EUTL)) =
        TrustRegistry(EphemeralStorage(), EnvironmentPolicy(trustLists = lists)).also { it.trustLists.install(snapshot) }

    @Test
    fun eutlServicesAnchorDocumentSignersAndTimeStamps() = runBlocking<Unit> {
        val server = Server()
        val snapshot = loader(server).eutl(null)
        assertEquals(listOf("AT", "BE"), snapshot.parts.map { it.territory })
        val at = snapshot.parts.first { it.territory == "AT" }
        assertNull(at.error)
        // The web-only CA is left out; the others are listed once each, for their own role.
        assertEquals(setOf("Test Qualified CA", "Test QTST", "Test Withdrawn CA"), at.services.map { it.name }.toSet())
        assertEquals(setOf(TrustRole.TSA.id), at.services.first { it.name == "Test QTST" }.roles)
        assertEquals(listOf(TrustLists.pin(tlSigner.der)), at.signerPins)
        assertEquals(listOf(TrustLists.pin(lotlSigner.der)), snapshot.signerPins)
        val be = snapshot.parts.first { it.territory == "BE" }
        assertTrue(be.services.isEmpty() && be.error != null, "forged list: ${be.error}")
        assertEquals(listOf("BE：${be.error}"), snapshot.errors)

        val reg = registry(snapshot)
        val doc = reg.decide(TrustRole.DOCUMENT, listOf(qcaLeaf.x509), now)
        assertEquals(TrustTier.T2, doc.tier)
        assertEquals(TrustEnvironment.PRODUCTION, doc.environment)
        assertTrue(!doc.official && TrustLabel.EUTL in doc.labels && TrustLabel.EU_QUALIFIED in doc.labels, "labels: ${doc.labels}")
        assertTrue(doc.anchorName!!.startsWith("Test Qualified CA"), doc.anchorName)

        // Roles are not shared: the time-stamp service anchors time stamps only, the CA documents only.
        assertEquals(TrustTier.T2, reg.decide(TrustRole.TSA, listOf(tsaLeaf.x509), now).tier)
        assertEquals(TrustTier.T3, reg.decide(TrustRole.DOCUMENT, listOf(tsaLeaf.x509), now).tier)
        assertEquals(TrustTier.T3, reg.decide(TrustRole.TSA, listOf(qcaLeaf.x509), now).tier)
        assertEquals(TrustTier.T3, reg.decide(TrustRole.ISSUER, listOf(qcaLeaf.x509), now).tier)
        // A CA for website certificates only does not anchor document signatures.
        assertEquals(TrustTier.T3, reg.decide(TrustRole.DOCUMENT, listOf(webLeaf.x509), now).tier)
        // A withdrawn service anchors only what was signed while it was granted.
        assertEquals(TrustTier.T3, reg.decide(TrustRole.DOCUMENT, listOf(oldLeaf.x509), now).tier)
        assertEquals(TrustTier.T2, reg.decide(TrustRole.DOCUMENT, listOf(oldLeaf.x509), Instant.parse("2020-06-01T00:00:00Z")).tier)
        // The list is consulted only when enabled.
        assertEquals(TrustTier.T3, registry(snapshot, emptySet()).decide(TrustRole.DOCUMENT, listOf(qcaLeaf.x509), now).tier)
        assertEquals(TrustTier.T3, registry(snapshot, setOf(TrustListKind.AATL)).decide(TrustRole.DOCUMENT, listOf(qcaLeaf.x509), now).tier)

        // The snapshot survives storage.
        val back = TrustListSnapshot.decode(snapshot.encode())
        assertEquals(snapshot, back)
    }

    @Test
    fun eutlUpdatesConditionallyAndKeepsListsWhenUnchanged() = runBlocking<Unit> {
        val server = Server()
        val first = loader(server).eutl(null)
        server.requests.clear()
        val second = loader(server).eutl(first)
        // The EU list is unchanged; the national lists are still asked for, with the signers named last time.
        assertTrue("$LOTL 304" in server.requests && "$TL_AT 304" in server.requests, "requests: ${server.requests}")
        assertEquals(first.services, second.services)
        assertNull(second.parts.first { it.territory == "AT" }.error)
        assertTrue(second.fetchedAt >= first.fetchedAt)
    }

    @Test
    fun eutlRejectsAnUnannouncedListSigner() = runBlocking<Unit> {
        val server = Server()
        val e = assertFailsWith<TrustListException> {
            TrustListLoader(server.client, lotlUrl = LOTL, lotlSignerPins = setOf(TrustLists.pin(stranger.der))).eutl(null)
        }
        assertTrue("公告" in e.message!!, e.message)
    }

    @Test
    fun aatlFromASignedSecuritySettingsPdf() = runBlocking<Unit> {
        val root = issue("CN=Test Adobe Root", ca = true)
        val ca = issue("CN=Test Adobe CDS CA", issuer = root, ca = true)
        val listSigner = issue("CN=Test AATL Signer", issuer = ca, ca = false)
        val aatlRoot = issue("CN=Test AATL Member Root,O=Member,C=TW", ca = true)
        val withPolicy = issue("CN=Policy Signer", issuer = aatlRoot, ca = false, policy = "1.2.3.4.5")
        val withoutPolicy = issue("CN=Other Signer", issuer = aatlRoot, ca = false)
        val freeRoot = issue("CN=Test AATL Free Root,C=TW", ca = true)
        val freeLeaf = issue("CN=Free Signer", issuer = freeRoot, ca = false)
        val xml = """<?xml version="1.0" encoding="UTF-8"?>
            <SaSaveData><TrustedIdentities>
              <Identity><ImportAction>1</ImportAction><Certificate>${b64(aatlRoot.der)}</Certificate>
                <CertificatePolicies><OID>1.2.3.4.5</OID></CertificatePolicies></Identity>
              <Identity><Certificate>${b64(freeRoot.der)}</Certificate></Identity>
            </TrustedIdentities></SaSaveData>""".trimIndent().toByteArray()
        val pdf = PdfComposer.compose("AATL", listOf(PdfComposer.Block.Paragraph("Security settings")),
            listOf(PdfComposer.Attachment("SecuritySettings.xml", "text/xml", xml)))
        val signed = DocumentSigning.signPdf(pdf, signer(listSigner, listOf(listSigner, ca, root)), PdfSignOptions(), null)
        val pins = setOf(TrustLists.pin(root.der))

        val (services, signerName) = TrustListLoader.aatlFromPdf(signed, pins, now)
        assertEquals("Test AATL Signer", signerName)
        assertEquals(2, services.size)
        assertEquals(listOf("1.2.3.4.5"), services.first { it.name == "Test AATL Member Root" }.policies)

        // Only the pinned root signs the list, and nothing may follow the signature.
        assertFailsWith<TrustListException> { TrustListLoader.aatlFromPdf(signed, setOf(TrustLists.pin(aatlRoot.der)), now) }
        assertFailsWith<TrustListException> { TrustListLoader.aatlFromPdf(signed + "\n%x\n".toByteArray(), pins, now) }

        val snapshot = TrustListSnapshot(kind = TrustListKind.AATL.id, fetchedAt = now.epochSeconds,
            parts = listOf(diw.wallet.core.trust.TrustListPart("AATL", "https://aatl.test", services = services)))
        val reg = registry(snapshot, setOf(TrustListKind.AATL))
        val ok = reg.decide(TrustRole.DOCUMENT, listOf(withPolicy.x509), now)
        assertEquals(TrustTier.T2, ok.tier)
        assertTrue(TrustLabel.AATL in ok.labels && TrustLabel.EU_QUALIFIED !in ok.labels, "labels: ${ok.labels}")
        // A restricted identity anchors only chains carrying one of its policies.
        assertEquals(TrustTier.T3, reg.decide(TrustRole.DOCUMENT, listOf(withoutPolicy.x509), now).tier)
        assertEquals(TrustTier.T2, reg.decide(TrustRole.TSA, listOf(freeLeaf.x509), now).tier)
        assertNotNull(reg.trustLists.snapshot(TrustListKind.AATL))
        reg.trustLists.remove(TrustListKind.AATL)
        assertEquals(TrustTier.T3, reg.decide(TrustRole.DOCUMENT, listOf(freeLeaf.x509), now).tier)
    }
}
