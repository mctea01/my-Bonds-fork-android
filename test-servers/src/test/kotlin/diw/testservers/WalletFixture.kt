package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.QesApprovalTransaction
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.w3c.addDiwCredentialImplementations
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.sdjwt.SdJwt
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage

/** A JVM wallet built from the core library, with software keys (fallback layer). */
class WalletFixture(
    val trustVerifierRoot: Boolean = true,
    val policy: PresentationPolicy = PresentationPolicy(),
    val trustIssuer: Boolean = true,
    val httpClient: HttpClient = HttpClient(Java) { followRedirects = false },
    val env: EnvironmentPolicy = EnvironmentPolicy(testEnvironmentEnabled = true, allowInsecureLoopbackHttp = true),
) {
    val storage = EphemeralStorage()
    val trust = TrustRegistry(storage, env)
    lateinit var secureArea: SoftwareSecureArea
    lateinit var documentStore: DocumentStore
    val documentTypes = DocumentTypeRepository().apply {
        addDocumentType(DrivingLicense.getDocumentType())
        addDocumentType(EUPersonalID.getDocumentType())
        QesApprovalTransaction.types.forEach { addTransactionType(it) }
    }
    lateinit var source: SimplePresentmentSource
    lateinit var holder: Oid4vpHolder
    lateinit var secureAreas: SecureAreaRepository
    lateinit var holderIdentities: HolderIdentities

    suspend fun init(pki: TestPki? = null): WalletFixture {
        secureArea = SoftwareSecureArea.create(storage)
        secureAreas = SecureAreaRepository.Builder().add(secureArea).build()
        documentStore = buildDocumentStore(storage, secureAreas) { addDiwCredentialImplementations(secureAreas) }
        holderIdentities = HolderIdentities(storage, secureAreas)
        source = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypes,
            domainsMdocSignature = listOf("mdoc"),
            domainsKeyBoundSdJwt = listOf("sdjwt"),
        )
        if (trustVerifierRoot && pki != null) {
            trust.addAnchor(TrustRole.VERIFIER, TrustEnvironment.TEST, pki.readerRootCert, "DIW TEST Verifier Root", false, "test")
        }
        if (trustIssuer && pki != null) trust.addAnchor(TrustRole.ISSUER, TrustEnvironment.TEST, pki.iacaCert, "DIW TEST IACA", false, "test")
        holder = Oid4vpHolder(httpClient, trust, source, env, policy, holderIdentities)
        return this
    }

    suspend fun issueSdJwtPid(pki: TestPki) {
        val doc = documentStore.createDocument(displayName = "PID")
        val cred = KeyBoundSdJwtVcCredential.create(doc, null, "sdjwt", secureArea, EUPersonalID.EUPID_VCT, SoftwareCreateKeySettings.Builder().build())
        val sdJwt = SdJwt.create(
            issuerKey = pki.documentSigner,
            kbKey = secureArea.getKeyInfo(cred.alias).publicKey,
            claims = buildJsonObject {
                put("given_name", "Che-Chuan"); put("family_name", "Lin"); put("birthdate", "1990-01-01"); put("nationality", "TW")
            },
            nonSdClaims = buildJsonObject {
                put("iss", "https://issuer.test.diw.invalid"); put("vct", EUPersonalID.EUPID_VCT)
                put("iat", pki.validFrom.epochSeconds); put("exp", pki.validUntil.epochSeconds)
            },
        )
        cred.certify(sdJwt.compactSerialization.encodeToByteString())
    }

    suspend fun issueMdl(pki: TestPki, authorizedTransactionNamespaces: List<String> = emptyList()) {
        val nsData = buildIssuerNamespaces {
            addNamespace(DrivingLicense.MDL_NAMESPACE) {
                addDataElement("given_name", Tstr("Che-Chuan"))
                addDataElement("family_name", Tstr("Lin"))
                addDataElement("age_over_18", org.multipaz.cbor.Simple.TRUE)
                addDataElement("issuing_country", Tstr("TW"))
            }
        }
        val doc = documentStore.createDocument(displayName = "mDL")
        val cred = MdocCredential.create(doc, null, "mdoc", secureArea, DrivingLicense.MDL_DOCTYPE, SoftwareCreateKeySettings.Builder().build())
        val mso = MobileSecurityObject(
            version = "1.0", docType = DrivingLicense.MDL_DOCTYPE,
            signedAt = pki.validFrom, validFrom = pki.validFrom, validUntil = pki.validUntil, expectedUpdate = null,
            digestAlgorithm = Algorithm.SHA256, valueDigests = nsData.getValueDigests(Algorithm.SHA256),
            deviceKey = cred.getAttestation().publicKey,
            deviceKeyAuthorizedNamespaces = authorizedTransactionNamespaces,
        )
        val tagged = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(mso.toDataItem()))))
        val prot = mapOf<CoseLabel, DataItem>(CoseNumberLabel(Cose.COSE_LABEL_ALG) to Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem())
        val unprot = mapOf<CoseLabel, DataItem>(CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN) to pki.documentSigner.certChain.toDataItem())
        val issuerAuth = Cbor.encode(Cose.coseSign1Sign(pki.documentSigner, tagged, true, prot, unprot).toDataItem())
        cred.certify(ByteString(Cbor.encode(buildCborMap {
            put("nameSpaces", nsData.toDataItem())
            put("issuerAuth", RawCbor(issuerAuth))
        })))
    }
}
