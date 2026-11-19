package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.did.DidKeys
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.verifier.AssuranceLevel
import diw.wallet.core.verifier.Check
import diw.wallet.core.verifier.CredentialVerification
import diw.wallet.core.verifier.Oid4vpMailboxClient
import diw.wallet.core.verifier.OnlineRequest
import diw.wallet.core.verifier.OnlineVerifierRequests
import diw.wallet.core.verifier.PresentationVerification
import diw.wallet.core.verifier.VerificationPolicy
import diw.wallet.core.verifier.declaration.DeclarationContent
import diw.wallet.core.verifier.declaration.DeclarationEvidence
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.verifier.declaration.CertificateJwsSigner
import diw.wallet.core.verifier.declaration.DidJwsSigner
import diw.wallet.core.verifier.declaration.JwsSigner
import diw.wallet.core.verifier.declaration.x509HashClientId
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64
import diw.wallet.core.verifier.declaration.EvidenceQueries
import diw.wallet.core.verifier.declaration.MandateContent
import diw.wallet.core.verifier.declaration.PartyId
import diw.wallet.core.verifier.declaration.ProximityDeclaration
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import org.multipaz.cbor.DataItem
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import diw.wallet.core.verifier.declaration.VerifierAgent
import diw.wallet.core.verifier.declaration.VerifierDeclaration
import diw.wallet.core.verifier.declaration.VerifierKind
import diw.wallet.core.verifier.declaration.VerifierMandate
import diw.wallet.core.verifier.declaration.VerifierParty
import diw.wallet.core.verifier.declaration.VerifierPurpose
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.storage.StorageTableSpec
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** An OpenPGP key of the holder's own card whose signature over each request is added as evidence for [role]. */
@Serializable
data class OpenPgpProof(val role: String, val fingerprint: String, val name: String)

/**
 * Who this wallet says it is when it verifies (docs/design/p5-verifier.md section 3). Requests are signed with the
 * profile's own did:key, or with an X.509 certificate key chosen when verifying (a card, PIV, PKCS#11, system or
 * PKCS#12 key, the mobile citizen certificate or a CSC service). The evidence is the wallet's own credentials (by
 * document id, with the claims the user chose), presented afresh for each request, the mandates other parties signed
 * for this profile's key, and optionally signatures of the holder's OpenPGP cards.
 */
@Serializable
data class VerifierProfile(
    val id: String,
    val kind: String = VerifierKind.NATURAL_PERSON.wire,
    val partyName: String,
    val partyScheme: String? = null,
    val partyValue: String? = null,
    val publicBody: Boolean = false,
    val agentName: String? = null,
    val agentRole: String? = null,
    val purpose: String = "",
    val legalBasis: String? = null,
    val retention: String? = null,
    val privacyPolicy: String? = null,
    val partyEvidence: List<String> = emptyList(),
    val agentEvidence: List<String> = emptyList(),
    val mandates: List<String> = emptyList(),
    /** A WRPRC (rc-wrp+jwt) issued to this profile's key, sent as verifier_info before the declaration. */
    val registration: String? = null,
    /** [SIGN_WALLET] (the profile's did:key) or [SIGN_X509] (a certificate key chosen when verifying). */
    val signingKey: String = SIGN_WALLET,
    /** The certificate (DER, base64) the X.509 key had when last read, for its name and client_id between uses. */
    val x509Certificate: String? = null,
    /** Claims chosen per evidence, keyed by "<role>:<document id>"; without an entry the identifying claims are disclosed. */
    val evidenceClaims: Map<String, List<List<String>>> = emptyMap(),
    val openPgp: List<OpenPgpProof> = emptyList(),
) {
    val usesX509: Boolean get() = signingKey == SIGN_X509

    /** The evidence count shown in lists: credentials, mandates and OpenPGP signatures. */
    val evidenceCount: Int get() = partyEvidence.size + agentEvidence.size + mandates.size + openPgp.size

    val verifierKind: VerifierKind get() = VerifierKind.fromWire(kind) ?: VerifierKind.NATURAL_PERSON

    /** The party and agent as the declaration states them. */
    fun party(): VerifierParty = VerifierParty(
        legal = verifierKind.partyLegal,
        name = partyName.trim(),
        id = partyScheme?.takeIf { it.isNotBlank() }?.let { s -> partyValue?.trim()?.takeIf { it.isNotEmpty() }?.let { PartyId(s, it) } },
        publicBody = publicBody.takeIf { verifierKind.partyLegal },
    )

    fun agent(): VerifierAgent? = if (!verifierKind.representative) null else
        agentName?.trim()?.takeIf { it.isNotEmpty() }?.let { VerifierAgent(it, agentRole?.trim()?.takeIf { r -> r.isNotEmpty() }) }

    companion object {
        const val SIGN_WALLET = "wallet"
        const val SIGN_X509 = "x509"

        fun claimKey(role: String, documentId: String): String = "$role:$documentId"
    }
}

/** The keys the user unlocked for one verification: the X.509 key and the OpenPGP cards by primary fingerprint. */
data class VerifierKeys(val x509: SignerChoice? = null, val openPgp: Map<String, SignerChoice.OpenPgp> = emptyMap()) {
    /** Whether every key [p] needs was given. */
    fun complete(p: VerifierProfile?, proximity: Boolean = false): Boolean =
        p == null || (proximity || !p.usesX509 || x509 != null) && p.openPgp.all { it.fingerprint in openPgp }
}

/** What the online verification asks for: one credential query. */
data class OnlineAsk(val id: String, val title: String, val query: JsonObject) {
    val dcql: JsonObject get() = buildJsonObject { putJsonArray("credentials") { add(query) } }

    companion object {
        /** The in-person presets as mdoc queries, and the EU PID as an SD-JWT VC. */
        fun all(): List<OnlineAsk> = ReaderRequest.entries.map { r -> OnlineAsk(r.name, r.title, r.query) } + OnlineAsk("PID_SD_JWT", tr(Res.string.ov_ask_pid_sdjwt), buildJsonObject {
            put("id", "q0")
            put("format", "dc+sd-jwt")
            put("meta", buildJsonObject { putJsonArray("vct_values") { add("urn:eudi:pid:1") } })
            putJsonArray("claims") {
                listOf("family_name", "given_name", "birthdate", "nationalities").forEach { add(buildJsonObject { put("path", buildJsonArray { add(it) }) }) }
            }
        })
    }
}

/** How the holder's wallet reaches this one: the user's server mailbox, or this phone on the local network. */
enum class OnlineRoute { SERVER, LAN }

/** One presented credential with its assurance and the policy's verdict. */
data class OnlineCredential(val verification: CredentialVerification, val level: AssuranceLevel?, val rule: Check)

sealed class OnlineVerifyUi {
    data object Setup : OnlineVerifyUi()
    data class Working(val message: String) : OnlineVerifyUi()
    /** The QR code for the holder: [invocation] opens the request on the holder's wallet. */
    data class Waiting(val invocation: String, val route: String, val profile: String?, val expiresAt: Instant, val details: List<String>) : OnlineVerifyUi()
    data class Result(
        val ask: String,
        val profile: String?,
        val policy: VerificationPolicy,
        val verification: PresentationVerification,
        val credentials: List<OnlineCredential>,
    ) : OnlineVerifyUi() {
        val passed: Boolean get() = verification.passed && credentials.all { it.rule.status == diw.wallet.core.verifier.CheckStatus.PASS }
    }
    data class Failed(val message: String) : OnlineVerifyUi()
}

/**
 * The wallet as an OpenID4VP verifier (docs/design/p5-verifier.md section 6): it signs a request with a profile's key,
 * carries the profile's declaration and evidence in verifier_info, and receives the holder's encrypted response
 * through the user's server mailbox or directly on the local network, then judges it under a [VerificationPolicy].
 */
class VerifierModel(private val model: WalletModel) {
    val profiles = MutableStateFlow<List<VerifierProfile>>(emptyList())
    val online = MutableStateFlow<OnlineVerifyUi>(OnlineVerifyUi.Setup)
    /** The profile being edited; null shows the list. */
    val editing = MutableStateFlow<VerifierProfile?>(null)
    private var job: Job? = null

    suspend fun load() {
        val raw = model.storage.getTable(TABLE).get(KEY) ?: return
        profiles.value = runCatching { DiwJson.decodeFromString(ListSerializer(VerifierProfile.serializer()), raw.decodeToString()) }.getOrDefault(emptyList())
    }

    private suspend fun persist(list: List<VerifierProfile>) {
        val t = model.storage.getTable(TABLE)
        val bytes = DiwJson.encodeToString(ListSerializer(VerifierProfile.serializer()), list).encodeToByteString()
        if (t.get(KEY) == null) t.insert(KEY, bytes) else t.update(KEY, bytes)
        profiles.value = list
    }

    fun openProfiles() {
        editing.value = null
        model.screen.value = Screen.VerifierProfiles
        model.scope.launch { load() }
    }

    fun newProfile() {
        editing.value = VerifierProfile(id = PlatformCrypto.randomBytes(12).toBase64Url(), partyName = "")
    }

    fun edit(p: VerifierProfile) {
        editing.value = p
    }

    fun save(p: VerifierProfile) = model.scope.launch {
        if (p.partyName.isBlank()) {
            model.message.value = tr(Res.string.vp_name_needed)
            return@launch
        }
        val list = profiles.value.filter { it.id != p.id } + p
        persist(list)
        editing.value = null
    }

    fun delete(p: VerifierProfile) = model.scope.launch {
        persist(profiles.value.filter { it.id != p.id })
        editing.value = null
    }

    /** The profile's key, made the first time it is used. */
    private suspend fun key(profileId: String?): HolderKey {
        val backend = model.backends.first()
        return model.holderIdentities.getOrCreate(profileId?.let { PROFILE_PREFIX + it } ?: ANONYMOUS_PROFILE, "did:key", backend.secureArea,
            backend.settings(ByteString(PlatformCrypto.randomBytes(16)), false))
    }

    private suspend fun didSigner(profileId: String?): DidJwsSigner {
        val k = key(profileId)
        val did = k.did ?: DidKeys.didKey(k.publicKey)
        return DidJwsSigner(k.signingKey(), did, DidKeys.verificationMethod(did))
    }

    /** Reads the X.509 key [choice] (a card is tapped here); SM2 keys and keys without a certificate are refused. */
    suspend fun readX509(choice: SignerChoice): CertificateJwsSigner = try {
        CertificateJwsSigner(model.files.signer(choice, tr(Res.string.ov_sign_hint)))
    } finally {
        model.files.busy.value = null
    }

    /** The key that signs as [p]: its did:key, or the X.509 key in [keys] (whose certificate is remembered in [p]). */
    private suspend fun signer(p: VerifierProfile?, keys: VerifierKeys): JwsSigner {
        if (p == null || !p.usesX509) return didSigner(p?.id)
        val choice = keys.x509 ?: throw ProtocolException("no_key", tr(Res.string.ov_x509_needed))
        val s = readX509(choice)
        val leaf = s.certificateChain.first().toBase64()
        if (p.x509Certificate != leaf) update(p.id) { it.copy(x509Certificate = leaf) }
        return s
    }

    /**
     * The client_id another party names in a mandate for [p]: decentralized_identifier:did:key:..., or x509_hash of
     * the certificate its X.509 key had when last read (null before it was read).
     */
    suspend fun clientId(p: VerifierProfile): String? =
        if (!p.usesX509) didSigner(p.id).clientId else p.x509Certificate?.let { x509HashClientId(it.fromBase64()) }

    /** Adds a mandate (compact JWS) someone signed for [p]; it must name this profile's key as the agent. */
    fun importMandate(p: VerifierProfile, jws: String) = model.scope.launch {
        val compact = jws.trim()
        val parsed = runCatching { VerifierMandate.parse(compact).content }.getOrNull()
        val own = clientId(p)
        when {
            parsed == null -> model.message.value = tr(Res.string.vp_mandate_unreadable)
            own == null -> model.message.value = tr(Res.string.vp_x509_not_read)
            own !in parsed.agentClientIds -> model.message.value = tr(Res.string.vp_mandate_other_key)
            else -> {
                val updated = p.copy(mandates = (p.mandates + compact).distinct())
                editing.value = updated
                persist(profiles.value.map { if (it.id == p.id) updated else it })
                model.message.value = tr(Res.string.vp_mandate_added, parsed.principal.name)
            }
        }
    }

    /**
     * Signs a mandate as [p] (the principal) for an agent: [agentClientId] is the agent's client_id, valid for [days]
     * days. Returns the compact JWS for the agent to import.
     */
    suspend fun issueMandate(
        p: VerifierProfile, agentName: String, agentRole: String?, agentClientId: String, purposes: List<String>, days: Int, keys: VerifierKeys,
    ): String = withContext(model.unlockProvider) {
        val s = signer(p, keys)
        val now = Clock.System.now()
        val content = MandateContent(
            principal = p.party(),
            agent = VerifierAgent(agentName.trim(), agentRole?.trim()?.takeIf { it.isNotEmpty() }),
            agentClientIds = listOf(agentClientId.trim()),
            purposes = purposes.map { it.trim() }.filter { it.isNotEmpty() },
            credentials = null,
            notBefore = now,
            expiresAt = now + days.coerceIn(1, 366).days,
        )
        VerifierMandate.sign(content, s, s.clientId, now)
    }

    fun openOnline() {
        stop()
        online.value = OnlineVerifyUi.Setup
        model.screen.value = Screen.OnlineVerify
        model.scope.launch { load() }
    }

    fun close() = stop()

    fun again() {
        stop()
        online.value = OnlineVerifyUi.Setup
    }

    private fun stop() {
        job?.cancel()
        job = null
        model.platform.keepScreenOn(false)
    }

    /** Whether the configured server can relay (feature oid4vp), as far as the last check of it showed. */
    fun serverRoute(): String? = model.server.base()

    fun start(ask: OnlineAsk, profile: VerifierProfile?, purpose: String, risk: RiskLevel, policy: VerificationPolicy, route: OnlineRoute, keys: VerifierKeys) {
        stop()
        online.value = OnlineVerifyUi.Working(tr(Res.string.ov_preparing))
        job = model.scope.launch(model.unlockProvider) {
            try {
                if (profile?.usesX509 == true) online.value = OnlineVerifyUi.Working(tr(Res.string.ov_reading_x509))
                val signer = signer(profile, keys)
                val verifierInfo: suspend (String, String) -> List<JsonObject> = { clientId, nonce ->
                    if (profile == null) emptyList() else declaration(profile, purpose, ask, clientId, nonce, signer, keys)
                }
                val result = when (route) {
                    OnlineRoute.SERVER -> viaServer(ask, profile, signer, verifierInfo)
                    OnlineRoute.LAN -> viaLan(ask, profile, signer, verifierInfo)
                } ?: run {
                    online.value = OnlineVerifyUi.Failed(tr(Res.string.ov_expired))
                    return@launch
                }
                online.value = OnlineVerifyUi.Working(tr(Res.string.ov_verifying))
                online.value = judge(ask, profile, policy, risk, result.first, result.second)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val message = tr(Res.string.ov_failed) + model.describe(e)
                model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = note(ask, profile), failure = message)
                online.value = OnlineVerifyUi.Failed(message)
            } finally {
                model.platform.keepScreenOn(false)
            }
        }
    }

    /** verifier_info for [profile]: its registration certificate, then the declaration bound to this request. */
    private suspend fun declaration(
        p: VerifierProfile, purpose: String, ask: OnlineAsk, clientId: String, nonce: String, signer: JwsSigner, keys: VerifierKeys,
    ): List<JsonObject> {
        val declared = VerifierDeclaration.entry(declarationJws(p, purpose, ask.query, clientId, nonce, signer, keys) { online.value = OnlineVerifyUi.Working(it) })
        val registration = registrationOf(p)?.let { buildJsonObject { put("format", "jwt"); put("data", it) } }
        return listOfNotNull(registration, declared)
    }

    private fun registrationOf(p: VerifierProfile): String? = p.registration?.trim()?.takeIf { it.count { c -> c == '.' } == 2 }

    /** Reader certificates made in this run, by profile id. */
    private val readerCertificates = HashMap<String, X509CertChain>()

    /**
     * The ISO/IEC 18013-5 reader authentication key of [p]: the profile's did:key key with a certificate it issues
     * itself, naming the agent of a representative and the party otherwise. A holder judges it T3 at most; the
     * declaration's evidence says who it is. An X.509 profile uses this key too in person.
     */
    suspend fun readerKey(p: VerifierProfile): AsymmetricKey.X509CertifiedSecureAreaBased {
        val k = key(p.id)
        val chain = readerCertificates[p.id] ?: run {
            val subject = (p.agent()?.name ?: p.partyName).trim().ifEmpty { tr(Res.string.wallet_user) }
            val der = DocumentSigning.selfIssuedCertificate(FilesModel.spki(k.publicKey), subject,
                { data -> k.signingKey("ES256").sign(data).toDerEncoded() }, SignerKeyType.EC_P256, 365)
            X509CertChain(listOf(X509Cert(ByteString(der)))).also { readerCertificates[p.id] = it }
        }
        return AsymmetricKey.X509CertifiedSecureAreaBased(certChain = chain, secureArea = k.secureArea, keyInfo = k.keyInfo, algorithm = k.signingKey("ES256").algorithm)
    }

    /**
     * The requestInfo of an in-person request as [p] asking for [query]: the declaration signed by [key], with the
     * client_id x509_hash of its certificate and the nonce of [encodedTranscript], and the registration certificate.
     */
    suspend fun proximityRequestInfo(
        p: VerifierProfile, purpose: String, query: JsonObject, key: AsymmetricKey.X509CertifiedSecureAreaBased,
        encodedTranscript: ByteArray, keys: VerifierKeys, progress: (String) -> Unit,
    ): Map<String, DataItem> {
        val clientId = ProximityDeclaration.clientId(key.certChain)
        val nonce = VerifierDeclaration.proximityNonce(encodedTranscript)
        val jws = declarationJws(p, purpose, query, clientId, nonce, didSigner(p.id), keys, progress)
        return ProximityDeclaration.requestInfo(jws, registrationOf(p))
    }

    /** The declaration of [p] for [query], bound to [clientId] and [nonce], with its evidence presented afresh. */
    private suspend fun declarationJws(
        p: VerifierProfile, purpose: String, query: JsonObject, clientId: String, nonce: String, signer: JwsSigner, keys: VerifierKeys,
        progress: (String) -> Unit,
    ): String {
        progress(tr(Res.string.ov_evidence))
        val holder = model.holder()
        val evidence = ArrayList<DeclarationEvidence>()
        for ((role, ids) in listOf(DeclarationEvidence.ROLE_PARTY to p.partyEvidence, DeclarationEvidence.ROLE_AGENT to p.agentEvidence)) {
            for ((i, docId) in ids.withIndex()) {
                val doc = model.documentStore.lookupDocument(docId) ?: continue
                val credential = doc.getCertifiedCredentials().firstOrNull() ?: continue
                val query = EvidenceQueries.forCredential("$role$i", credential, model.documentTypes, p.evidenceClaims[VerifierProfile.claimKey(role, docId)])
                    ?: throw ProtocolException("invalid_evidence", tr(Res.string.ov_evidence_unusable, doc.displayName ?: docId))
                evidence += DeclarationEvidence.Presentation(role, query, holder.evidence(clientId, nonce, query, docId))
            }
        }
        p.mandates.forEach { evidence += DeclarationEvidence.Mandate(it) }
        p.openPgp.forEach { proof -> evidence += openPgpEvidence(proof, keys, clientId, nonce, progress) }
        val content = DeclarationContent(
            kind = p.verifierKind,
            party = p.party(),
            agent = p.agent(),
            purpose = VerifierPurpose(
                text = purpose.ifBlank { p.purpose }.trim(),
                lang = tr(Res.string.ov_lang),
                legalBasis = p.legalBasis,
                retention = p.retention,
                privacyPolicy = p.privacyPolicy?.trim()?.takeIf { it.isNotEmpty() },
            ),
            credentials = buildJsonArray { add(query) },
        )
        return VerifierDeclaration.sign(content, clientId, nonce, evidence, signer)
    }

    /** The holder's OpenPGP card signs this request's client_id and nonce; the card must hold [proof]'s key. */
    private suspend fun openPgpEvidence(
        proof: OpenPgpProof, keys: VerifierKeys, clientId: String, nonce: String, progress: (String) -> Unit,
    ): DeclarationEvidence.OpenPgp {
        val choice = keys.openPgp[proof.fingerprint] ?: throw ProtocolException("no_key", tr(Res.string.ov_pgp_needed, proof.name))
        progress(tr(Res.string.ov_pgp_signing, proof.name))
        try {
            val card = model.files.openPgpSigner(choice, x509 = false)
            val fpr = card.signatureKey.fingerprint?.let { DocCryptoUtil.hex(it).uppercase() }
            if (fpr == null || model.openPgp.holder(fpr)?.fingerprint != proof.fingerprint) {
                throw ProtocolException("other_card", tr(Res.string.ov_pgp_other_card, proof.name))
            }
            val signature = card.signDetached(DeclarationEvidence.openPgpStatement(clientId, nonce)).decodeToString()
            return DeclarationEvidence.OpenPgp(proof.role, signature, model.openPgp.entry(proof.fingerprint)?.certificate)
        } finally {
            model.files.busy.value = null
        }
    }

    private suspend fun update(id: String, transform: (VerifierProfile) -> VerifierProfile) {
        if (profiles.value.none { it.id == id }) return
        persist(profiles.value.map { if (it.id == id) transform(it) else it })
    }

    private suspend fun viaServer(
        ask: OnlineAsk,
        profile: VerifierProfile?,
        signer: JwsSigner,
        verifierInfo: suspend (String, String) -> List<JsonObject>,
    ): Pair<OnlineRequest, Map<String, String>>? {
        val base = model.server.base() ?: throw ProtocolException("no_server", tr(Res.string.ov_no_server))
        val mailbox = Oid4vpMailboxClient(model.http, base, model.server.tokenFor(base))
        val session = mailbox.open()
        try {
            val request = OnlineVerifierRequests.build(signer, ask.dcql, session.requestUri, session.responseUri, verifierInfo = verifierInfo)
            mailbox.putRequest(session, request.requestObject)
            model.platform.keepScreenOn(true)
            online.value = OnlineVerifyUi.Waiting(request.invocation, tr(Res.string.ov_route_server, hostOf(base)), profile?.partyName, session.expiresAt,
                listOf(tr(Res.string.ov_detail_client, signer.clientId), tr(Res.string.ov_detail_request, session.requestUri)))
            val form = mailbox.awaitResponse(session) ?: return null
            return request to form
        } finally {
            mailbox.close(session)
        }
    }

    private suspend fun viaLan(
        ask: OnlineAsk,
        profile: VerifierProfile?,
        signer: JwsSigner,
        verifierInfo: suspend (String, String) -> List<JsonObject>,
    ): Pair<OnlineRequest, Map<String, String>>? {
        val lan = model.platform.bondsLan ?: throw ProtocolException("no_lan", tr(Res.string.ov_no_lan))
        val address = lan.localAddresses().firstOrNull() ?: throw ProtocolException("no_lan", tr(Res.string.ov_no_lan))
        val secret = PlatformCrypto.randomBytes(16).toBase64Url()
        val requestPath = OnlineVerifierRequests.LAN_REQUEST + "/" + secret
        val responsePath = OnlineVerifierRequests.LAN_RESPONSE + "/" + secret
        val listening = CompletableDeferred<String>()
        val built = CompletableDeferred<OnlineRequest>()
        val received = CompletableDeferred<ByteArray>()
        return withTimeoutOrNull(diw.wallet.core.verifier.Oid4vpMailbox.LIFETIME) {
            coroutineScope {
                val served = launch {
                    val body = lan.serve(listOf(address), responsePath, diw.wallet.core.verifier.Oid4vpMailbox.MAX_RESPONSE_BYTES,
                        onListening = { urls -> urls.firstOrNull()?.let { listening.complete(it) } },
                        get = { target ->
                            if (target != requestPath) null
                            else withTimeoutOrNull(30.seconds) { built.await() }?.let { "application/oauth-authz-req+jwt" to it.requestObject.encodeToByteArray() }
                        },
                    ) { body ->
                        val form = OnlineVerifierRequests.form(body)
                        val ok = form["response"] != null || form["error"] != null
                        (if (ok) "{}" else """{"error":"invalid_request"}""").encodeToByteArray() to ok
                    }
                    received.complete(body)
                }
                val responseUri = listening.await()
                val requestUri = responseUri.substringBefore(OnlineVerifierRequests.LAN_RESPONSE) + requestPath
                val request = OnlineVerifierRequests.build(signer, ask.dcql, requestUri, responseUri, verifierInfo = verifierInfo)
                built.complete(request)
                model.platform.keepScreenOn(true)
                online.value = OnlineVerifyUi.Waiting(request.invocation, tr(Res.string.ov_route_lan, address), profile?.partyName,
                    Clock.System.now() + diw.wallet.core.verifier.Oid4vpMailbox.LIFETIME,
                    listOf(tr(Res.string.ov_detail_client, signer.clientId), tr(Res.string.ov_detail_request, requestUri)))
                val body = received.await()
                served.join()
                request to OnlineVerifierRequests.form(body)
            }
        }
    }

    private suspend fun judge(
        ask: OnlineAsk,
        profile: VerifierProfile?,
        policy: VerificationPolicy,
        risk: RiskLevel,
        request: OnlineRequest,
        form: Map<String, String>,
    ): OnlineVerifyUi {
        if (form["error"] != null && form["response"] == null) {
            val message = tr(Res.string.ov_declined, form["error"].orEmpty())
            model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = note(ask, profile), failure = message)
            return OnlineVerifyUi.Failed(message)
        }
        val verification = model.presentationVerifier().verifyDirectPost(form, request.session)
        val credentials = verification.credentials.map { c -> OnlineCredential(c, VerificationPolicy.assurance(c), policy.evaluate(c)) }
        val result = OnlineVerifyUi.Result(ask.title, profile?.partyName, policy, verification, credentials)
        if (credentials.isEmpty()) {
            model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = note(ask, profile),
                failure = verification.errorDescription ?: verification.error ?: tr(Res.string.ov_nothing))
        }
        credentials.forEach { c ->
            model.record(
                HistoryKind.VERIFIED, tr(Res.string.reader_holder_of, c.verification.typeName), c.verification.issuerTrust,
                listOf(c.verification.issuerTrust.anchorName ?: c.verification.typeName),
                c.verification.claims.keys.toList(),
                note(ask, profile) + tr(Res.string.sep_semicolon) + (c.level?.title ?: tr(Res.string.ov_unjudged)) +
                    tr(Res.string.sep_semicolon) + StatusTexts.risk(risk),
                failure = if (result.passed) null else c.rule.detail.ifEmpty { tr(Res.string.ov_not_passed) },
            )
        }
        return result
    }

    private fun note(ask: OnlineAsk, profile: VerifierProfile?): String =
        tr(Res.string.ov_note, ask.title) + (profile?.let { tr(Res.string.ov_note_as, it.partyName) } ?: "")

    private fun hostOf(url: String): String = runCatching { io.ktor.http.Url(url).host }.getOrDefault(url)

    companion object {
        private val TABLE = StorageTableSpec(name = "DiwVerifierProfiles", supportPartitions = false, supportExpiration = false)
        private const val KEY = "profiles"
        const val PROFILE_PREFIX = "verifier:"
        /** The key of requests made without a profile: a did:key that says nothing about who verifies. */
        const val ANONYMOUS_PROFILE = "verifier"

        val LEGAL_BASES = VerifierPurpose.LEGAL_BASES
        val RETENTIONS = listOf("none", "P1D", "P30D", "P6M", "P1Y")
    }
}
