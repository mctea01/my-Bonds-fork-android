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
import diw.wallet.core.verifier.declaration.DidJwsSigner
import diw.wallet.core.verifier.declaration.EvidenceQueries
import diw.wallet.core.verifier.declaration.MandateContent
import diw.wallet.core.verifier.declaration.PartyId
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

/**
 * Who this wallet says it is when it verifies (docs/design/p5-verifier.md section 3). Each profile has its own did:key
 * in the wallet's key store; the evidence is the wallet's own credentials (by document id), presented afresh for each
 * request, and the mandates other parties signed for this profile's key.
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
) {
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
}

/** What the online verification asks for: one credential query. */
data class OnlineAsk(val id: String, val title: String, val query: JsonObject) {
    val dcql: JsonObject get() = buildJsonObject { putJsonArray("credentials") { add(query) } }

    companion object {
        /** The in-person presets as mdoc queries, and the EU PID as an SD-JWT VC. */
        fun all(): List<OnlineAsk> = ReaderRequest.entries.map { r ->
            OnlineAsk(r.name, r.title, buildJsonObject {
                put("id", "q0")
                put("format", "mso_mdoc")
                put("meta", buildJsonObject { put("doctype_value", r.docType) })
                putJsonArray("claims") {
                    (mapOf(r.namespace to r.elements) + r.more).forEach { (ns, elements) ->
                        elements.forEach { e -> add(buildJsonObject { put("path", buildJsonArray { add(ns); add(e) }) }) }
                    }
                }
            })
        } + OnlineAsk("PID_SD_JWT", tr(Res.string.ov_ask_pid_sdjwt), buildJsonObject {
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

    private suspend fun signer(profileId: String?): DidJwsSigner {
        val k = key(profileId)
        val did = k.did ?: DidKeys.didKey(k.publicKey)
        return DidJwsSigner(k.signingKey(), did, DidKeys.verificationMethod(did))
    }

    /** The client_id another party names in a mandate for [p] (decentralized_identifier:did:key:...). */
    suspend fun clientId(p: VerifierProfile): String = signer(p.id).clientId

    /** Adds a mandate (compact JWS) someone signed for [p]; it must name this profile's key as the agent. */
    fun importMandate(p: VerifierProfile, jws: String) = model.scope.launch {
        val compact = jws.trim()
        val parsed = runCatching { VerifierMandate.parse(compact).content }.getOrNull()
        val own = clientId(p)
        when {
            parsed == null -> model.message.value = tr(Res.string.vp_mandate_unreadable)
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
    suspend fun issueMandate(p: VerifierProfile, agentName: String, agentRole: String?, agentClientId: String, purposes: List<String>, days: Int): String {
        val s = signer(p.id)
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
        return VerifierMandate.sign(content, s, s.clientId, now)
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

    fun start(ask: OnlineAsk, profile: VerifierProfile?, purpose: String, risk: RiskLevel, policy: VerificationPolicy, route: OnlineRoute) {
        stop()
        online.value = OnlineVerifyUi.Working(tr(Res.string.ov_preparing))
        job = model.scope.launch {
            try {
                val signer = signer(profile?.id)
                val verifierInfo: suspend (String, String) -> List<JsonObject> = { clientId, nonce ->
                    if (profile == null) emptyList() else declaration(profile, purpose, ask, clientId, nonce, signer)
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
    private suspend fun declaration(p: VerifierProfile, purpose: String, ask: OnlineAsk, clientId: String, nonce: String, signer: DidJwsSigner): List<JsonObject> {
        online.value = OnlineVerifyUi.Working(tr(Res.string.ov_evidence))
        val holder = model.holder()
        val evidence = ArrayList<DeclarationEvidence>()
        for ((role, ids) in listOf(DeclarationEvidence.ROLE_PARTY to p.partyEvidence, DeclarationEvidence.ROLE_AGENT to p.agentEvidence)) {
            for ((i, docId) in ids.withIndex()) {
                val doc = model.documentStore.lookupDocument(docId) ?: continue
                val credential = doc.getCertifiedCredentials().firstOrNull() ?: continue
                val query = EvidenceQueries.forCredential("$role$i", credential, model.documentTypes)
                    ?: throw ProtocolException("invalid_evidence", tr(Res.string.ov_evidence_unusable, doc.displayName ?: docId))
                evidence += DeclarationEvidence.Presentation(role, query, holder.evidence(clientId, nonce, query, docId))
            }
        }
        p.mandates.forEach { evidence += DeclarationEvidence.Mandate(it) }
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
            credentials = buildJsonArray { add(ask.query) },
        )
        val declared = VerifierDeclaration.entry(VerifierDeclaration.sign(content, clientId, nonce, evidence, signer))
        val registration = p.registration?.trim()?.takeIf { it.count { c -> c == '.' } == 2 }?.let { buildJsonObject { put("format", "jwt"); put("data", it) } }
        return listOfNotNull(registration, declared)
    }

    private suspend fun viaServer(
        ask: OnlineAsk,
        profile: VerifierProfile?,
        signer: DidJwsSigner,
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
        signer: DidJwsSigner,
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
