package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.verifier.PresentationVerifier
import diw.testservers.zktls.ZkTlsRecordPage
import diw.testservers.zktls.ZkTlsRelay
import diw.testservers.zktls.ZkTlsTarget
import diw.testservers.zktls.ZkTlsVerifierService
import diw.testservers.zktls.zkTlsRelayRoutes
import diw.testservers.zktls.zkTlsVerifierRoutes
import io.ktor.server.application.install
import io.ktor.server.websocket.WebSockets
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.revocation.CachingRevocationChecker
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.io.File

/** All test servers in one process: verifier, issuer (with status lists) and wallet provider. */
class TestServers(
    val baseUrl: String,
    val pki: TestPki,
    issuerOptions: IssuerOptions = IssuerOptions(),
    /** Checks Bonds age proofs on the server; without it the age verifier only relays. */
    ageVerifier: diw.wallet.core.zk.OpenAcAgeVerifier? = null,
    /** Whether the native library here has TLSNotary; without it zkTLS sessions are refused (the relay still works). */
    zkTls: suspend () -> Boolean = { false },
    /**
     * The DNS name of the synthetic record page and its port (0: any). A phone can prove the page only under a name
     * that resolves to this machine; TLSNotary does not connect to IP addresses.
     */
    zkTlsHost: String = "localhost",
    zkTlsPort: Int = 0,
) {
    val storage = EphemeralStorage()
    val trust = TrustRegistry(storage, EnvironmentPolicy(testEnvironmentEnabled = true, allowInsecureLoopbackHttp = true))
    val documentTypes = DocumentTypeRepository().apply {
        addDocumentType(DrivingLicense.getDocumentType())
        addDocumentType(EUPersonalID.getDocumentType())
    }
    val httpClient = HttpClient(Java)
    val longfellow = diw.wallet.core.zk.LongfellowZk(System.getProperty("os.name"))
    val presentationVerifier = PresentationVerifier(trust, documentTypes, CachingRevocationChecker(storage, httpClient), zkSystemRepository = longfellow.repository, acceptUnsecuredJwtResponse = true)
    val verifier = VerifierService(baseUrl, pki, presentationVerifier)
    val issuer = IssuerService(baseUrl, pki, trust, issuerOptions)
    val walletProvider = WalletProviderService(baseUrl, pki)
    val bondsAge = BondsAgeService(baseUrl, ageVerifier, diw.wallet.core.did.DidResolver(httpClient))

    /** The synthetic record page zkTLS sessions prove, started on first use (its own test CA). */
    val recordPage: ZkTlsTarget by lazy { ZkTlsTarget(responder = ZkTlsRecordPage::respond, host = zkTlsHost, fixedPort = zkTlsPort) }
    val zkTlsRelay = ZkTlsRelay()
    val zkTlsVerifier = ZkTlsVerifierService(baseUrl, pki, { listOf(ZkTlsRecordPage.profile(recordPage.port, recordPage.host)) }, { listOf(recordPage.caDer) }, zkTls)

    suspend fun init(): TestServers {
        trust.addAnchor(TrustRole.ISSUER, TrustEnvironment.TEST, pki.iacaCert, "DIW TEST IACA", official = false, source = "diw-test-servers")
        trust.addAnchor(TrustRole.WALLET_PROVIDER, TrustEnvironment.TEST, pki.walletProviderRootCert, "DIW TEST Wallet Provider", official = false, source = "diw-test-servers")
        return this
    }

    fun start(port: Int, wait: Boolean): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> =
        embeddedServer(Netty, port = port, host = "0.0.0.0") {
            install(WebSockets) { maxFrameSize = 1L shl 20 }
            routing {
                get("/") { call.respondText("DIW MY WALLET test servers (TEST environment only)\nVerifier test page: $baseUrl/verifier") }
                get("/pki/{name}") {
                    val pem = when (call.parameters["name"]) {
                        "iaca.pem" -> pki.iacaCert.toPem()
                        "verifier-root.pem" -> pki.readerRootCert.toPem()
                        "wallet-provider-root.pem" -> pki.walletProviderRootCert.toPem()
                        "zktls-ca.pem" -> X509Cert(ByteString(recordPage.caDer)).toPem()
                        else -> null
                    }
                    if (pem == null) call.respondText("not found", status = io.ktor.http.HttpStatusCode.NotFound)
                    else call.respondText(pem)
                }
                verifierRoutes(verifier)
                issuerRoutes(issuer)
                walletProviderRoutes(walletProvider)
                bondsAgeRoutes(bondsAge)
                zkTlsRelayRoutes(zkTlsRelay)
                zkTlsVerifierRoutes(zkTlsVerifier)
            }
        }.start(wait = wait)
}

fun main(args: Array<String>) = runBlocking {
    val port = args.getOrNull(0)?.toInt() ?: 8080
    val baseUrl = args.getOrNull(1) ?: "http://localhost:$port"
    val pkiDir = File(args.getOrNull(2) ?: "build/test-pki")
    // DIW_OPENAC_DATA holds a verified zk-assets folder (see OpenAcAgeProofTest): Bonds age proofs are then checked here.
    val zk = System.getenv("DIW_OPENAC_DATA")?.let { File(it) }?.takeIf { File(it, "zk-assets").isDirectory }?.let { data ->
        diw.wallet.core.zk.native.JvmZkEnvironment(data, HttpClient(Java)) { diw.wallet.core.zk.ZkPlatformInfo("server", 0, 0, 0, true) }
            .takeIf { it.loadNative() is diw.wallet.core.zk.ZkResult.Ok }
    }
    // zkTLS needs only the native library (no assets): DIW_ZK_DATA is where it is unpacked.
    val native = (System.getenv("DIW_ZK_DATA") ?: System.getenv("DIW_OPENAC_DATA"))?.let { File(it) }
    val tls = native?.let { diw.wallet.core.zk.native.ZkNative.load(it) as? diw.wallet.core.zk.ZkResult.Ok }
        ?.value?.backends?.contains(diw.wallet.core.zk.ZkBackend.TLSN) == true
    // DIW_ZKTLS_HOST names this machine for the record page (the base address's host when it is a name, not an IP).
    val baseHost = io.ktor.http.Url(baseUrl).host
    val zkTlsHost = System.getenv("DIW_ZKTLS_HOST")?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        ?: baseHost.takeIf { h -> h.any { it.isLetter() } && ':' !in h } ?: "localhost"
    val zkTlsPort = System.getenv("DIW_ZKTLS_PORT")?.toIntOrNull() ?: 0
    val servers = TestServers(baseUrl, TestPki.create(pkiDir), ageVerifier = zk?.ageVerifier, zkTls = { tls }, zkTlsHost = zkTlsHost, zkTlsPort = zkTlsPort).init()
    println("DIW test servers on $baseUrl (PKI in ${pkiDir.absolutePath}); Bonds age proofs ${if (zk != null) "verified here" else "relayed only"}; " +
        "zkTLS ${if (tls) "verified here" else "relay only"} (record page https://$zkTlsHost)")
    servers.start(port, wait = true)
    Unit
}
