package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.verifier.PresentationVerifier
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

/** All test servers in one process: verifier (and later issuer, wallet provider, status lists). */
class TestServers(val baseUrl: String, val pki: TestPki) {
    val storage = EphemeralStorage()
    val trust = TrustRegistry(storage, EnvironmentPolicy(testEnvironmentEnabled = true, allowInsecureLoopbackHttp = true))
    val documentTypes = DocumentTypeRepository().apply {
        addDocumentType(DrivingLicense.getDocumentType())
        addDocumentType(EUPersonalID.getDocumentType())
    }
    val httpClient = HttpClient(Java)
    val presentationVerifier = PresentationVerifier(trust, documentTypes, CachingRevocationChecker(storage, httpClient))
    val verifier = VerifierService(baseUrl, pki, presentationVerifier)

    suspend fun init(): TestServers {
        trust.addAnchor(TrustRole.ISSUER, TrustEnvironment.TEST, pki.iacaCert, "DIW TEST IACA", official = false, source = "diw-test-servers")
        return this
    }

    fun start(port: Int, wait: Boolean): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> =
        embeddedServer(Netty, port = port, host = "0.0.0.0") {
            routing {
                get("/") { call.respondText("DIW MY WALLET test servers (TEST environment only)") }
                get("/pki/{name}") {
                    val pem = when (call.parameters["name"]) {
                        "iaca.pem" -> pki.iacaCert.toPem()
                        "verifier-root.pem" -> pki.readerRootCert.toPem()
                        "wallet-provider-root.pem" -> pki.walletProviderRootCert.toPem()
                        else -> null
                    }
                    if (pem == null) call.respondText("not found", status = io.ktor.http.HttpStatusCode.NotFound)
                    else call.respondText(pem)
                }
                verifierRoutes(verifier)
            }
        }.start(wait = wait)
}

fun main(args: Array<String>) = runBlocking {
    val port = args.getOrNull(0)?.toInt() ?: 8080
    val baseUrl = args.getOrNull(1) ?: "http://localhost:$port"
    val pkiDir = File(args.getOrNull(2) ?: "build/test-pki")
    val servers = TestServers(baseUrl, TestPki.create(pkiDir)).init()
    println("DIW test servers on $baseUrl (PKI in ${pkiDir.absolutePath})")
    servers.start(port, wait = true)
    Unit
}
