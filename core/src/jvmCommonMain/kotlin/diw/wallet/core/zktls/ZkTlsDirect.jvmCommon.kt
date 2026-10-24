package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

actual object ZkTlsDirect {
    private const val TIMEOUT_MS = 30_000

    actual suspend fun fetch(profile: ZkTlsProfile, request: ByteArray, extraRoots: List<ByteArray>): ZkTlsFetched = withContext(Dispatchers.IO) {
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trust(extraRoots)), null) }
        val socket = try {
            context.socketFactory.createSocket(profile.host, profile.port) as SSLSocket
        } catch (e: Exception) {
            throw ProtocolException("unavailable", "無法連到 ${profile.host}：${e.message}", e)
        }
        socket.use { s ->
            s.soTimeout = TIMEOUT_MS
            s.sslParameters = s.sslParameters.apply {
                serverNames = listOf(SNIHostName(profile.host))
                endpointIdentificationAlgorithm = "HTTPS"
            }
            try {
                s.startHandshake()
            } catch (e: Exception) {
                throw ProtocolException("untrusted_server", "${profile.host} 的 TLS 連線無法建立或憑證不受信任：${e.message}", e)
            }
            val session = s.session
            val chain = session.peerCertificates.map { it.encoded }
            s.outputStream.apply { write(request); flush() }
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(16384)
            val cap = profile.limits.maxRecv + 1
            while (out.size() <= cap) {
                val n = s.inputStream.read(buffer)
                if (n < 0) break
                out.write(buffer, 0, n)
            }
            ZkTlsFetched(out.toByteArray(), chain, session.cipherSuite, session.protocol, System.currentTimeMillis() / 1000)
        }
    }

    /** The platform's trust manager, and when that refuses a chain, one that trusts only [extraRoots]. */
    private fun trust(extraRoots: List<ByteArray>): X509TrustManager {
        fun manager(store: KeyStore?): X509TrustManager =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
                .trustManagers.filterIsInstance<X509TrustManager>().first()
        val system = manager(null)
        if (extraRoots.isEmpty()) return system
        val factory = CertificateFactory.getInstance("X.509")
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            extraRoots.forEachIndexed { i, der -> setCertificateEntry("extra$i", factory.generateCertificate(der.inputStream())) }
        }
        val extra = manager(store)
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) = system.checkClientTrusted(chain, authType)
            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
                try {
                    system.checkServerTrusted(chain, authType)
                } catch (e: CertificateException) {
                    extra.checkServerTrusted(chain, authType)
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers + extra.acceptedIssuers
        }
    }
}
