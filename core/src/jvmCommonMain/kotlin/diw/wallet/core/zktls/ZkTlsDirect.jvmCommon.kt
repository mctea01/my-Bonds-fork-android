package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

actual object ZkTlsDirect {
    private const val TIMEOUT_MS = 30_000

    actual suspend fun fetch(profile: ZkTlsProfile, request: ByteArray, extraRoots: List<ByteArray>): ZkTlsFetched = withContext(Dispatchers.IO) {
        connect(profile, extraRoots).use { s ->
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

    /**
     * A completed handshake with the platform's roots, or when those refuse the site, with only [extraRoots].
     * Both use the platform's own trust managers with HTTPS host name checks; nothing is sent before the handshake.
     */
    private fun connect(profile: ZkTlsProfile, extraRoots: List<ByteArray>): SSLSocket {
        val stores = listOf<KeyStore?>(null) + if (extraRoots.isEmpty()) emptyList() else listOf(store(extraRoots))
        var refused: Exception? = null
        for (store in stores) {
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            val context = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
            val socket = try {
                context.socketFactory.createSocket(profile.host, profile.port) as SSLSocket
            } catch (e: Exception) {
                throw ProtocolException("unavailable", "無法連到 ${profile.host}：${e.message}", e)
            }
            try {
                socket.soTimeout = TIMEOUT_MS
                socket.sslParameters = socket.sslParameters.apply {
                    serverNames = listOf(SNIHostName(profile.host))
                    endpointIdentificationAlgorithm = "HTTPS"
                }
                socket.startHandshake()
                return socket
            } catch (e: Exception) {
                socket.close()
                refused = e
            }
        }
        throw ProtocolException("untrusted_server", "${profile.host} 的 TLS 連線無法建立或憑證不受信任：${refused?.message}", refused)
    }

    private fun store(roots: List<ByteArray>): KeyStore {
        val factory = CertificateFactory.getInstance("X.509")
        return KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            roots.forEachIndexed { i, der -> setCertificateEntry("extra$i", factory.generateCertificate(der.inputStream())) }
        }
    }
}
