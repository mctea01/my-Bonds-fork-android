package diw.testservers.zktls

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.SocketException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Collections
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

/**
 * Local HTTPS target for TLSNotary tests. TLSNotary alpha.15 speaks TLS 1.2 only, so the server offers TLS 1.2 with
 * ECDHE-ECDSA AES-128-GCM. Each instance makes a fresh test CA and a localhost certificate (nothing is persisted)
 * and answers every request with a synthetic body that starts with status=OK, with a Content-Length or, when
 * [chunked], in 127-byte chunks. Requests received are kept in [requests] so a test can check what was really sent.
 */
class ZkTlsTarget(
    private val bodySize: Int = 24,
    private val chunked: Boolean = false,
    /** Answers a request head with a body instead of the status=OK filler (a synthetic record page). */
    private val responder: ((String) -> ByteArray)? = null,
) : AutoCloseable {
    private val caKeys = ecKeys()
    private val leafKeys = ecKeys()
    private val ca: X509Certificate = certificate("CN=DIW zkTLS Test CA", caKeys.public, "CN=DIW zkTLS Test CA", caKeys, authority = true)
    private val leaf: X509Certificate = certificate("CN=localhost", leafKeys.public, "CN=DIW zkTLS Test CA", caKeys, authority = false)
    private val server: SSLServerSocket
    private val acceptor: Thread

    /** The test CA certificate (DER), the root a test passes to TLSNotary. */
    val caDer: ByteArray get() = ca.encoded

    /** The server certificate (DER). */
    val leafDer: ByteArray get() = leaf.encoded

    val port: Int get() = server.localPort

    /** Raw request heads received, in order. */
    val requests: MutableList<String> = Collections.synchronizedList(mutableListOf())

    init {
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("leaf", leafKeys.private, PASSWORD, arrayOf(leaf, ca))
        }
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, PASSWORD) }
        val context = SSLContext.getInstance("TLSv1.2").apply { init(keys.keyManagers, null, SecureRandom()) }
        server = (context.serverSocketFactory.createServerSocket(0, 8, InetAddress.getByName("127.0.0.1")) as SSLServerSocket).apply {
            enabledProtocols = arrayOf("TLSv1.2")
            enabledCipherSuites = arrayOf("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
        }
        acceptor = thread(name = "zktls-target", isDaemon = true) {
            while (!server.isClosed) {
                val socket = try { server.accept() as SSLSocket } catch (_: SocketException) { break }
                thread(name = "zktls-target-connection", isDaemon = true) { runCatching { serve(socket) } }
            }
        }
    }

    private fun serve(socket: SSLSocket) = socket.use { s ->
        s.soTimeout = 120_000
        val input = s.inputStream
        val head = ByteArrayOutputStream()
        while (!head.toByteArray().endsWithCrlfCrlf()) {
            val b = input.read()
            if (b < 0) return
            head.write(b)
            require(head.size() <= 4096) { "Request head too long" }
        }
        val text = head.toByteArray().decodeToString()
        requests += text
        val body = responder?.invoke(text) ?: ByteArray(bodySize) { 'x'.code.toByte() }.also { "status=OK".encodeToByteArray().copyInto(it) }
        val response = ByteArrayOutputStream()
        if (chunked) {
            response.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".encodeToByteArray())
            for (start in body.indices step 127) {
                val end = minOf(start + 127, body.size)
                response.write("${(end - start).toString(16).uppercase()}\r\n".encodeToByteArray())
                response.write(body, start, end - start)
                response.write("\r\n".encodeToByteArray())
            }
            response.write("0\r\n\r\n".encodeToByteArray())
        } else {
            val type = if (responder != null) "Content-Type: text/html; charset=utf-8\r\n" else ""
            response.write("HTTP/1.1 200 OK\r\n${type}Content-Length: ${body.size}\r\nConnection: close\r\n\r\n".encodeToByteArray())
            response.write(body)
        }
        s.outputStream.write(response.toByteArray())
        s.outputStream.flush()
    }

    override fun close() {
        server.close()
        acceptor.join(5_000)
    }

    private fun ByteArray.endsWithCrlfCrlf() =
        size >= 4 && this[size - 4] == '\r'.code.toByte() && this[size - 3] == '\n'.code.toByte() &&
            this[size - 2] == '\r'.code.toByte() && this[size - 1] == '\n'.code.toByte()

    private companion object {
        val PASSWORD = "zktls-test".toCharArray()

        fun ecKeys(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        fun certificate(subject: String, publicKey: java.security.PublicKey, issuer: String, issuerKeys: KeyPair, authority: Boolean): X509Certificate {
            val now = System.currentTimeMillis()
            val utils = JcaX509ExtensionUtils()
            val builder = JcaX509v3CertificateBuilder(
                X500Name(issuer), BigInteger(64, SecureRandom()), Date(now - 3_600_000), Date(now + 86_400_000), X500Name(subject), publicKey,
            )
                .addExtension(Extension.basicConstraints, true, BasicConstraints(authority))
                .addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey))
                .addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerKeys.public))
            if (authority) {
                builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
            } else {
                builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
                    .addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
                    .addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, "localhost")))
            }
            val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.private)
            return JcaX509CertificateConverter().getCertificate(builder.build(signer))
        }
    }
}
