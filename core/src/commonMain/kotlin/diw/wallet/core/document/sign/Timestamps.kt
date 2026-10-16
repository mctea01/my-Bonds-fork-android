package diw.wallet.core.document.sign

import diw.wallet.core.document.DocumentInspector
import kotlinx.coroutines.CancellationException

/** Gets an RFC 3161 time-stamp token over SHA-256 of some data. */
fun interface Timestamper {
    suspend fun timestamp(data: ByteArray): ByteArray
}

/** A time-stamp authority the user can choose; [publicRoot] tells whether its root is in common trust stores. */
class TsaService(val id: String, val name: String, val url: String, val publicRoot: Boolean)

object TsaServices {
    val all = listOf(
        TsaService("digicert", "DigiCert", "http://timestamp.digicert.com", true),
        TsaService("sectigo", "Sectigo", "https://timestamp.sectigo.com", true),
        TsaService("globalsign", "GlobalSign", "http://timestamp.globalsign.com/tsa/r6advanced1", true),
        TsaService("identrust", "IdenTrust", "http://timestamp.identrust.com", true),
        TsaService("entrust", "Entrust", "http://timestamp.entrust.net/TSS/RFC3161sha2TS", true),
        TsaService("apple", "Apple", "http://timestamp.apple.com/ts01", false),
        TsaService("microsoft", "Microsoft", "http://timestamp.acs.microsoft.com", false),
        TsaService("freetsa", "FreeTSA", "https://freetsa.org/tsr", false),
    )

    fun byId(id: String?) = all.firstOrNull { it.id == id } ?: all.first()
}

/** RFC 3161 over HTTP (application/timestamp-query). */
class TsaClient(private val http: SignedDataHttp, private val url: String) : Timestamper {
    override suspend fun timestamp(data: ByteArray): ByteArray {
        val reply = try {
            http.exchange(url, DocumentInspector.timestampRequest(data), "application/timestamp-query", "application/timestamp-reply")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw SigningException("無法連線到時戳機構（$url）：" + (e.message ?: e::class.simpleName), e)
        }
        if (!reply.success) throw SigningException("時戳機構回應 HTTP ${reply.status}")
        return try {
            DocumentInspector.timestampToken(reply.body)
        } catch (e: Exception) {
            throw SigningException(e.message ?: "時戳機構的回應無法解析", e)
        }
    }
}
