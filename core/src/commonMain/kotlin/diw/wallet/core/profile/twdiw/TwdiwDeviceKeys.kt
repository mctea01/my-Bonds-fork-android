package diw.wallet.core.profile.twdiw

import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.Serializable
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec

/** Historical records from the earlier, unverified device-registration implementation. */
@Serializable
data class TwdiwDeviceKeyRecord(
    val host: String,
    val secureArea: String,
    val alias: String,
    val protection: String,
    val keyType: String = KEY_TYPE,
    val keyPrefix: String,
    val did: String,
    val keyId: String? = null,
    val status: String? = null,
    val registeredAt: Long? = null,
    val lastAttemptAt: Long? = null,
    val lastHttpStatus: Int? = null,
    val lastResponse: String? = null,
    val lastError: String? = null,
) {
    val registered: Boolean get() = keyId != null

    companion object {
        const val KEY_TYPE = "EC"
    }
}

/** Read/delete migration support only. No network calls or new registrations are performed. */
class TwdiwDeviceKeys(private val storage: Storage, private val secureAreas: SecureAreaRepository) {
    private suspend fun table() = storage.getTable(TABLE)

    suspend fun record(host: String): TwdiwDeviceKeyRecord? = table().get(host)?.let {
        runCatching { DiwJson.decodeFromString(TwdiwDeviceKeyRecord.serializer(), it.decodeToString()) }.getOrNull()
    }

    suspend fun records(): List<TwdiwDeviceKeyRecord> = table().enumerate().mapNotNull { record(it) }

    suspend fun reset(host: String) {
        record(host)?.let { record -> secureAreas.getImplementation(record.secureArea)?.deleteKey(record.alias) }
        table().delete(host)
    }

    companion object {
        private val TABLE = StorageTableSpec("DiwTwdiwDeviceKeys", supportPartitions = false, supportExpiration = false)
    }
}
