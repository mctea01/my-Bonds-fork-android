package diw.wallet.core.storage

import kotlinx.io.bytestring.ByteString
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTable
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Instant

/** Authenticated encryption for stored values. Implementations keep the key in platform key storage. */
interface ValueCipher {
    suspend fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray
    suspend fun decrypt(ciphertext: ByteArray, aad: ByteArray): ByteArray
}

/**
 * Wraps a Multipaz [Storage] so every stored value is encrypted (documents, credentials, trust anchors,
 * software key material). Keys and partition ids stay in clear text; values are bound to their table and
 * partition through the AEAD associated data.
 * Note: Multipaz schema upgrades operate on the inner storage and would see ciphertext; a new storage file
 * is created per schema generation instead of upgrading in place.
 */
class EncryptedStorage(
    private val inner: Storage,
    private val cipher: ValueCipher,
) : Storage {
    override suspend fun getTable(spec: StorageTableSpec): StorageTable =
        EncryptedStorageTable(this, inner.getTable(spec), cipher, spec.name)

    override suspend fun purgeExpired() = inner.purgeExpired()
}

private class EncryptedStorageTable(
    override val storage: Storage,
    private val inner: StorageTable,
    private val cipher: ValueCipher,
    private val tableName: String,
) : StorageTable {
    private fun aad(partitionId: String?) = "$tableName\u0000${partitionId ?: ""}".encodeToByteArray()

    private suspend fun seal(data: ByteString, partitionId: String?) = ByteString(cipher.encrypt(data.toByteArray(), aad(partitionId)))

    private suspend fun open(data: ByteString, partitionId: String?) = ByteString(cipher.decrypt(data.toByteArray(), aad(partitionId)))

    override suspend fun get(key: String, partitionId: String?): ByteString? =
        inner.get(key, partitionId)?.let { open(it, partitionId) }

    override suspend fun insert(key: String?, data: ByteString, partitionId: String?, expiration: Instant): String =
        inner.insert(key, seal(data, partitionId), partitionId, expiration)

    override suspend fun update(key: String, data: ByteString, partitionId: String?, expiration: Instant?) =
        inner.update(key, seal(data, partitionId), partitionId, expiration)

    override suspend fun delete(key: String, partitionId: String?): Boolean = inner.delete(key, partitionId)

    override suspend fun deleteAll() = inner.deleteAll()

    override suspend fun deletePartition(partitionId: String) = inner.deletePartition(partitionId)

    override suspend fun enumerate(partitionId: String?, afterKey: String?, limit: Int): List<String> =
        inner.enumerate(partitionId, afterKey, limit)

    override suspend fun enumerateWithData(partitionId: String?, afterKey: String?, limit: Int): List<Pair<String, ByteString>> =
        inner.enumerateWithData(partitionId, afterKey, limit).map { (k, v) -> k to open(v, partitionId) }
}
