package diw.wallet.core.zk

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.*
import org.multipaz.cbor.DataItem
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.zkp.*
import org.multipaz.mdoc.zkp.longfellow.LongfellowZkSystem
import org.multipaz.request.RequestedClaim
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** Loads the Longfellow native library; the reason it cannot be used here, or null. */
internal expect object LongfellowNative {
    fun unavailableReason(): String?
}

/**
 * Longfellow registration shared by the holder, proximity reader and verifier. [nativeCheck] loads the native
 * library once: multipaz-longfellow ships it only for some platforms, and a failed load is an Error that would
 * otherwise escape every proof operation.
 */
class LongfellowZk(platformName: String, nativeCheck: () -> String? = LongfellowNative::unavailableReason) {
    val unavailableReason: String? by lazy {
        if (platformName.startsWith("Windows", ignoreCase = true)) "Windows 尚無 Longfellow 原生函式庫" else nativeCheck()
    }
    val repository: ZkSystemRepository? by lazy {
        if (unavailableReason != null) null else ZkSystemRepository().apply { add(CheckedSystem()) }
    }

    fun specs(attributeCount: Int): List<ZkSystemSpec> = repository?.getAllZkSystemSpecs()
        ?.filter { it.getParam<Long>("num_attributes") == attributeCount.toLong() }.orEmpty()

    /** DCQL's ZK format requires a proof; it never silently requests ordinary mdoc instead. */
    fun ageOver18Query(): JsonObject {
        val specs = specs(1)
        check(specs.isNotEmpty()) { "Longfellow is unavailable" }
        return buildJsonObject {
            putJsonArray("credentials") {
                addJsonObject {
                    put("id", "age"); put("format", "mso_mdoc_zk")
                    putJsonObject("meta") {
                        put("doctype_value", "org.iso.18013.5.1.mDL")
                        putJsonArray("zk_system_type") {
                            specs.forEach { spec -> addJsonObject {
                                put("id", spec.id); put("system", spec.system)
                                spec.params.forEach { (key, value) -> put(key, value.toJson()) }
                            } }
                        }
                    }
                    putJsonArray("claims") { addJsonObject {
                        putJsonArray("path") { add("org.iso.18013.5.1"); add("age_over_18") }
                    } }
                }
            }
        }
    }

    /** Verifies against exactly the circuits offered in this session. */
    fun verify(document: ZkDocument, offered: List<ZkSystemSpec>, transcript: DataItem) = privateOperation {
        val spec = offered.single { it.id == document.documentData.zkSystemSpecId }
        val system = repository?.lookup(spec.system) ?: error("Unavailable system")
        system.verifyProof(document, spec, transcript)
    }

    private class CheckedSystem : ZkSystem {
        private val delegate = LongfellowZkSystem().apply { addDefaultCircuits() }
        override val name get() = delegate.name
        override val systemSpecs get() = delegate.systemSpecs.map(::copySpec)

        private fun known(spec: ZkSystemSpec): Boolean = spec.system == name &&
            delegate.systemSpecs.any { it.id == spec.id && it.params == spec.params }

        override fun getMatchingSystemSpec(zkSystemSpecs: List<ZkSystemSpec>, requestedClaims: List<RequestedClaim>): ZkSystemSpec? =
            zkSystemSpecs.filter { known(it) && it.getParam<Long>("num_attributes") == requestedClaims.size.toLong() }
                .maxByOrNull { it.getParam<Long>("version") ?: 0 }?.let(::copySpec)

        override fun generateProof(zkSystemSpec: ZkSystemSpec, document: MdocDocument, sessionTranscript: DataItem, timestamp: Instant): ZkDocument = privateOperation {
            require(known(zkSystemSpec))
            val proof = delegate.generateProof(zkSystemSpec, document, sessionTranscript, timestamp)
            verifyProof(proof, zkSystemSpec, sessionTranscript)
            proof
        }

        override fun verifyProof(zkDocument: ZkDocument, zkSystemSpec: ZkSystemSpec, sessionTranscript: DataItem) = privateOperation {
            require(known(zkSystemSpec) && zkDocument.documentData.zkSystemSpecId == zkSystemSpec.id)
            require(zkDocument.documentData.deviceSigned.isEmpty())
            // The proof establishes validity at its timestamp, which must also be fresh now.
            require((Clock.System.now() - zkDocument.documentData.timestamp).absoluteValue <= 5.minutes)
            delegate.verifyProof(zkDocument, zkSystemSpec, sessionTranscript)
        }
    }

    class ProofException(cause: Throwable? = null) :
        IllegalArgumentException("Longfellow proof operation failed" + (cause?.message?.let { ": $it" } ?: ""), cause)

    companion object {
        private fun copySpec(spec: ZkSystemSpec) = ZkSystemSpec(spec.id, spec.system).also { copy ->
            spec.params.forEach { (name, value) -> copy.addParam(name, value.toDataItem()) }
        }

        private inline fun <T> privateOperation(block: () -> T): T = try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw ProofException(e)
        }
    }
}
