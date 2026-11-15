package diw.wallet.app.android

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import diw.wallet.app.FaceComparison
import diw.wallet.app.FaceKeyAttestation
import diw.wallet.app.FaceMatchFailure
import diw.wallet.app.FaceMatchService
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.tr
import diw.wallet.core.zkpassport.KeyAttestationInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import org.multipaz.facematch.FacePose
import org.multipaz.facenet.FaceEmbedding
import org.multipaz.facenet.FaceNetFaceMatcher
import org.multipaz.facenet.FaceNetModelConfig
import org.multipaz.facenet.FaceNetSessionBase
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.FaceMatcherLivenessPromptDialogModel
import org.multipaz.prompt.FaceMatcherPromptDialogModel
import org.multipaz.prompt.PromptDismissedException
import org.multipaz.prompt.Reason
import org.multipaz.prompt.getFaceMatcherDialogModel
import org.multipaz.prompt.getFaceMatcherLivenessDialogModel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Face comparison on Android (docs/design/zkpassport.md 5.6): Multipaz's FaceNet matcher (BlazeFace detection,
 * MobileFaceNet embeddings, MiniFASNetV2 passive liveness) behind Multipaz's camera prompt, and a fresh Android
 * Keystore key whose attestation vouches for the statement. Camera frames are compared in memory and not kept.
 */
class AndroidFaceMatch(private val context: Context, private val prompts: () -> AndroidPromptModel?) : FaceMatchService {
    override val appId: String get() = context.packageName

    override val appVersion: String by lazy {
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull() ?: "0"
    }

    /** The keystore states the app's `signatures` (the oldest certificate of a rotated signing key), so this reads the same. */
    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
    override val ownSigner: String? by lazy {
        runCatching {
            val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            info.signatures?.firstOrNull()?.toByteArray()
                ?.let { MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02x".format(b) } }
        }.getOrNull()
    }

    private val matcher: FaceNetFaceMatcher by lazy {
        FaceNetFaceMatcher(ByteString(context.assets.open(MODEL).use { it.readBytes() }), FaceNetModelConfig.MOBILE_FACENET)
    }

    override suspend fun compare(portrait: ByteArray, strict: Boolean): FaceComparison {
        val model = prompts() ?: throw FaceMatchFailure("unavailable")
        val faces = withContext(Dispatchers.Default) { runCatching { matcher }.getOrNull() }?.takeIf { it.isSupported }
            ?: throw FaceMatchFailure("unavailable")
        val photo = ByteString(portrait)
        val reference = try {
            faces.getFaceEmbedding(photo)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw FaceMatchFailure("photo")
        }
        val session = faces.createSession(photo)
        val matched = try {
            model.getFaceMatcherDialogModel().displayPrompt(
                FaceMatcherPromptDialogModel.FaceMatcherRequest(
                    session, Reason.HumanReadable(tr(Res.string.face_prompt_title), tr(Res.string.face_prompt_text), false), false,
                ),
            )
        } catch (e: PromptDismissedException) {
            throw FaceMatchFailure("cancelled")
        } finally {
            session.cancel()
        }
        val threshold = faces.config.matchThreshold
        val score = (session as? FaceNetSessionBase<*>)?.bestSimilarity ?: throw FaceMatchFailure("unavailable")
        if (!matched || score < threshold) throw FaceMatchFailure("no_match")
        if (strict) challenge(model, faces, reference)
        return FaceComparison(reference.embedding, scaled(score), scaled(threshold))
    }

    /**
     * The strict mode's active check: the holder faces the camera, then turns left and right in an order drawn here,
     * and the frontal picture taken in that session must match the document's photo as well.
     */
    private suspend fun challenge(model: AndroidPromptModel, faces: FaceNetFaceMatcher, reference: FaceEmbedding) {
        val turns = listOf(FacePose.LOOK_LEFT, FacePose.LOOK_RIGHT).shuffled()
        val session = faces.createLivenessSession(listOf(FacePose.FRONT) + turns)
        val captured = try {
            model.getFaceMatcherLivenessDialogModel().displayPrompt(
                FaceMatcherLivenessPromptDialogModel.FaceMatcherLivenessRequest(
                    session, Reason.HumanReadable(tr(Res.string.face_turn_title), tr(Res.string.face_turn_text), false), false,
                ),
            )
        } catch (e: PromptDismissedException) {
            throw FaceMatchFailure("cancelled")
        } finally {
            session.cancel()
        }
        val front = captured[FacePose.FRONT]
        if (front == null || turns.any { it !in captured }) throw FaceMatchFailure("no_match")
        val live = try {
            faces.getFaceEmbedding(front)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw FaceMatchFailure("no_match")
        }
        if (reference.calculateSimilarity(live) < faces.config.matchThreshold) throw FaceMatchFailure("no_match")
    }

    override suspend fun attest(toSign: ByteArray): FaceKeyAttestation? = withContext(Dispatchers.IO) {
        val alias = "diw.facematch." + UUID.randomUUID()
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    // The circuits do not read the challenge; it still ties the certificate to this statement.
                    .setAttestationChallenge(toSign)
                    .build(),
            )
            val pair = generator.generateKeyPair()
            val chain = store.getCertificateChain(alias)?.map { it.encoded }.orEmpty()
            // A hardware attestation ends in the manufacturer's root; a software keystore gives one self-signed certificate.
            val stated = chain.firstOrNull()?.let { KeyAttestationInfo.read(it) }
            val digest = stated?.signerDigest
            if (chain.size < 3 || stated == null || !stated.provable || digest == null || stated.packageName != appId) return@withContext null
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update(toSign)
                sign()
            }
            FaceKeyAttestation(chain, signature, digest)
        } catch (e: Exception) {
            null
        } finally {
            runCatching { store.deleteEntry(alias) }
        }
    }

    private fun scaled(score: Float): Long = Math.round(score.toDouble() * SCALE)

    private companion object {
        const val MODEL = "facenet/mobile_facenet.tflite"
        const val KEYSTORE = "AndroidKeyStore"
        const val SCALE = 100_000_000.0
    }
}
