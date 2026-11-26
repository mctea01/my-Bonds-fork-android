package diw.wallet.app.android

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import diw.wallet.app.FaceComparison
import diw.wallet.app.FaceKeyAttestation
import diw.wallet.app.FaceMatchFailure
import diw.wallet.app.FaceMatchService
import diw.wallet.app.FaceMatchText
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.tr
import diw.wallet.core.document.image.ImageKind
import diw.wallet.core.document.image.Jpeg2000
import diw.wallet.core.zkpassport.KeyAttestationInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import org.multipaz.facematch.CameraFrame
import org.multipaz.facematch.FaceMatcherLivenessPromptState
import org.multipaz.facematch.FaceMatcherLivenessSession
import org.multipaz.facematch.FaceMatcherPromptState
import org.multipaz.facematch.FaceMatcherSession
import org.multipaz.facematch.FacePose
import org.multipaz.facenet.FaceEmbedding
import org.multipaz.facenet.FaceNetFaceMatcher
import org.multipaz.facenet.FaceNetModelConfig
import org.multipaz.facenet.FaceNetSessionBase
import org.multipaz.facenet.NormalizationMethod
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.FaceMatcherLivenessPromptDialogModel
import org.multipaz.prompt.FaceMatcherPromptDialogModel
import org.multipaz.prompt.PromptDismissedException
import org.multipaz.prompt.Reason
import org.multipaz.prompt.getFaceMatcherDialogModel
import org.multipaz.prompt.getFaceMatcherLivenessDialogModel
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Face comparison on Android (docs/design/zkpassport.md 5.6): Multipaz FaceNet's pipeline (BlazeFace detection,
 * MobileFaceNet embeddings, MiniFASNetV2 passive liveness) in [AveragedFaceSession], which compares the mean of
 * several frames, behind Multipaz's camera prompt, and a fresh Android Keystore key whose attestation vouches for the
 * statement. Camera frames are compared in memory and not kept.
 */
class AndroidFaceMatch(
    private val context: Context,
    override val alternateModel: PlayFeatureAsset?,
    private val prompts: () -> AndroidPromptModel?,
) : FaceMatchService {
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

    private val model: ByteArray by lazy { context.assets.open(MODEL).use { it.readBytes() } }

    private val config = FaceNetModelConfig.MOBILE_FACENET.copy(matchThreshold = MATCH_THRESHOLD)

    /** Multipaz's matcher, used for the strict mode's head-turn session. */
    private val matcher: FaceNetFaceMatcher by lazy { FaceNetFaceMatcher(ByteString(model), config) }

    @Volatile private var facenet: ByteArray? = null

    override suspend fun compare(portrait: ByteArray, strict: Boolean, alternate: Boolean): FaceComparison {
        val prompt = prompts() ?: throw FaceMatchFailure("unavailable")
        val pipeline = withContext(Dispatchers.Default) {
            if (alternate) {
                val bytes = facenet ?: alternateModel?.read()?.also { facenet = it } ?: throw FaceMatchFailure("model")
                runCatching { FacePipeline(bytes, FACENET_CONFIG) }.getOrNull()
            } else {
                runCatching { FacePipeline(model, config) }.getOrNull()
            }
        } ?: throw FaceMatchFailure("unavailable")
        try {
            val photo = withContext(Dispatchers.Default) { reference(portrait) }
            val reference = withContext(Dispatchers.Default) { runCatching { pipeline.portrait(photo) }.getOrNull() }
                ?: throw FaceMatchFailure("photo")
            val session = runCatching { AveragedFaceSession(ByteString(photo), reference, pipeline) }.getOrNull()
                ?: throw FaceMatchFailure("photo")
            val matched = try {
                prompt.getFaceMatcherDialogModel().displayPrompt(
                    FaceMatcherPromptDialogModel.FaceMatcherRequest(
                        LocalizedSession(session),
                        Reason.HumanReadable(tr(Res.string.face_prompt_title), tr(Res.string.face_prompt_text), false), false,
                    ),
                )
            } catch (e: PromptDismissedException) {
                throw failure(session)
            } finally {
                session.cancel()
            }
            val threshold = pipeline.config.matchThreshold
            val score = session.bestSimilarity
            if (!matched || score < threshold) throw mismatch(score, threshold)
            if (strict) challenge(prompt, pipeline, reference)
            return FaceComparison(reference.embedding, scaled(score), scaled(threshold))
        } finally {
            pipeline.close()
        }
    }

    /**
     * The document's photo as given to the matcher. A JPEG 2000 portrait is decoded by the wallet's own decoder (the
     * one that shows the photo in the document's details) and passed on as PNG, so the face is taken from the same
     * pixels the holder sees rather than from the library's fallback decoder.
     */
    private fun reference(portrait: ByteArray): ByteArray {
        if (ImageKind.of(portrait) != ImageKind.JPEG2000) return portrait
        val pixels = Jpeg2000.decode(portrait) ?: return portrait
        val opaque = IntArray(pixels.argb.size) { i -> pixels.argb[i] or OPAQUE }
        val bitmap = Bitmap.createBitmap(opaque, pixels.width, pixels.height, Bitmap.Config.ARGB_8888)
        return try {
            ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
        } finally {
            bitmap.recycle()
        }
    }

    /**
     * Why the camera screen closed without a match. The screen closes by itself two seconds after the session failed,
     * which reaches here as a dismissal like the holder's own; the session's state tells the two apart.
     */
    private fun failure(session: FaceNetSessionBase<*>): FaceMatchFailure {
        val config = session.config
        val state = session.state.value
        if (state.status != FaceMatcherPromptState.Status.FAILED) return FaceMatchFailure("cancelled")
        if (FaceMatchText.isReferenceFailure(state.message)) return FaceMatchFailure("photo")
        return when {
            session.bestSimilarity <= 0f -> FaceMatchFailure("timeout")
            session.bestSimilarity < config.matchThreshold -> mismatch(session.bestSimilarity, config.matchThreshold)
            session.bestLivenessScore < config.passiveLivenessThreshold -> FaceMatchFailure("liveness")
            else -> FaceMatchFailure("timeout")
        }
    }

    private fun mismatch(best: Float, threshold: Float) =
        FaceMatchFailure("mismatch:" + FaceMatchText.score(best) + ":" + FaceMatchText.score(threshold))

    /**
     * The strict mode's active check: the holder faces the camera, then turns left and right in an order drawn here,
     * and the frontal picture taken in that session must match the document's photo as well.
     */
    private suspend fun challenge(prompt: AndroidPromptModel, pipeline: FacePipeline, reference: FaceEmbedding) {
        val turns = listOf(FacePose.LOOK_LEFT, FacePose.LOOK_RIGHT).shuffled()
        val session = withContext(Dispatchers.Default) { runCatching { matcher }.getOrNull() }?.takeIf { it.isSupported }
            ?.createLivenessSession(listOf(FacePose.FRONT) + turns) ?: throw FaceMatchFailure("unavailable")
        val captured = try {
            prompt.getFaceMatcherLivenessDialogModel().displayPrompt(
                FaceMatcherLivenessPromptDialogModel.FaceMatcherLivenessRequest(
                    LocalizedLivenessSession(session),
                    Reason.HumanReadable(tr(Res.string.face_turn_title), tr(Res.string.face_turn_text), false), false,
                ),
            )
        } catch (e: PromptDismissedException) {
            val state = session.state.value
            throw when {
                state.status != FaceMatcherLivenessPromptState.Status.FAILED -> FaceMatchFailure("cancelled")
                state.message?.contains("timed out") == true -> FaceMatchFailure("timeout")
                else -> FaceMatchFailure("liveness")
            }
        } finally {
            session.cancel()
        }
        val front = captured[FacePose.FRONT]
        if (front == null || turns.any { it !in captured }) throw FaceMatchFailure("liveness")
        val live = withContext(Dispatchers.Default) { runCatching { pipeline.portrait(front.toByteArray()) }.getOrNull() }
            ?: throw FaceMatchFailure("no_match")
        val similarity = reference.calculateSimilarity(live)
        val threshold = pipeline.config.matchThreshold
        if (similarity < threshold) throw mismatch(similarity, threshold)
    }

    /** [inner] with its messages in the app's language ([FaceMatchText]); everything else is the inner session's. */
    private class LocalizedSession(private val inner: FaceMatcherSession) : FaceMatcherSession(inner.referencePortrait) {
        init {
            sync()
        }

        private fun sync() {
            val s = inner.state.value
            _state.value = s.copy(message = s.message?.let { FaceMatchText.localize(it) })
        }

        override suspend fun feedFrame(frame: CameraFrame) {
            inner.feedFrame(frame)
            sync()
        }

        override fun onTouchEvent(x: Float, y: Float) {
            inner.onTouchEvent(x, y)
            sync()
        }

        override fun cancel() = inner.cancel()
    }

    private class LocalizedLivenessSession(private val inner: FaceMatcherLivenessSession) : FaceMatcherLivenessSession(inner.poses) {
        init {
            sync()
        }

        private fun sync() {
            val s = inner.state.value
            _state.value = s.copy(message = s.message?.let { FaceMatchText.localize(it) })
        }

        override suspend fun feedFrame(frame: CameraFrame) {
            inner.feedFrame(frame)
            sync()
        }

        override fun onTouchEvent(x: Float, y: Float) {
            inner.onTouchEvent(x, y)
            sync()
        }

        override fun cancel() = inner.cancel()
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

    companion object {
        private const val MODEL = "facenet/mobile_facenet.tflite"
        /**
         * Calibrated with tools/facematch-eval: 1 in 100,000 false accepts per comparison on LFW, 90% of genuine pairs
         * passing (Multipaz's 0.63 rejects 4 in 10 genuine pairs).
         */
        private const val MATCH_THRESHOLD = 0.47f
        /** The optional model's file in its feature module (features/facenet). */
        const val FACENET_ASSET = "facenet/facenet_512.tflite"
        /**
         * facenet-pytorch's VGGFace2 InceptionResnetV1 with int8 weights (tools/facematch-eval/README.md), at the same
         * 1 in 100,000 false accepts on LFW as [MATCH_THRESHOLD]; 65% of genuine pairs pass.
         */
        val FACENET_CONFIG = FaceNetModelConfig(
            imageSquareSize = 160,
            embeddingDim = 512,
            normalization = NormalizationMethod.SCALE_MINUS_ONE_TO_ONE,
            matchThreshold = 0.74f,
            passiveLivenessThreshold = 0.5f,
        )
        private const val KEYSTORE = "AndroidKeyStore"
        private const val SCALE = 100_000_000.0
        private const val OPAQUE = -0x1000000
    }
}
