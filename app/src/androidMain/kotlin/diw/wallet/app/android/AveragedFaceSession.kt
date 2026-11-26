package diw.wallet.app.android

import android.graphics.Bitmap
import kotlinx.io.bytestring.ByteString
import org.multipaz.facematch.CameraFrame
import org.multipaz.facenet.BlazeFaceDetection
import org.multipaz.facenet.FaceEmbedding
import org.multipaz.facenet.FaceNetSessionBase

/**
 * Multipaz's camera session (pose guidance, passive liveness, two matching frames in a row, timeouts) with one change:
 * the camera side of each comparison is the mean embedding of the last [WINDOW] consecutive frontal frames rather
 * than a single frame (docs/design/zkpassport.md 5.6). A single frame can pass by chance on its own, and the session
 * tries every frame for up to eight seconds; the mean smooths that noise for the holder and takes the luck away from
 * anyone else. The window starts over whenever a frame has no single frontal face.
 */
internal class AveragedFaceSession(
    referencePortrait: ByteString,
    private val reference: FaceEmbedding,
    private val pipeline: FacePipeline,
) : FaceNetSessionBase<BlazeFaceDetection>(referencePortrait, pipeline.config) {
    private val recent = ArrayDeque<FloatArray>()
    private var frameNumber = 0L
    private var lastEmbedded = -1L
    private var current: CameraFrame? = null
    private var image: Bitmap? = null
    private var owned = false

    override suspend fun initializePipeline() {
        referenceEmbedding = reference
    }

    override suspend fun detectFaces(frame: CameraFrame): List<BlazeFaceDetection> {
        frameNumber++
        val faces = picture(frame)?.let { pipeline.detect(it) }.orEmpty()
        if (faces.size != 1) recent.clear()
        return faces
    }

    override suspend fun computeCameraEmbedding(frame: CameraFrame, face: BlazeFaceDetection): FaceEmbedding? {
        val single = picture(frame)?.let { pipeline.embed(it, face) }
        if (single == null || lastEmbedded != frameNumber - 1) recent.clear()
        if (single == null) return null
        lastEmbedded = frameNumber
        recent.addLast(single.embedding)
        if (recent.size > WINDOW) recent.removeFirst()
        return if (recent.size < WINDOW) null else FacePipeline.mean(recent)
    }

    override suspend fun computeLivenessScore(frame: CameraFrame, face: BlazeFaceDetection): Float? =
        picture(frame)?.let { pipeline.liveness(it, face) }

    override fun onSessionClosed() {
        release()
        recent.clear()
    }

    /** The upright bitmap of [frame], made once per frame for detection, embedding and liveness. */
    private fun picture(frame: CameraFrame): Bitmap? {
        if (frame !== current) {
            release()
            current = frame
            image = pipeline.upright(frame)
            owned = image != null && image !== frame.platformHandle
        }
        return image
    }

    private fun release() {
        if (owned) image?.recycle()
        image = null
        current = null
        owned = false
    }

    companion object {
        const val WINDOW = 5
    }
}
