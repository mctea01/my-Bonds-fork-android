package diw.wallet.app.android

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import androidx.camera.core.ImageProxy
import org.multipaz.facematch.CameraFrame
import org.multipaz.facenet.BlazeFaceDecoder
import org.multipaz.facenet.BlazeFaceDetection
import org.multipaz.facenet.BlazeFaceModelData
import org.multipaz.facenet.FaceEmbedding
import org.multipaz.facenet.FaceNetModelConfig
import org.multipaz.facenet.MiniFasNetModelData
import org.multipaz.facenet.NormalizationMethod
import org.multipaz.facenet.computeAntiSpoofCropBox
import org.multipaz.facenet.computeFaceAlignmentTransform
import org.tensorflow.lite.Interpreter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.max
import kotlin.math.sqrt

/**
 * The face pipeline of Multipaz FaceNet 0.102.0 (`AndroidFaceDetector` and `AndroidFaceNetInterpreter`, Apache
 * License 2.0), in the wallet because those classes are internal and [AveragedFaceSession] needs each frame's
 * embedding: BlazeFace short-range on a 128x128 letterbox, the ArcFace 4-point alignment, the embedding model, and
 * MiniFASNetV2 on the face box widened 2.7 times. The models are Multipaz's own; [model] is the embedding model.
 */
internal class FacePipeline(model: ByteArray, val config: FaceNetModelConfig) : AutoCloseable {
    private val options = Interpreter.Options().apply {
        numThreads = 4
        useXNNPACK = true
    }
    private val detector = Interpreter(direct(BlazeFaceModelData.defaultModelBytes.toByteArray()), options)
    private val antiSpoof = Interpreter(direct(MiniFasNetModelData.defaultModelBytes.toByteArray()), options)
    private val embedder = Interpreter(direct(model), options)
    private val boxes = if (detector.getOutputTensor(0).shape().last() == BlazeFaceDecoder.NUM_COORDS) 0 else 1
    private val channelsFirst = embedder.getInputTensor(0).shape().let { it.size == 4 && it[1] == 3 }
    private val size = config.imageSquareSize
        ?: embedder.getInputTensor(0).shape().let { if (channelsFirst) it[2] else it[1] }
    private val dim = config.embeddingDim ?: embedder.getOutputTensor(0).shape().last()
    private val batch = embedder.getOutputTensor(0).shape().first()
    private val lock = Any()
    private var closed = false

    /** The frame turned upright, or null for an unknown frame type; it is the frame's own bitmap when no copy was needed. */
    fun upright(frame: CameraFrame): Bitmap? {
        val handle = frame.platformHandle
        val (raw, degrees) = when (handle) {
            is ImageProxy -> handle.toBitmap() to handle.imageInfo.rotationDegrees
            is Bitmap -> handle to frame.rotationDegrees
            else -> return null
        }
        val turn = ((degrees % 360) + 360) % 360
        if (turn == 0) return raw
        val turned = Bitmap.createBitmap(raw, 0, 0, raw.width, raw.height, Matrix().apply { postRotate(turn.toFloat()) }, true)
        if (raw !== handle && turned !== raw) raw.recycle()
        return turned
    }

    fun detect(image: Bitmap): List<BlazeFaceDetection> = synchronized(lock) {
        if (closed || image.width <= 0 || image.height <= 0) return emptyList()
        val n = BlazeFaceDecoder.INPUT_SIZE
        val scale = n.toFloat() / max(image.width, image.height)
        val w = (image.width * scale).toInt().coerceAtLeast(1)
        val h = (image.height * scale).toInt().coerceAtLeast(1)
        val scaled = Bitmap.createScaledBitmap(image, w, h, true)
        val input = Bitmap.createBitmap(n, n, Bitmap.Config.ARGB_8888)
        Canvas(input).apply {
            drawColor(Color.BLACK)
            drawBitmap(scaled, ((n - w) / 2).toFloat(), ((n - h) / 2).toFloat(), null)
        }
        if (scaled !== image) scaled.recycle()
        val buffer = interleaved(input, n) { (it - 127.5f) / 127.5f }
        input.recycle()
        val anchors = BlazeFaceDecoder.NUM_ANCHORS
        val coords = BlazeFaceDecoder.NUM_COORDS
        val raw = Array(1) { Array(anchors) { FloatArray(coords) } }
        val scores = Array(1) { Array(anchors) { FloatArray(1) } }
        detector.runForMultipleInputsOutputs(arrayOf(buffer), mapOf(boxes to raw, 1 - boxes to scores))
        BlazeFaceDecoder.decode(
            rawBoxes = FloatArray(anchors * coords) { raw[0][it / coords][it % coords] },
            rawScores = FloatArray(anchors) { scores[0][it][0] },
            imageWidth = image.width.toDouble(),
            imageHeight = image.height.toDouble(),
        )
    }

    fun embed(image: Bitmap, face: BlazeFaceDetection): FaceEmbedding? {
        val crop = crop(image, face)
        return try {
            embed(crop)
        } finally {
            if (crop !== image) crop.recycle()
        }
    }

    /** The embedding of the first face found in a PNG or JPEG photo. */
    fun portrait(bytes: ByteArray): FaceEmbedding? {
        val image = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null
        return try {
            detect(image).firstOrNull()?.let { embed(image, it) }
        } finally {
            image.recycle()
        }
    }

    /** MiniFASNetV2's probability that [face] is a real face rather than a photo or a screen. */
    fun liveness(image: Bitmap, face: BlazeFaceDetection): Float? = synchronized(lock) {
        if (closed || image.width <= 1 || image.height <= 1) return null
        val box = computeAntiSpoofCropBox(face.boundingBox, image.width, image.height, 2.7)
        val left = box.left.toInt().coerceIn(0, image.width - 1)
        val top = box.top.toInt().coerceIn(0, image.height - 1)
        val w = box.width.toInt().coerceIn(1, image.width - left)
        val h = box.height.toInt().coerceIn(1, image.height - top)
        val sub = Bitmap.createBitmap(image, left, top, w, h)
        val crop = Bitmap.createScaledBitmap(sub, SPOOF_SIZE, SPOOF_SIZE, true)
        val buffer = interleaved(crop, SPOOF_SIZE) { it }
        if (crop !== sub && crop !== image) crop.recycle()
        if (sub !== image) sub.recycle()
        val out = Array(1) { FloatArray(3) }
        antiSpoof.run(buffer, out)
        out[0][1].coerceIn(0f, 1f)
    }

    private fun crop(image: Bitmap, face: BlazeFaceDetection): Bitmap {
        val t = computeFaceAlignmentTransform(face.rightEye, face.leftEye, face.noseTip, face.mouthCenter, size)
        if (t != null) {
            val matrix = Matrix().apply {
                setValues(floatArrayOf(t.a.toFloat(), -t.b.toFloat(), t.tx.toFloat(), t.b.toFloat(), t.a.toFloat(), t.ty.toFloat(), 0f, 0f, 1f))
            }
            return Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
                .also { Canvas(it).drawBitmap(image, matrix, Paint(Paint.FILTER_BITMAP_FLAG)) }
        }
        val bb = face.boundingBox
        val left = (bb.left - bb.width * 0.1).toInt().coerceIn(0, image.width - 1)
        val top = (bb.top - bb.height * 0.1).toInt().coerceIn(0, image.height - 1)
        val right = (bb.right + bb.width * 0.1).toInt().coerceAtMost(image.width)
        val bottom = (bb.bottom + bb.height * 0.1).toInt().coerceAtMost(image.height)
        val sub = Bitmap.createBitmap(image, left, top, (right - left).coerceAtLeast(1), (bottom - top).coerceAtLeast(1))
        val scaled = Bitmap.createScaledBitmap(sub, size, size, true)
        if (scaled !== sub && sub !== image) sub.recycle()
        return scaled
    }

    private fun embed(face: Bitmap): FaceEmbedding? = synchronized(lock) {
        if (closed) return null
        val n = size * size
        val argb = IntArray(n).also { face.getPixels(it, 0, size, 0, 0, size, size) }
        val rgb = Array(3) { c -> FloatArray(n) { i -> ((argb[i] shr (16 - 8 * c)) and 0xFF).toFloat() } }
        val (shift, scale) = when (config.normalization) {
            NormalizationMethod.SCALE_ZERO_TO_ONE -> 0f to 1f / 255f
            NormalizationMethod.SCALE_MINUS_ONE_TO_ONE -> 127.5f to 1f / 128f
            NormalizationMethod.STANDARDIZE -> {
                val mean = rgb.sumOf { ch -> ch.sumOf { it.toDouble() } } / (3 * n)
                val variance = rgb.sumOf { ch -> ch.sumOf { (it - mean) * (it - mean) } } / (3 * n)
                mean.toFloat() to 1f / max(sqrt(variance).toFloat(), 1f / sqrt(3f * n))
            }
        }
        val buffer = ByteBuffer.allocateDirect(3 * n * Float.SIZE_BYTES).order(ByteOrder.nativeOrder())
        if (channelsFirst) {
            for (ch in rgb) for (v in ch) buffer.putFloat((v - shift) * scale)
        } else {
            for (i in 0 until n) for (ch in rgb) buffer.putFloat((ch[i] - shift) * scale)
        }
        buffer.rewind()
        val inputs = Array<Any>(embedder.inputTensorCount) { buffer.duplicate().order(ByteOrder.nativeOrder()) }
        val out = Array(batch) { FloatArray(dim) }
        embedder.runForMultipleInputsOutputs(inputs, mapOf(0 to out))
        unit(out[0])
    }

    override fun close() = synchronized(lock) {
        if (closed) return
        closed = true
        runCatching { detector.close() }
        runCatching { antiSpoof.close() }
        runCatching { embedder.close() }
        Unit
    }

    companion object {
        private const val SPOOF_SIZE = 80

        /** The unit-length mean of unit-length embeddings. */
        fun mean(embeddings: Collection<FloatArray>): FaceEmbedding {
            val sum = FloatArray(embeddings.first().size)
            for (e in embeddings) for (i in sum.indices) sum[i] += e[i]
            return unit(sum)
        }

        private fun unit(v: FloatArray): FaceEmbedding {
            val norm = sqrt(v.fold(0f) { acc, x -> acc + x * x })
            if (norm > 0f) for (i in v.indices) v[i] /= norm
            return FaceEmbedding(v)
        }

        private fun direct(bytes: ByteArray): ByteBuffer =
            ByteBuffer.allocateDirect(bytes.size).order(ByteOrder.nativeOrder()).apply {
                put(bytes)
                rewind()
            }

        /** RGB channels-last, each 0 to 255 value passed through [f]. */
        private fun interleaved(image: Bitmap, n: Int, f: (Float) -> Float): ByteBuffer {
            val argb = IntArray(n * n).also { image.getPixels(it, 0, n, 0, 0, n, n) }
            val buffer = ByteBuffer.allocateDirect(argb.size * 3 * Float.SIZE_BYTES).order(ByteOrder.nativeOrder())
            for (p in argb) {
                buffer.putFloat(f(((p shr 16) and 0xFF).toFloat()))
                buffer.putFloat(f(((p shr 8) and 0xFF).toFloat()))
                buffer.putFloat(f((p and 0xFF).toFloat()))
            }
            buffer.rewind()
            return buffer
        }
    }
}
