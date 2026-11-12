package diw.testservers

import diw.wallet.core.document.image.Jbig2
import java.io.File
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Decodes a local JBIG2 corpus (DIW_JBIG2_DIR with streams/NAME.jb2, optional NAME.glob, and ref/NAME-000.png
 * decoded by another implementation) and compares every pixel. Skipped without the variable.
 */
class Jbig2CorpusTest {
    @Test
    fun matchesReferenceDecoder() {
        val dir = System.getenv("DIW_JBIG2_DIR")?.let { File(it) } ?: return
        val failures = ArrayList<String>()
        var checked = 0
        for (f in dir.resolve("streams").listFiles().orEmpty().filter { it.extension == "jb2" }.sortedBy { it.name }) {
            val ref = dir.resolve("ref/${f.nameWithoutExtension}-000.png").takeIf { it.exists() } ?: continue
            val globals = File(f.path.removeSuffix(".jb2") + ".glob").takeIf { it.exists() }?.readBytes()
            checked++
            val result = runCatching { Jbig2.decode(f.readBytes(), globals) }
            val bmp = result.getOrElse { failures.add("${f.name}: ${it.message}"); continue }
            System.getenv("DIW_JBIG2_OUT")?.let { o ->
                val out = java.awt.image.BufferedImage(bmp.width, bmp.height, java.awt.image.BufferedImage.TYPE_BYTE_GRAY)
                for (y in 0 until bmp.height) for (x in 0 until bmp.width) out.setRGB(x, y, if (bmp[x, y] != 0) 0 else 0xFFFFFF)
                File(o).mkdirs()
                ImageIO.write(out, "png", File(o, f.nameWithoutExtension + ".png"))
            }
            val img = ImageIO.read(ref)
            if (img.width != bmp.width || img.height != bmp.height) {
                failures.add("${f.name}: size ${bmp.width}x${bmp.height} expected ${img.width}x${img.height}"); continue
            }
            var diff = 0
            for (y in 0 until img.height) for (x in 0 until img.width) {
                val rgb = img.getRGB(x, y)
                val black = ((rgb shr 16 and 0xFF) + (rgb shr 8 and 0xFF) + (rgb and 0xFF)) < 384
                if (black != (bmp[x, y] != 0)) diff++
            }
            if (diff > 0) {
                // Most corpus files encode one test image in different ways: compare with its plain encoding too.
                val canon = dir.resolve("ref/bitmap-mmr-000.png").takeIf { it.exists() }?.let { ImageIO.read(it) }
                var canonDiff = -1
                if (canon != null && canon.width == bmp.width && canon.height == bmp.height) {
                    canonDiff = 0
                    for (y in 0 until canon.height) for (x in 0 until canon.width) {
                        val rgb = canon.getRGB(x, y)
                        val black = ((rgb shr 16 and 0xFF) + (rgb shr 8 and 0xFF) + (rgb and 0xFF)) < 384
                        if (black != (bmp[x, y] != 0)) canonDiff++
                    }
                }
                var refCanon = -1
                if (canon != null && canon.width == img.width && canon.height == img.height) {
                    refCanon = 0
                    for (y in 0 until canon.height) for (x in 0 until canon.width) if ((canon.getRGB(x, y) and 0xFFFFFF) != (img.getRGB(x, y) and 0xFFFFFF)) refCanon++
                }
                failures.add("${f.name}: $diff pixels differ (ours vs plain image: $canonDiff, reference vs plain image: $refCanon)")
            }
        }
        println("JBIG2 corpus: $checked checked, ${failures.size} failed")
        failures.forEach { println("  $it") }
        assertTrue(failures.isEmpty(), failures.joinToString("\n"))
    }
}
