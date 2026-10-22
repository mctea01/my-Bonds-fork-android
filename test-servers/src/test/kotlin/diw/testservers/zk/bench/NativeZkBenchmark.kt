package diw.testservers.zk.bench

import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Opt-in native subprocess measurements. All fixtures are synthetic. */
class NativeZkBenchmark {
    private fun enabled() = assumeTrue(System.getProperty("diw.bench") == "true", "Use -Pbench=true")
    private fun output(): File = File(System.getProperty("diw.bench.output")).apply { mkdirs() }

    @Test
    fun noirComponents() {
        enabled()
        val circuits = System.getenv("DIW_CIRCUITS")?.let(::File)
        assumeTrue(circuits?.resolve("tools/measure.py")?.isFile == true, "Set DIW_CIRCUITS to the M3a circuits directory")
        val nargo = System.getenv("DIW_NARGO")
        val bb = System.getenv("DIW_BB")
        val crs = System.getenv("DIW_BB_CRS")
        assumeTrue(nargo != null && bb != null && crs != null, "Set DIW_NARGO, DIW_BB and DIW_BB_CRS")
        val packages = listOf("sha256_65", "sha256_130", "sha256_260", "inflate_16k", "inflate_32k", "inflate_40k")
        val fixtures = ProcessBuilder("python3", circuits!!.resolve("tools/bench_fixtures.py").path)
            .redirectErrorStream(true).redirectOutput(output().resolve("fixtures.log")).start()
        assertTrue(fixtures.waitFor(1, TimeUnit.MINUTES), "Synthetic fixture generation timed out")
        assertEquals(0, fixtures.exitValue(), "Synthetic fixture generation failed")
        val command = listOf("python3", circuits.resolve("tools/measure.py").path) + packages +
            listOf("--nargo", nargo!!, "--bb", bb!!, "--crs", crs!!)
        val log = output().resolve("noir-run.log")
        val process = ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log).start()
        try {
            assertTrue(process.waitFor(120, TimeUnit.MINUTES), "Noir benchmark exceeded its time budget")
            assertEquals(0, process.exitValue(), "Noir benchmark failed; inspect local diagnostics")
            packages.forEach { name ->
                val source = circuits.resolve("target/measurements/$name.json")
                assertTrue(source.isFile, "Missing benchmark measurement")
                source.copyTo(output().resolve("$name.json"), overwrite = true)
            }
        } finally {
            if (process.isAlive) {
                process.descendants().forEach { it.destroyForcibly() }
                process.destroyForcibly().waitFor()
            }
        }
    }

    @Test
    fun tlsNotaryDesktop() {
        enabled()
        val binary = System.getenv("DIW_TLSN_TEST_BINARY")?.let(::File)
        assumeTrue(binary?.isFile == true, "Set DIW_TLSN_TEST_BINARY to WP5's release loopback test executable")
        // A fresh child for each size/mode gives a non-cumulative native-process
        // RSS peak. Prover and verifier share that child; this is not per-role RSS.
        val script = """
            import json,os,resource,subprocess,sys,time
            start=time.monotonic()
            result=subprocess.run([sys.argv[1],'desktop_benchmark','--exact','--ignored','--nocapture'],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=600)
            if result.returncode: raise SystemExit('Native benchmark failed')
            records=[line for line in result.stdout.splitlines() if line.startswith('BENCH ')]
            if len(records)!=2: raise SystemExit('Missing benchmark measurements')
            print(json.dumps(dict(records=records,process_seconds=time.monotonic()-start,
                combined_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)))
        """.trimIndent()
        for (mode in listOf("proxy", "mpc")) for (size in listOf(1024, 16384, 204800)) {
            val file = output().resolve("tlsn-$mode-$size.json")
            val builder = ProcessBuilder("python3", "-c", script, binary!!.absolutePath)
                .redirectOutput(file).redirectError(ProcessBuilder.Redirect.INHERIT)
            builder.environment()["DIW_TLSN_BENCH_MODE"] = mode
            builder.environment()["DIW_TLSN_BENCH_BYTES"] = size.toString()
            val process = builder.start()
            try {
                assertTrue(process.waitFor(11, TimeUnit.MINUTES), "TLSNotary benchmark exceeded its time budget")
                assertEquals(0, process.exitValue(), "TLSNotary benchmark failed")
            } finally {
                if (process.isAlive) {
                    process.descendants().forEach { it.destroyForcibly() }
                    process.destroyForcibly().waitFor()
                }
            }
        }
    }
}
