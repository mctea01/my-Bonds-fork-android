package diw.testservers.tools

import diw.wallet.core.util.DiwJson
import diw.wallet.core.zk.ZkTemplatePack
import diw.wallet.core.zktls.ZkTlsProfile
import kotlinx.serialization.json.JsonObject
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.sec.ECPrivateKey
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.File
import java.io.StringReader
import java.math.BigInteger
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64
import kotlin.system.exitProcess
import kotlin.time.Clock

/**
 * Builds the signed template pack for a release: every `*.json` under templates/zktls (one verification page profile
 * each) and templates/zkpdf (one document template each), checked, versioned by the build time and signed with the
 * P-256 key in the environment variable ZK_TEMPLATES_KEY (PEM, SEC1 or PKCS#8). The key never touches a file.
 *
 * Usage: TemplatePackTool <templates directory> <output file>
 */
object TemplatePackTool {
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size != 2) {
            System.err.println("Usage: TemplatePackTool <templates directory> <output file>")
            exitProcess(2)
        }
        val pem = System.getenv("ZK_TEMPLATES_KEY")?.takeIf { it.isNotBlank() } ?: run {
            System.err.println("ZK_TEMPLATES_KEY is not set")
            exitProcess(2)
        }
        val pack = build(File(args[0]))
        File(args[1]).writeText(sign(pack, privateKey(pem)))
        println("Template pack version ${pack.version}: ${pack.zktls.size} zkTLS pages, ${pack.zkpdf.size} zkPDF templates")
    }

    /** Reads and checks the templates; a malformed file stops the build. */
    fun build(dir: File, version: Long = Clock.System.now().epochSeconds): ZkTemplatePack {
        fun files(sub: String) = File(dir, sub).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty().sortedBy { it.name }
        fun json(f: File) = runCatching { DiwJson.parseToJsonElement(f.readText(Charsets.UTF_8)) as JsonObject }
            .getOrElse { throw IllegalArgumentException("${f.name} is not a JSON object", it) }
        val zktls = files("zktls").map { f -> runCatching { ZkTlsProfile.parse(json(f)) }.getOrElse { throw IllegalArgumentException("${f.name}: ${it.message}", it) } }
        val zkpdf = files("zkpdf").map(::json)
        val pack = ZkTemplatePack(version, kotlin.time.Instant.fromEpochSeconds(version), zktls, zkpdf)
        // The same checks a wallet applies.
        return ZkTemplatePack.read(pack.payload())
    }

    /** A compact ES256 JWS over the pack, made with JCA so any PEM form of the key works. */
    fun sign(pack: ZkTemplatePack, key: PrivateKey): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val header = """{"alg":"ES256","typ":"${ZkTemplatePack.TYP}"}"""
        val input = enc.encodeToString(header.toByteArray()) + "." + enc.encodeToString(pack.payload().toString().toByteArray())
        val der = Signature.getInstance("SHA256withECDSA").apply { initSign(key); update(input.toByteArray()) }.sign()
        val seq = ASN1Sequence.getInstance(der)
        fun fixed(i: BigInteger): ByteArray = i.toByteArray().let { b -> ByteArray(32).also { out -> b.takeLast(32).toByteArray().let { it.copyInto(out, 32 - it.size) } } }
        val raw = fixed((seq.getObjectAt(0) as ASN1Integer).value) + fixed((seq.getObjectAt(1) as ASN1Integer).value)
        return input + "." + enc.encodeToString(raw)
    }

    fun privateKey(pem: String): PrivateKey {
        val converter = JcaPEMKeyConverter()
        return when (val o = PEMParser(StringReader(pem)).readObject()) {
            is PEMKeyPair -> converter.getKeyPair(o).private
            is PrivateKeyInfo -> converter.getPrivateKey(o)
            is ECPrivateKey -> converter.getPrivateKey(PrivateKeyInfo(AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, X9ObjectIdentifiers.prime256v1), o))
            else -> throw IllegalArgumentException("ZK_TEMPLATES_KEY is not a P-256 private key")
        }
    }
}
