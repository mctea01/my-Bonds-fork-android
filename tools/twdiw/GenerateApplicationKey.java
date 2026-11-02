import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Properties;

/** Build-only provisioning of a caller-owned P-256 application key. Never prints private material. */
public class GenerateApplicationKey {
    private static final String PRIVATE = "DIW_TWDIW_APP_PRIVATE_KEY";
    private static final String PUBLIC = "DIW_TWDIW_APP_PUBLIC_KEY";

    private static class SetupException extends Exception {
        SetupException(String message) { super(message); }
    }

    public static void main(String[] args) {
        try {
            if (args.length != 2) throw new SetupException("Expected source directory and local state directory");
            generate(Path.of(args[0]), Path.of(args[1]));
        } catch (SetupException error) {
            System.err.println("TWDIW application key setup failed: " + error.getMessage());
            System.exit(1);
        } catch (Exception error) {
            System.err.println("TWDIW application key setup failed: invalid key material, mismatched pair, or inaccessible local state");
            System.exit(1);
        }
    }

    private static String setting(String name) {
        String value = System.getenv(name);
        return value == null ? "" : value.trim();
    }

    private static byte[] der(String input, String label) throws SetupException {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        if (input.contains("-----")) {
            if (!input.startsWith(begin) || !input.endsWith(end)) {
                throw new SetupException("Use PKCS#8 PRIVATE KEY and SPKI PUBLIC KEY PEM, or Base64 DER");
            }
            input = input.substring(begin.length(), input.length() - end.length());
        }
        return Base64.getDecoder().decode(input.replaceAll("\\s", ""));
    }

    private static void secure(Path path) throws Exception {
        if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
    }

    private static void write(Path path, byte[] value) throws Exception {
        Files.createDirectories(path.getParent());
        if (Files.exists(path) && Arrays.equals(Files.readAllBytes(path), value)) {
            secure(path);
            return;
        }
        Path temporary = Files.createTempFile(path.getParent(), ".twdiw-", ".tmp");
        try {
            secure(temporary);
            Files.write(temporary, value);
            try {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException error) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
            secure(path);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static boolean sameCurve(ECParameterSpec actual, ECParameterSpec expected) {
        return actual.getCurve().equals(expected.getCurve()) && actual.getGenerator().equals(expected.getGenerator())
                && actual.getOrder().equals(expected.getOrder()) && actual.getCofactor() == expected.getCofactor();
    }

    private static void generate(Path output, Path stateDirectory) throws Exception {
        String privateText = setting(PRIVATE);
        String publicText = setting(PUBLIC);
        if (privateText.isEmpty() != publicText.isEmpty()) {
            throw new SetupException(PRIVATE + " and " + PUBLIC + " must be supplied together, or both left blank");
        }
        Files.createDirectories(stateDirectory);
        try (FileChannel channel = FileChannel.open(stateDirectory.resolve("key.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             var lock = channel.lock()) {
            boolean provided = !privateText.isEmpty();
            Path statePath = stateDirectory.resolve("generated-key.properties");
            Properties values = new Properties();
            if (provided) {
                values.setProperty("private", Base64.getEncoder().encodeToString(der(privateText, "PRIVATE KEY")));
                values.setProperty("public", Base64.getEncoder().encodeToString(der(publicText, "PUBLIC KEY")));
            } else if (Files.exists(statePath)) {
                secure(statePath);
                values.load(new ByteArrayInputStream(Files.readAllBytes(statePath)));
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair pair = generator.generateKeyPair();
                values.setProperty("private", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
                values.setProperty("public", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                values.store(bytes, "Local generated application key; deleted by clean; never commit or upload");
                write(statePath, bytes.toByteArray());
            }
            KeyFactory factory = KeyFactory.getInstance("EC");
            ECPrivateKey privateKey = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(values.getProperty("private"))));
            ECPublicKey publicKey = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(values.getProperty("public"))));
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
            if (!sameCurve(privateKey.getParams(), p256) || !sameCurve(publicKey.getParams(), p256)) {
                throw new SetupException("Application signing keys must use P-256 (secp256r1)");
            }
            byte[] challenge = "DIW application key-pair validation".getBytes(StandardCharsets.UTF_8);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(challenge);
            byte[] proof = signature.sign();
            signature.initVerify(publicKey);
            signature.update(challenge);
            if (!signature.verify(proof)) throw new SetupException("The supplied public and private keys do not match");
            String publicBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            String source = "package diw.wallet.app\n\n"
                    + "/** Generated from build-time application key settings; never commit. */\n"
                    + "internal object BuiltInTwdiwApplicationKey {\n"
                    + "    const val publicKeySpkiBase64 = \"" + publicBase64 + "\"\n"
                    + "    const val privateKeyPkcs8Base64 = \"" + privateBase64 + "\"\n"
                    + "    const val source = \"" + (provided ? "provided" : "generated") + "\"\n"
                    + "}\n";
            write(output.resolve("diw/wallet/app/BuiltInTwdiwApplicationKey.kt"), source.getBytes(StandardCharsets.UTF_8));
            String keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicBase64.getBytes(StandardCharsets.UTF_8)));
            System.out.println("TWDIW application key: " + (provided ? "provided" : "generated") + "; public keyId=" + keyId);
        }
    }
}
