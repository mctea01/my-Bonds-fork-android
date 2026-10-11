package dsscheck;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.util.List;

/**
 * Validates the wallet's signed samples with EU DSS and prints the ETSI indications and integrity checks.
 * Usage: DIW_SIGNED_OUT=dir ./gradlew :test-servers:test --tests '*DocumentSigningTest', then
 * ./gradlew -p tools/dss-check run --args=dir
 */
public class Main {
    public static void main(String[] args) throws Exception {
        File dir = new File(args[0]);
        // The default ETSI policy, except that missing revocation data only warns: the test PKI has no CRL or OCSP.
        String xml = new String(Main.class.getResourceAsStream("/policy/constraint.xml").readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
            .replace("<RevocationDataAvailable Level=\"FAIL\" />", "<RevocationDataAvailable Level=\"WARN\" />")
            .replace("<AcceptableRevocationDataFound Level=\"FAIL\" />", "<AcceptableRevocationDataFound Level=\"WARN\" />");
        byte[] policy = xml.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        CertificateToken root = DSSUtils.loadCertificate(new File(dir, "root.cer"));
        trusted.addCertificate(root);
        String[] files = {"pades-rsa.pdf", "pades-twice.pdf", "pades-xrefstream.pdf", "detached.p7s", "enveloping.p7m", "container.asice", "xades-rsa.xml", "xades-ec.xml", "letter.di"};
        for (String name : files) {
            if (!new File(dir, name).exists()) continue;
            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            verifier.setTrustedCertSources(trusted);
            verifier.setAIASource(null);
            verifier.setCrlSource(null);
            verifier.setOcspSource(null);
            SignedDocumentValidator validator;
            try {
                validator = SignedDocumentValidator.fromDocument(new FileDocument(new File(dir, name)));
            } catch (Exception e) {
                System.out.println("RESULT " + name + " | DSS cannot read: " + e.getMessage());
                continue;
            }
            validator.setCertificateVerifier(verifier);
            if (name.endsWith(".p7s")) validator.setDetachedContents(List.<DSSDocument>of(new FileDocument(new File(dir, "detached.bin"))));
            Reports reports;
            try {
                reports = validator.validateDocument(new java.io.ByteArrayInputStream(policy));
            } catch (Exception e) {
                System.out.println("RESULT " + name + " | DSS cannot read: " + e.getMessage());
                continue;
            }
            SimpleReport simple = reports.getSimpleReport();
            DiagnosticData diag = reports.getDiagnosticData();
            for (SignatureWrapper sig : diag.getSignatures()) {
                StringBuilder ts = new StringBuilder();
                for (TimestampWrapper t : sig.getTimestampList()) ts.append(t.getType()).append(" intact=").append(t.isSignatureIntact() && t.isMessageImprintDataIntact()).append(' ');
                System.out.println("RESULT " + name + " | " + sig.getSignatureFormat() + " | indication=" + simple.getIndication(sig.getId())
                    + (simple.getSubIndication(sig.getId()) != null ? "/" + simple.getSubIndication(sig.getId()) : "")
                    + " | signatureIntact=" + sig.isSignatureIntact() + " dataIntact=" + sig.isSignatureValid()
                    + " | chainTrusted=" + sig.isTrustedChain()
                    + " | timestamps=" + ts.toString().trim()
                    + " | errors=" + simple.getAdESValidationErrors(sig.getId()).stream().map(x -> x.getValue()).toList());
            }
            for (TimestampWrapper t : diag.getTimestampList()) {
                if (t.getType().isDocumentTimestamp()) System.out.println("RESULT " + name + " | document timestamp intact=" + t.isSignatureIntact());
            }
        }
    }
}
