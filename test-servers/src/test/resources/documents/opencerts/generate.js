// Generates the fictional OpenAttestation fixtures of OpenCertsTest:
// npm install @govtechsg/open-attestation@6.9.7 ethers@5 in <dir>, then node generate.js <dir> <out dir>.
const path = require('path');
// schemata.openattestation.com may be unreachable; skip the JSON-LD context check of version 3 wrapping.
require(path.join(process.argv[2], 'node_modules/@govtechsg/open-attestation/dist/cjs/3.0/validate/validate')).validateW3C = async () => {};
const oa = require(path.join(process.argv[2], 'node_modules/@govtechsg/open-attestation'));
const { Wallet } = require(path.join(process.argv[2], 'node_modules/ethers'));
const fs = require('fs');
const out = process.argv[3];
const png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const base = (name, extra) => Object.assign({
  $template: { name: 'GOVTECH_DEMO', type: 'EMBEDDED_RENDERER', url: 'https://demo-renderer.opencerts.io' },
  id: 'TEST-CERT-' + name, name: 'Bachelor of Testing', issuedOn: '2026-06-30T00:00:00+08:00', admissionDate: '2022-09-01',
  graduationDate: '2026-06-30',
  issuers: [{ name: 'Test University', url: 'https://test.example', documentStore: '0x1111111111111111111111111111111111111111',
    identityProof: { type: 'DNS-TXT', location: 'certs.test.example' } }],
  recipient: { name: 'Test Person', studentId: 'S0001', email: 'test@example.com' },
  transcript: [{ name: 'Testing 101', grade: 'A', courseCredit: '4', courseCode: 'T101', examinationDate: '2023-01-15', semester: '1' },
               { name: 'Testing 102', grade: 'B+', courseCredit: '3', courseCode: 'T102', examinationDate: '2023-06-15', semester: '2' }],
  additionalData: { certSignatories: [{ name: 'Test Dean', position: 'Dean', organisation: 'Test University', signature: png }], merit: 'Honours', images: { logo: png } },
  attachments: [{ filename: 'note.txt', type: 'text/plain', data: Buffer.from('test attachment').toString('base64') }],
}, extra || {});
const [a, b] = oa.wrapDocuments([base('A'), base('B')]);
fs.writeFileSync(out + '/oa-v2-store.json', JSON.stringify(a, null, 2));
fs.writeFileSync(out + '/oa-v2-store-obfuscated.json', JSON.stringify(oa.obfuscateDocument(b, ['recipient.email', 'transcript.1.grade']), null, 2));
const tampered = JSON.parse(JSON.stringify(a));
tampered.data.recipient.name = tampered.data.recipient.name.replace('Test Person', 'Other Person');
fs.writeFileSync(out + '/oa-v2-tampered.json', JSON.stringify(tampered, null, 2));
(async () => {
  const w = new Wallet('0x' + '11'.repeat(32));
  const did = 'did:ethr:' + w.address;
  const didDoc = oa.wrapDocument({
    id: 'TEST-DID-1', name: 'DID Signed Testing Certificate', issuedOn: '2026-06-30',
    issuers: [{ id: did, name: 'Test DID Issuer', revocation: { type: 'NONE' }, identityProof: { type: 'DNS-DID', location: 'did.test.example', key: did + '#controller' } }],
    recipient: { name: 'Test Person' },
  });
  const signed = await oa.signDocument(didDoc, oa.SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018, { public: did + '#controller', private: '0x' + '11'.repeat(32) });
  fs.writeFileSync(out + '/oa-v2-did.json', JSON.stringify(signed, null, 2));
  const v3doc = (n) => ({
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://schemata.openattestation.com/com/openattestation/1.0/OpenAttestation.v3.json'],
    type: ['VerifiableCredential', 'OpenAttestationCredential'],
    issuanceDate: '2026-06-30T00:00:00Z', name: 'Version Three Testing Certificate ' + n,
    openAttestationMetadata: { template: { name: 'GOVTECH_DEMO', type: 'EMBEDDED_RENDERER', url: 'https://demo-renderer.opencerts.io' },
      proof: { type: 'OpenAttestationProofMethod', method: 'DOCUMENT_STORE', value: '0x2222222222222222222222222222222222222222' },
      identityProof: { type: 'DNS-TXT', identifier: 'v3.test.example' } },
    credentialSubject: { id: 'urn:test:subject', name: 'Test Person', courses: [{ code: 'T101', score: 90 }, { code: 'T102', score: 85.5 }], graduated: true },
    issuer: { id: 'https://test.example', name: 'Test University V3', type: 'OpenAttestationIssuer' },
  });
  const [v3] = await oa.__unsafe__use__it__at__your__own__risks__wrapDocuments([v3doc('A'), v3doc('B')], { version: 'https://schema.openattestation.com/3.0/schema.json' });
  fs.writeFileSync(out + '/oa-v3-store.json', JSON.stringify(v3, null, 2));
  console.log('A', a.signature.merkleRoot, a.signature.targetHash, a.signature.proof);
  console.log('DID', did, signed.signature.merkleRoot, signed.proof[0].signature);
  console.log('V3', v3.proof.merkleRoot);
})().catch(e => { console.error(e); process.exit(1); });
