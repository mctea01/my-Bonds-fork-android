# zkPassport Statement

Version 2, effective 2026-11-06

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- **What is offered now is verifying others:** this app creates a zkPassport request, the other person answers with zero-knowledge proofs from a zkPassport compatible app, and this app verifies them on the device. Answering other people's requests with this app is not offered yet.
- Verifying connects to third parties: the zkPassport relay service, the circuit download server and a public node for the Ethereum registry contract (which you can replace with your own node in settings). They may see your IP address, the connection time and some metadata.
- You only receive the fields and condition results the other person's proofs disclose, plus an identifier that stays the same under the domain you entered; the domain in a request is entered by the requester and cannot be confirmed by the holder.
- Declining means the zkPassport service is not used; NFC reading and local verification of e-passports are not affected.

## 1. What is offered

zkPassport is a third-party zero-knowledge proof protocol and related services for electronic passports. This app currently offers the verifier side: you choose the fields the other person discloses (the document type and issuing country are always disclosed) and conditions such as age, nationality, issuing country and bound data, and this app creates a request link and QR code; the other person reads their e-passport chip with a zkPassport compatible app, which produces proofs and returns them through the relay service, and this app checks every proof and its public inputs on the device.

**Not offered yet:** answering other people's zkPassport requests with this app, cloud proving, and conditions such as FaceMatch, sanctions lists and salted unique identifiers. When features or data flows change materially, this statement is updated and you are asked to choose again.

## 2. Third-party operators and data flows

- **Relay service (`bridge.zkpassport.id`):** forwards requests and proofs between you and the other person. Messages are encrypted with keys the two sides exchange, but the encryption protocol is designed by a third party and this app cannot guarantee its strength; the service can still observe IP addresses, connection times, session identifiers and transfer sizes. So that the other person's app accepts the request, this app connects with the domain you entered as its origin.
- **Circuit downloads (`circuits2.zkpassport.id`):** the circuit manifest and verification keys for the proofs' version are downloaded and kept in a local cache; the server may record your IP address, the version and the kinds of circuits fetched, and infer from them the signature algorithm of the other person's document.
- **Public Ethereum node:** the zkPassport registry contract is queried to confirm that the certificate tree and circuit manifest used by the proofs were valid on the proof date. By default a public node service is used (`ethereum-rpc.publicnode.com`, or a Sepolia test network node in test mode), which you can replace with your own node in settings; the node operator may learn the contract, time and roots queried.
- **zkPassport online verification API (`verifier.zkpassport.id`, off by default):** only when you enable it in settings and the local Barretenberg verification fails are the whole proofs, the request conditions and the result the other person's app returned sent to that service for its decision; the result is then marked as decided by that service.

The services the other person's app connects to (such as its proving or download flows) are decided by that app and are outside this statement.

## 3. What you receive and its limits

- **Only committed values are used:** the fields and conditions shown come from the public inputs of verified proofs; the plaintext result the other person's app sends alongside is not relied on.
- **Identifier:** the proofs usually carry an unsalted identifier derived from the passport data, the domain and the purpose, which stays the same for the same domain and purpose and can recognize the same passport when it is presented again; it is not the passport number, but it is linkable information and should be handled with care.
- **Domain and requester identity:** the domain in a request is entered by the requester, and the other person's app shows it but cannot confirm it; when verifying, this app only confirms that the proofs were made for that domain, which does not mean that anyone's real identity has been confirmed.
- **Scope of trust:** verification confirms that the proofs match the certificate tree and circuits in the zkPassport registry; when the issuing country's CSCA is also among this app's trust anchors, a higher trust is shown. A zero-knowledge proof only guarantees properties under a particular circuit, and **does not mean that any identity or claim is recognized by a government**.
- **Test mode:** accepts proofs from zkPassport test passports and uses the test network registry; results are marked as tests and should not be used for real checks.
- **Service availability:** third parties may change or stop their services under their own rules; when a service or node cannot be reached, verification fails rather than skipping a check.

## 4. Unofficial compatible implementation

This app has no cooperation, certification, authorization, agency or endorsement relationship with zkPassport or its operators. The compatible features are implemented from its public and suitably licensed code, circuits and interfaces; an open-source licence does not necessarily grant permission to use third-party online services or a trademark licence. The zkPassport name is used only to identify the supported protocol or service.

## 5. After declining or withdrawing

- This app does not connect to the zkPassport relay service, circuit downloads, Ethereum nodes or the online verification service for this integration, and the zkPassport feature of the verify tab shows that it is not enabled.
- Independent e-passport NFC reading, local signature verification and document keeping are not disabled by declining this.

## 6. Consent and withdrawal

Choosing "Accept and enable" means that you understand how the third parties above handle data, and choose to use this app's zkPassport verification. You can withdraw under Settings > Legal and consent to stop further requests; data sent earlier, completed verifications or third-party records are not deleted automatically by withdrawal.
