# zkPassport Statement

Version 4, effective 2026-11-12

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- **This app offers two uses:** verifying others, where this app creates a zkPassport request, the other person answers with zero-knowledge proofs from a zkPassport compatible app, and this app verifies them on the device; and answering requests, where you open someone else's zkPassport request with this app, choose a stored e-passport, and this app makes the proofs on the device (or, if you choose, has your own prover make them) and returns them to the requester.
- Both uses connect to third parties: the zkPassport relay service, the circuit and certificate package download servers and a public node for the Ethereum registry contract (which you can replace with your own node in settings). They may see your IP address, the connection time and some metadata.
- When you answer a request, the requester only receives what the consent screen lists; but the domain, service name and purpose in a request are entered by the requester, and this app cannot confirm the requester's real identity.
- Declining means the zkPassport service is not used; NFC reading and local verification of e-passports are not affected.

## 1. What is offered

zkPassport is a third-party zero-knowledge proof protocol and related services for electronic passports.

**Verifying others:** you choose the fields the other person discloses (the document type and issuing country are always disclosed) and conditions such as age, nationality, issuing country and bound data, and this app creates a request link and QR code; the other person reads their e-passport chip with a zkPassport compatible app, which produces proofs and returns them through the relay service, and this app checks every proof and its public inputs on the device. When the server of this app you have set up offers an OPRF key, this app also accepts salted identifiers made with that key; salted identifiers made with other keys are not accepted.

**Answering requests:** after you scan or open a zkPassport request link with this app, this app first connects to the relay service to learn the requester's origin, then shows a consent screen: the domain, service name and purpose the requester states, what the proofs would establish, and the stored e-passports you can use. When you agree, this app makes the proofs on the device from the chip data of that passport read earlier and kept on the device (the SOD, DG1 and, when kept, the DG2 photo hash), and sends them to the requester through the relay service; when you decline, the requester is only told that you declined. When the origin the relay service reports differs from the domain the request names, this app warns that the link may have been passed on by another site and sends only after you confirm again.

**Handing off to your own prover:** when the device cannot make the proofs or you prefer not to, you can choose on the consent screen to have your own prover make them: a proving service you set up yourself and reach with a dedicated token, or a temporary prover started with `diw-server prover` on a computer in the same local network and paired with a one-time pairing code. This app then sends the SOD and DG1 of that passport (all the machine-readable zone data, such as name, passport number, date of birth and expiry) with the request to that prover, without the DG2 photo; the proofs come back to this app and are still sent to the requester through the relay service.

**Not offered yet:** cloud proving (modes that need zkPassport's servers to make the proofs) and FaceMatch face matching; answers also do not use salted identifiers. Requests that ask for these can only be declined. When features or data flows change materially, this statement is updated and you are asked to choose again.

## 2. Third-party operators and data flows

- **Relay service (`bridge.zkpassport.id`):** forwards requests and proofs between you and the other person. Messages are encrypted with keys the two sides exchange, but the encryption protocol is designed by a third party and this app cannot guarantee its strength; the service can still observe IP addresses, connection times, session identifiers and transfer sizes. When verifying others, so that the other person's app accepts the request, this app connects with the domain you entered as its origin; when answering requests, this app compares against the requester's origin the relay service reports.
- **Circuit downloads (`circuits2.zkpassport.id`):** the circuit manifest, verification keys and the circuits needed to make proofs are downloaded and kept in a local cache; the server may record your IP address, the version and the kinds of circuits fetched, and infer from them the signature algorithm of the document. When answering requests, what can be inferred is the signature algorithm of your own passport, and possibly the range of issuing countries.
- **Certificate package downloads (`certificates.zkpassport.id`):** the list of CSCA public keys for a certificate tree root is downloaded, its root recomputed on this device before use, and kept in a local cache; the server may record your IP address and the root fetched. When verifying others it is used to compare the issuing country's CSCA with this app's trust anchors; when answering requests it is used on this device to find the CSCA of your passport, the whole list is downloaded and none of your passport data is sent.
- **Public Ethereum node:** the zkPassport registry contract is queried to confirm that the certificate tree and circuit manifest were valid on the proof date. By default a public node service is used (`ethereum-rpc.publicnode.com`, or a Sepolia test network node in test mode), which you can replace with your own node in settings; the node operator may learn the contract, time and roots queried.
- **zkPassport online verification API (`verifier.zkpassport.id`, off by default, only for verifying others):** only when you enable it in settings and the local Barretenberg verification fails are the whole proofs, the request conditions and the result the other person's app returned sent to that service for its decision; the result is then marked as decided by that service.
- **This app's server:** when verifying others, this app reads the public OPRF key information (`/info`) of the server you have set up, without sending any proof content. You set up the server yourself; it is not operated by zkPassport.
- **Your own prover (used only when you choose it):** you run it yourself; it is not operated by zkPassport or the developer of this app. This project's prover program handles passport data in memory only, deletes a result once it is read and deletes unread jobs after 10 minutes; the temporary prover accepts local network connections only, encrypts traffic with a TLS certificate made for that run and carried in the pairing code, and clears its pairings and data when closed. Modified programs or other people's computers cannot be guaranteed to do the same, so use only your own computer. The prover itself connects to Ethereum nodes and the circuit and certificate package download servers.

The services the other person's app connects to (such as its proving or download flows) are decided by that app and are outside this statement. When you answer a request, how the requester keeps, uses or passes on the proofs is decided by the requester and is outside this statement.

## 3. What you receive when verifying others and its limits

- **Only committed values are used:** the fields and conditions shown come from the public inputs of verified proofs; the plaintext result the other person's app sends alongside is not relied on.
- **Identifier:** the proofs usually carry an identifier derived from the passport data, the domain and the purpose, which stays the same for the same domain and purpose and can recognize the same passport when it is presented again; it is not the passport number, but it is linkable information and should be handled with care. Salted identifiers are accepted only with the OPRF key of this app's server.
- **Domain and requester identity:** the domain in a request is entered by the requester, and the other person's app shows it but cannot confirm it; when verifying, this app only confirms that the proofs were made for that domain, which does not mean that anyone's real identity has been confirmed.
- **Scope of trust:** verification confirms that the proofs match the certificate tree and circuits in the zkPassport registry; when the issuing country's CSCA is also among this app's trust anchors, a higher trust is shown. A zero-knowledge proof only guarantees properties under a particular circuit, and **does not mean that any identity or claim is recognized by a government**.
- **Test mode:** accepts proofs from zkPassport test passports and uses the test network registry; results are marked as tests and should not be used for real checks.
- **Service availability:** third parties may change or stop their services under their own rules; when a service or node cannot be reached, verification fails rather than skipping a check.

## 4. What you provide when answering requests and its limits

- **What is sent:** the requester receives the proofs and their public inputs: the disclosed fields the consent screen lists, whether each condition holds (for example that you are at least a certain age, not your date of birth), bound data, and an identifier that stays the same for the requester's domain and purpose. A requester with the same domain and purpose can use the identifier to recognize the same passport presented again; identifiers differ between domains.
- **What is not sent:** the raw chip data, fields that are not listed and the passport photo itself are not sent to the requester; when the proofs are made on this device, making them does not send passport data to any server; when you choose your own prover, the SOD and DG1 go only to the prover you chose.
- **The requester's identity cannot be confirmed:** the domain, service name, purpose and logo are entered by the requester; the origin the relay service reports only shows which site the link was opened from, and does not mean that the requester's real identity or purpose has been confirmed. Answer only requests you trust.
- **Unsupported passports:** the signature algorithms of some passports are not supported by zkPassport's circuits yet; this app then tells the requester that the passport is not supported and sends nothing else.
- **Records:** this app keeps, in the history on the device, the requester's domain and origin, the file name of the passport used, what the proofs established and (when your own prover is used) its address, but not the proofs themselves; you can delete the history in the app.
- **Test requests:** when a request is marked as a test, the requester accepts test passports and uses the test network registry.

## 5. Unofficial compatible implementation

This app has no cooperation, certification, authorization, agency or endorsement relationship with zkPassport or its operators. The compatible features are implemented from its public and suitably licensed code, circuits and interfaces; an open-source licence does not necessarily grant permission to use third-party online services or a trademark licence. The zkPassport name is used only to identify the supported protocol or service.

## 6. After declining or withdrawing

- This app does not connect to the zkPassport relay service, circuit and certificate package downloads, Ethereum nodes or the online verification service for this integration, and the zkPassport feature of the verify tab shows that it is not enabled; opening a zkPassport request link shows this statement first.
- Independent e-passport NFC reading, local signature verification and document keeping are not disabled by declining this.

## 7. Consent and withdrawal

Choosing "Accept and enable" means that you understand how the third parties above handle data, and choose to use this app's zkPassport verification and answering; each answer still needs your confirmation on the consent screen. You can withdraw under Settings > Legal and consent to stop further requests; data sent earlier, completed verifications or answers, and the records of third parties or requesters are not deleted automatically by withdrawal.
