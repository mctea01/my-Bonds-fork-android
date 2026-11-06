# zkPassport Statement (reserved, feature not yet available)

Version 1, effective 2026-11-05

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- **The zkPassport compatible features are not available yet.** This document describes the third-party zero-knowledge proof flow planned for the future; showing this document does not provide or enable the feature right away.
- In the current plan, the zkPassport relay service, circuit and certificate package downloads and blockchain lookups are run by third parties, which may see your IP address, the connection time and some request metadata.
- FaceMatch and salted unique identifier proofs, which only the official app can produce, are not planned to be supported; unsalted identifiers may stay the same within one service and are not completely unlinkable.
- Declining means the zkPassport service is not used; NFC reading and local verification of e-passports provided by other features are not affected. The actual data flows and this statement should be checked again before release.

## 1. Planned features and current state

zkPassport is a third-party zero-knowledge proof protocol and related services for electronic passports. In the current plan of this project, e-passport data read by NFC could in future be used to produce or verify particular zero-knowledge proofs about conditions such as age or nationality, instead of sending the full passport content with each proof; zkPassport requests to verify others might also be produced.

**This integration is not offered yet.** If features or interfaces are added or changed, data transfers are widened or third-party providers change, the statement should be revised and the matching consent obtained before release; no security can be promised to users on the basis of an unimplemented design.

## 2. Planned operators and data flows

If implemented according to the current plan, the following may be involved:

- **Relay service (such as `bridge.zkpassport.id`):** forwards requests or proofs between the requester and the responder. If end-to-end encryption is actually enabled and verified, the service usually cannot read the protected proof content directly, but may still observe the IP address, connection time, session identifiers and transfer sizes; until verified, it cannot be guaranteed that no content is visible.
- **Circuit, certificate package and sanctions list downloads:** the download servers may record your IP address and the kind of data obtained, and from that infer the passport's issuing country, signature algorithm or verification context.
- **Public Ethereum nodes:** circuits, certificate trees or registry contracts are queried through nodes; node operators may learn the queried addresses, times and contracts.
- **Optional online verification API:** the whole proof and related results might be sent to a third party only when you enable it separately and the configured trigger conditions are met; disabled by default in the current plan.
- **Optional cloud proving service:** if some kind of compressed proof needs third-party computation, the necessary sub-proofs or computation data might be sent only after you confirm that request; not enabled by default in the current plan. Sub-proofs are not necessarily the raw passport data, but may still contain identifying information.

The actual third-party names, endpoints, data visibility, security mechanisms and retention periods are those of the released version, the service terms and the tested message flows.

## 3. Privacy, unique identifiers and verification limits

- **FaceMatch:** in the current compatible plan, this app does not support FaceMatch proofs, which only the official zkPassport app can produce; requests that need it cannot be completed by this app.
- **Salted identifiers:** the current plan does not support salted unique identifiers that need the official mechanism; unsalted identifiers may be derived from passport data, the domain and the purpose and stay the same within the same service context, so there is a risk of linking across sessions; parties who know the full chip data may also derive the related results.
- **Requester identity:** the domain or identification in a request may be supplied by whoever created the request; this app plans to compare the origin and warn on mismatch, but a warning does not mean that the other side's real identity has been independently confirmed.
- **Service availability:** third parties may change or stop their services under their own rules. A zero-knowledge proof only guarantees properties under a particular circuit and verification conditions, and **does not mean that any identity or claim is recognized by a government**.

## 4. Unofficial compatible implementation

This app has no cooperation, certification, authorization, agency or endorsement relationship with zkPassport or its operators. The related compatible features are planned to be implemented from its public and suitably licensed code, circuits and interfaces; an open-source licence does not necessarily grant permission to use third-party online services or a trademark licence. The zkPassport name is used only to identify the protocol or service intended to be supported.

## 5. After declining or withdrawing

- This app does not connect to the zkPassport relay, downloads, on-chain lookups, cloud proving or online verification services for this integration; related requests show that the feature is not enabled or not yet provided.
- Independent e-passport NFC reading, local signature verification and document keeping (where the version provides them) are not disabled by declining this.
- Before release, the choice made on this statement should not be used as a blank advance authorization for wider future data use; if the data flows or features differ materially, the updated statement should be shown separately.

## 6. Consent and withdrawal

Only once this feature is officially provided and the statement is confirmed again for the released version does "Accept and enable" mean that you choose to use the matching zkPassport compatible features. You can withdraw under Settings > Legal and consent to stop further integration requests; data sent earlier, completed proofs or third-party records are not deleted automatically by withdrawal. **In versions where the feature is not yet available, "not yet provided" should be shown, and choosing to accept must not be read as the feature being enabled.**
