# TWDIW Digital Wallet Statement

Version 1, effective 2026-11-05

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- The TWDIW digital wallet (Taiwan Digital Identity Wallet) platform is operated by the Ministry of Digital Affairs; issuing, verification and over-the-counter interactions may also involve other authorities, organizations and public blockchain nodes.
- **This app is not the official digital wallet and is not issued, certified or endorsed by the Ministry of Digital Affairs.** To stay compatible with certain interfaces it may connect with the `moda_dw` identifier and a compatible User-Agent; this does not mean that this app really is the official client.
- In the current compatible design, TWDIW cards share the holder key and related identifying information, which may let different verifiers link presentation records; the platform may also refuse unofficial implementations.
- You can decline or withdraw, which disables only the TWDIW integration; stored cards are not deleted, and other standard protocol features are not affected.

## 1. Service and relationship

The Taiwan Digital Identity Wallet (TWDIW) is a digital credential platform built by the Ministry of Digital Affairs. Once you enable it, this app can, through the supported compatible flows, browse the card catalogue, apply for and receive cards from the platform's issuers, present to registered verifiers (including static QR codes and custom fields), use the related over-the-counter barcode services, and use the platform's trust lists to assess issuers and verifiers.

This app is a third-party compatible tool provided by the individual developer LIN, CHE-CHUAN, not an official app of the Ministry of Digital Affairs; the Ministry of Digital Affairs, issuing authorities and verifiers do not become partners, licensors or guarantors of this app through technical interoperability.

## 2. Operators and data flows

- **Receiving:** this app may send the holder DID, public key, signed proofs and the identifying information the platform or issuer asks for to issuers related to `wallet.gov.tw`; data you enter on the issuer's website is handled by that website.
- **Presenting:** sends the fields you select, the holder DID and the presentation proof to verifiers registered on the platform; with custom fields or static QR codes, what you fill in and the necessary protocol information may also be sent.
- **Over-the-counter services:** following the specific flow, submits the required presentation to the service provider's system, and the platform or service provider returns a barcode or confirmation.
- **Platform trust and status:** downloads the trust data of the production and official test environments and queries on-chain registration from public Arbitrum One nodes (such as `arb1.arbitrum.io`); for stored TWDIW cards, the current design may check the issuer again every 12 hours and query status regularly.

Each recipient can obtain the request, your source IP address and the time of the connection; from the request content, it may also infer which authorities or organizations you interact with. How the data is actually kept depends on the operator concerned.

## 3. Centralization, identification and privacy risks

- The platform controls its trust registry and service interfaces; issuers and verifiers each manage the issuing, acceptance, suspension or revocation of credentials. If any of them stops the service or changes its rules, the related features may stop working.
- In the current compatible design, TWDIW cards share one holder key, and the related holder DID or re-identifiable information may let different verifiers match and link several presentations; **selective disclosure of fields is not anonymity or untraceability**.
- The platform, issuers, verifiers and node operators may record the request time, source and related identifying information.
- Using test environments, third-party verification or over-the-counter services does not guarantee obtaining production credentials or acceptance by a particular business.

## 4. Important notice about the unofficial compatible implementation

This app implements the compatible flows from public standards, the official published code and the actual interface behaviour. To interoperate with the platform, some flows may use the official wallet identifier `moda_dw` and a compatible User-Agent in their requests; you can change the applicable settings under Settings > Interoperability.

**These identifiers may make the platform treat the requests as coming from the official wallet type, but this app is in fact not the official wallet and has no official certification.** Compatibility cannot be taken as proof of authorization for any service; the platform may refuse, interrupt or limit requests because of client identification, service terms, security policies or technical updates. Do not represent this app's unofficial status to others as official approval. Before production use, check the service rules and whether third-party clients are allowed.

## 5. Effects of declining or withdrawing

- Disables the TWDIW card catalogue, receiving cards, platform verification and over-the-counter integration; scanning such a QR code or opening such a link shows that this integration is not enabled.
- This app does not connect to `wallet.gov.tw` or the Arbitrum lookup nodes for the TWDIW integration, no longer uses the platform trust lists to reassess the related DIDs, and does not query TWDIW card status.
- Stored cards stay on the device; in the current design they cannot be presented to platform verifiers at `wallet.gov.tw` addresses. Earlier trust results may stay at their last update and cannot be treated as currently valid.
- Other standard features such as OpenID4VCI, OpenID4VP and ISO/IEC 18013-5 are not disabled by this withdrawal; if they connect independently to operators on the same underlying network, they work according to their own features and policies.

## 6. Consent and withdrawal

Choosing "Accept and enable" means that you have read the above about the unofficial status, data flows and linkability risks, and ask this app to enable the TWDIW compatible features; it is not a condition for using other features of the app. You can withdraw under Settings > Legal and consent; after withdrawal, this app starts no new service requests through this integration. Transactions completed or sent before withdrawal and data the other side obtained are not undone or deleted automatically; to exercise data rights against a third party, contact the actual recipient.
