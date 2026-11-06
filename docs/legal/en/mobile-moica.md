# Mobile Citizen Digital Certificate Signing Statement

Version 1, effective 2026-11-05

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- This feature uses the mobile citizen digital certificate service of the Ministry of the Interior to let you confirm a signature in the official mobile citizen digital certificate app; this app is not published, certified or endorsed by the Ministry of the Interior.
- **The developer of this project currently has no service provider (SP) account for the Ministry of the Interior's mobile citizen digital certificate service, and provides no ready-to-use built-in SP in its published versions.** The "built-in SP" integration code in the source is only a reserved implementation for publishers of derived versions (forks) who lawfully obtain authorization in the future to assess and configure themselves; it does not mean that this app has been approved for the integration.
- An actual signing request must go through an SP that is lawfully qualified for the integration; where configured in compliance, the source may be a server you set up yourself, an SP entered by hand by an authorized holder, or an SP lawfully configured by a derived version. **The presence of the feature or your acceptance of this statement does not mean that SP authorization has been obtained or that signing will succeed.**
- The Ministry of the Interior receives your national ID number, the signing description (which may include the file name), the attributes to be signed and the document hash, but not the full document to be signed; when a server is in between, its operator may also obtain the above data and the returned results.
- Declining disables only this signing method; citizen digital certificate cards, certificate files and other signing methods are not affected.

## 1. Service and confirmation flow

This project provides **integration code and an entry point** for signing with the mobile citizen digital certificate, but the developer currently has no SP of their own and does not guarantee that the official published versions have a usable integration source. **Only when an SP lawfully qualified for the integration is actually configured and the related services are available** can you choose this method on the document signing screen, with this app sending the request to the Ministry of the Interior's service through that SP. You must confirm in the official mobile citizen digital certificate app; after the Ministry of the Interior returns the certificate, the signature value and the transaction result, this app verifies them following the supported procedure and writes the signature into the document.

- **Push confirmation:** the Ministry of the Interior pushes a confirmation request to the official app you registered; the computer versions use this method.
- **App to app:** on supported phones, the official app is opened with a one-time ticket and, after you confirm, returns to this app; the one-time ticket does not contain the SP key.

In the current design, the first signature in each run usually needs the certificate to be obtained before signing, so two official confirmations may be needed; the certificate data is kept only in memory for this run, and reuse across runs is not guaranteed.

## 2. SP sources, eligibility and identifying information

An SP is a service provider that has applied to the Ministry of the Interior for the integration and holds a service code and the related keys. **Obtaining and using the account and keys, and whether others may be entrusted with the integration, are governed by the scope approved by the Ministry of the Interior, the integration application rules, contracts and other applicable rules**; the fact that an account can technically be used does not mean that any publisher, server or user is entitled to provide services in the name of that SP.

**Current publication facts:** the developer of this project, LIN, CHE-CHUAN, has not obtained an SP account or keys; the official published versions of this project provide no built-in SP held by the developer, and there is no default SP server run by the developer. The integration code is kept in the source to allow technical extension by future derived versions, not to claim that this version is approved by the Ministry of the Interior or has a usable SP.

The following are **sources that may appear once a particular version is lawfully authorized and actually configured**; this project does not currently provide all of them:

- **Server SP you set up:** you set the address of a `diw-wallet-server` deployment that supports the mobile citizen digital certificate yourself and use the access token it provides. The data path is "this app to the server to the Ministry of the Interior", and the SP key is kept on the server. The actual holder of the SP and the data processor is the deploying or operating party approved to use that SP, **not necessarily the developer of this app**; the deployer must still make sure that its integration and relaying meet the approval conditions.
- **Built-in SP configured by a derived version (reserved for the future):** the source keeps a technical flow to configure an SP at build time, mainly for future fork developers who have lawfully obtained SP integration eligibility to assess. If their derived version actually configures one, requests may go from that version directly to the Ministry of the Interior in the name of the SP it is approved to use. **The official published versions of this project currently configure no such SP**; publishers of derived versions must themselves confirm their eligibility, the approved systems and purposes, whether this kind of client deployment is allowed, and the necessary personal data and security obligations. An SP secret key embedded in a public program may be extracted; that the code can support the configuration must not be mistaken for permission to do so.
- **SP entered by hand (developer and test setting):** people with lawful eligibility can turn on "Enter an SP account by hand" under Settings > Developer and testing, enter the service code and AES key themselves, choose the matching environment and send requests directly to the Ministry of the Interior. In the current design, the key is used only in memory for this run and is not written to the device. This entry is only for people entitled to use that SP; do not enter accounts or keys obtained without authorization.

The signing screen should let you identify the **SP source, the production or test environment, and, where available and confirmed, the SP provider's name or identification** used this time. If only the source type can be shown and the actual holder cannot be confirmed, do not treat the SP's identity as verified. In the current design, when manual entry is on, the manual source is used by default; otherwise a configured server's SP takes precedence, and a built-in SP can appear only if that published version **actually configures one with lawful authorization**. **If no lawful and usable SP is available, signing cannot be completed, and it should not be shown to users as directly usable.**

## 3. Production and test environments

- **Production:** uses the Ministry of the Interior's production interface `fidoapi.moi.gov.tw`. Through a server SP, the current design has this app check that the first certificate obtained is issued by MOICA G3; other verification follows the mechanisms actually supported. These technical checks do not replace confirming that the SP authorization is valid.
- **Test (UAT):** uses `fido-test.moi.gov.tw` and still requires test integration eligibility under the Ministry of the Interior's rules. Test certificates and test signatures must not be passed off as production signatures, and any individual evidential value they may have is still decided under the applicable law.
- **Sources and environments:** if a future derived version lawfully configures a built-in SP, the environment follows that version's release settings; a manual SP is specified by the entitled user, and a server SP follows the environment the server publishes. In the current design, this app checks that the environment information the server provides is consistent with this request, but this check alone cannot establish that the other side is lawfully authorized.

## 4. Data sent to the Ministry of the Interior and servers

Following the signing flow, this app sends the following data to the Ministry of the Interior, which handles it under its rules:

- Your national ID number.
- The signing description the official app may show: `DIW MY WALLET signature: ` (in the language of the app) followed by the file name, limited to 60 characters in the current design; **the file name itself may contain names, case names or other sensitive information**.
- The signing attributes to be signed, including the document hash and the information signing needs, but not the full document content.
- Protocol information such as the confirmation method, time limit and SP service code.

The Ministry of the Interior returns the certificate (which may contain the name, identity fields and the like), the signature value and the transaction result. With a direct integration, this app verifies the response with the related key; through a server, some checks may be done by the server, and this app verifies the supported signatures and certificate chain on the device.

**If a server you specify is used, its operator can also access the above request and response data.** The server code provided by the project is designed to keep data in memory temporarily, avoid persistent logging and limit concurrency, but deployers may modify the code, add logs or use different configurations; the developer cannot verify the actual retention or security measures of every third-party server. Before choosing a server, check its operator, privacy information and authorization.

## 5. Main risks and legal effect

- The Ministry of the Interior and the SP holder can learn from the request the signing time, the SP, the national ID number and the description that may contain the file name; when a server relays, its operator may learn them too.
- The Ministry of the Interior may suspend an SP, change the interface or limit unapproved uses; servers may also stop their service, making signing fail.
- **Only when a future derived version actually configures an SP** do the risks of extraction, abuse and joint suspension arise from building an SP secret key into a public app. **This project currently has no built-in SP key, and does not recommend that any derived version publish a production SP secret key in a recoverable form.**
- The SP only stands for the source of the integration service; it does not mean that the SP holder signs the document on your behalf. The effect of a document signature still depends on the validity of the certificate, your confirmation in the official app, the signing result and rules such as the Electronic Signatures Act, and must not be guaranteed solely by this app's verification result or the SP source.

## 6. Unofficial status and SP responsibilities

This app is not an official app published, certified, authorized or endorsed by the Ministry of the Interior. **The developer of this project currently has no SP; the technical implementation of a built-in SP in the source is only a reference and extension point for future fork developers and does not mean that the Ministry of the Interior has approved the integration.** The integration was implemented with reference to open-source code and specifications lawfully available, and does not mean that the Ministry of the Interior allows any SP account to be used in this app. Third-party server operators, people entering an SP by hand and publishers of derived versions who actually provide an SP should, according to their roles, confirm their approved eligibility, the scope of the integration, key custody and personal data security; users must also not use unauthorized SP information. These descriptions of responsibilities do not exclude any party's liability under the law for its own publication, design or data processing.

## 7. After declining or withdrawing

- This app does not offer this mobile citizen digital certificate document signing flow, and does not send signing requests to the Ministry of the Interior or such requests to the server you specified for this feature.
- Sign-in and verification flows in which other websites send you to the official mobile citizen digital certificate app themselves are services started independently by those websites and are outside this disabling.
- Citizen digital certificate cards on the device, certificate files, CSC remote signing and other methods are not affected.

## 8. Consent and withdrawal

"Accept and enable" means that you understand the SP sources, the flows of personal data and file names, the differences between production and test environments and the unofficial risks, and allow this signing integration to be offered to you **when a lawful and usable SP source exists**; **this consent does not provide an SP account, turn the reserved code into a usable service automatically, or replace the approval the Ministry of the Interior requires**. You can withdraw at any time under Settings > Legal and consent to stop later signing requests of this kind. Signatures already sent or completed, and data the Ministry of the Interior, the SP or the server kept earlier under the law, are not cancelled or deleted automatically by withdrawal.
