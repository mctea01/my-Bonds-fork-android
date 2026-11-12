# DIW MY WALLET Privacy Policy

Version 2, effective 2026-11-11

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- This app needs no developer account and has no ads, usage analytics, crash reporting or built-in tracking; the developer currently runs no back-end server that receives wallet credentials, documents or usage records.
- Credentials, keys, documents, settings and consent records are stored mainly in the app's protected private storage on the device; but features such as presenting, signing, lookups or background verification may send the necessary data to third parties.
- Some HTTP lookups and the offline transfers compatible with the Bonds format have no transport encryption; third parties may still obtain your IP address, what you looked up or the data you agreed to present.
- The TWDIW digital wallet, Microsoft Entra Verified ID, the mobile citizen digital certificate, MyData and similar features must be enabled separately. You can withdraw each consent, but data already sent is not deleted from third parties.

## 1. Scope and terms

This policy explains how DIW MY WALLET ("this app", including the Android, Windows and Linux versions) published by the individual developer LIN, CHE-CHUAN handles data on the device, and when it sends data to third parties. Terms such as "user", "holder", "issuer", "verifier" and "third-party service" are defined in section 2 of the Terms of Use.

This policy is written to explain transparently the app's actual data flows, retention and user choices, with reference to the principles of notice and data subject rights emphasized by the Personal Data Protection Act currently in force in the Taiwan area. Whether the developer or another operator bears legal personal data obligations for a particular processing activity is still determined by the facts of who actually controls, obtains and uses the data and by the applicable law; this policy does not exclude in advance any liability under the law, nor does it mean that the developer controls every third party.

The data flows of this app are a different matter from information you give the developer directly through GitHub Issues or e-mail; third parties have their own privacy policies and legal obligations.

## 2. Data the developer actually obtains

This app requires no developer account; as currently designed, it contains no ads, app usage analytics, crash reporting or user tracking SDKs, and by default it does not upload the credentials, private keys, documents or interaction records in the wallet to any server run by the developer. This app has no default back end of its own; servers you enter yourself are not services the developer necessarily runs.

If you contact the developer through GitHub Issues or e-mail, the developer obtains the name, contact details, description and attachments you provide, and may use and keep them as reasonably needed to solve the problem and handle security reports; GitHub and e-mail providers also process them under their own policies. Do not post national ID numbers, certificates, keys, private documents or other sensitive content in public issues. You can make requests about that contact data through the original channel, and the developer handles them according to the applicable law and the data actually held.

Even though the developer does not receive wallet data, when the app sends data off the device as part of a feature, the Google Play data safety declaration may still treat that transfer as "collection"; this is a separate question from whether the developer keeps the data.

## 3. Data kept on the device and its uses

- **Credentials and certificate data:** digital credentials, identifying fields, photos or card images, issuer information, status lookup results and self-issued derived credentials.
- **Private keys and protection data:** the private keys the wallet and signing need; Android uses the Android Keystore or StrongBox when available, otherwise software keys may be protected with the app PIN. The security available depends on the device and the type of key.
- **Electronic documents and verification data:** imported or downloaded PDFs, official electronic documents, OpenCerts and other files, and signatures, certificate chains, timestamps, revocation data, verification results, zkPDF evidence and the like.
- **Interaction records:** the other party, the time of the interaction, the credential used and the names of the disclosed fields; as currently designed, field values are not kept in these records. Credentials and documents themselves may still contain full personal data.
- **Settings and caches:** the MyData national ID number and date of birth you choose to keep, server addresses you specify, trust lists, translation caches and the like.
- **Consent records of the legal documents:** the version of each document, whether you accepted or declined, and the time, kept on the device only.

This data is used for display on the device, verification, signing, trust decisions, feature settings and keeping your choices. As a rule it is in the app's private storage, encrypted with the device keys on Android and with the protection provided by the app PIN on computers; not every kind of key can be hardware-isolated on every device. The Android version has the system's automatic backup of this app switched off; documents you export yourself, other backup tools or handing data to third parties are outside this limitation.

## 4. Data sent off the device

Data is sent when you start a related operation, or when this app performs a necessary lookup to complete credential or document status checks, trust decisions or other enabled features; not every lookup needs a separate presentation confirmation. The other side of the connection can usually obtain your source IP address, the time of the connection and the content of the request, and may infer from this which issuer issued a credential you hold. How long and for what the data is actually kept is decided by the recipient's policies and regulations.

- **Receiving credentials:** sends the data needed for authorization, the holder DID or public key, key attestations and the information the issuer asks for; data you fill in on the issuer's web pages is received by that website.
- **Presenting and verifying:** depending on your choice, sends the credential, the fields you agree to disclose, holder identification, necessary protocol information and the presentation proof to the verifier or the other device; QR codes, NFC or Bluetooth may be used to set up the connection or to carry the data directly. Different protocols may disclose different metadata; "only the selected fields are sent" should not be read as meaning that no other necessary protocol data is sent.
- **Status, issuer information and trust lookups:** depending on the settings, obtains credential status, DID documents, OCSP, CRLs, issuer information, Adobe AATL, the EU EUTL, mdoc trust lists and test trust anchors from issuers, DID hosts and third-party publishers; some lookups happen automatically, and some updates can be switched off in the settings.
- **Document timestamps:** sends a timestamp request to the timestamp authority you choose (DigiCert by default), containing a SHA-256 hash computed from the document being processed, not the full document; the request may also contain fields the protocol requires.
- **Document signing:** certificate cards on the device sign on the device. Remote CSC services may receive the hash to be signed, a description (which may include the file name) and sign-in or authorization data. For signing with the mobile citizen digital certificate, see its dedicated statement.
- **OpenCerts online verification:** sends lookups about the certificate store or domain to public Ethereum nodes and DNS over HTTPS services; after you choose "Show in the issuer's style", the whole certificate is sent over HTTPS to the display website the certificate names, which may contain third-party code and handle data in its own way.
- **DID resolution:** where external resolution is needed, such as `did:ion`, the DID document may be requested from the Microsoft DID resolution service or the hosts involved.
- **External document websites:** when you open a government or other document source website in the in-app browser, that website receives what you enter directly; this app keeps the files you choose to download or import.
- **Zero-knowledge proofs:** proofs such as zkPDF can be computed on the device; flows that use zkTLS or otherwise need a connection may connect to the target website or notary, relay or verification services and send the proof, necessary protocol information and the data you agree to provide. Some proof or evidence formats may include document content or the signed version, so they cannot all be assumed never to send documents.
- **Servers you set up yourself:** there is no default server. When you enter a server address yourself and use its features, its operator may receive relay messages, zkTLS verification data, access tokens, or the national ID number, file name description, signing attributes and returned certificate needed for mobile citizen digital certificate signing. Whether the server can read what is sent depends on the feature and the encryption used.
- **System Credential Manager:** on the device, the Android version can register the names, images and display fields of presentable credentials with the system picker of Android or Google Play services, so that other apps or websites can ask to use the credentials. This is an integration with the device's system and does not mean that the data has been uploaded to a developer server.

These features may involve names, e-mail addresses, national ID numbers and other user identifiers, addresses, dates of birth, nationality, gender, photos, files and documents; if a credential or document you choose to send contains financial, health or similar information, the recipient may obtain that content as well. Whether particular data types must be declared in app stores depends on what is actually sent and on the platform's definitions.

## 5. Transport and remaining risks

Most online receiving, presenting and remote signing connections use HTTPS, and ISO/IEC 18013-5 proximity presentation sets up an encrypted channel under the protocol. But **not every transmission has transport-layer encryption**:

- Some timestamp, OCSP, CRL, certificate or related lookups may use HTTP addresses provided by third parties; onlookers may learn what is requested, certificate serial numbers or hashes, and may also interfere with the transmission. Signed responses help verify integrity, but this does not mean that all HTTP content is safe or that the privacy of the lookup is protected.
- Some Bluetooth or local network offline presentations compatible with the Bonds format have no connection-level encryption; third parties nearby or on the same network may capture the fields you disclose, so avoid using them in untrusted environments or for highly sensitive information.
- Test services or local or LAN endpoints you specify may allow HTTP; whether they are safe to use depends on the network environment.

The developer reduces risks with security measures in the software, but does not guarantee that all third-party communication or recipients meet the same security standards.

## 6. Dedicated services and individual choices

The following integrations need you to read their dedicated statements and choose whether to accept them: the TWDIW digital wallet of the Ministry of Digital Affairs, Microsoft Entra Verified ID, the mobile citizen digital certificate of the Ministry of the Interior, and MyData of the Ministry of Digital Affairs. The zkPassport compatible features have their own dedicated statement, which lists the parts offered; a feature that is not actually provided is not enabled by showing its text in advance.

Declining or withdrawing a dedicated statement stops only further connections and features of that particular integration, and the other standards-compatible features remain available. Credentials and documents kept earlier stay on the device as a rule; data sent to third parties earlier and signatures, presentations or applications already completed are not deleted or invalidated automatically by withdrawal. You can choose again under Settings > Legal and consent.

## 7. Device permissions

- **Camera:** for scanning QR codes, and for recognizing the machine readable zone of travel documents such as e-passports to fill in the document number, date of birth and expiry date needed to read the chip; recognition runs on the device in real time with the built-in Tesseract engine, and images are neither kept nor sent.
- **NFC:** for reading certificate cards and chip documents such as e-passports by tapping, and for proximity presentation or verification.
- **Bluetooth:** for proximity transfers; Android 11 and earlier may also ask for location permission to use Bluetooth, but this app does not use that permission to read or record your location.
- **Biometrics:** for user confirmation on the device; this app does not obtain or keep biometric templates.
- **USB:** for connecting compatible smart card readers.
- **Network:** for the third-party connections described above that you start or that features need.

Refusing a permission may make the matching feature unavailable and usually does not affect other features. Permission requirements differ between operating systems and versions.

## 8. Retention, deletion and data subject rights

Credentials, documents, records and settings on the device are, as a rule, kept until you delete them, reset or remove the app. You can remove items with the delete operations the app provides; uninstalling on Android usually deletes the app's private data, while Windows and Linux users may also have to remove the app's data folder. Deletion may be irreversible. Data you exported yourself, backed up with other tools or that third parties already obtained is not deleted along with it.

You can use the features of this app to view, export or delete data on the device; for issued data that needs correcting, contact the original issuing authority. If data has been received by a verifier, a document website, a signing provider, MyData or a server you set up yourself, ask that actual holder how to exercise rights such as access, correction, stopping use and deletion. The developer cannot delete data on behalf of third parties, nor guarantee how soon they delete it.

For contact data the developer receives directly through GitHub or e-mail, you can ask through the channels in section 14 for access, correction, stopping use or deletion; the developer handles the request according to the data actually held and the applicable law, and may keep related records where the law requires.

## 9. Data protection law and responsibilities

The duty to give notice under Article 8 of the Personal Data Protection Act currently in force in the Taiwan area presupposes that a government or non-government agency actually collects personal data from the data subject. Based on the current design, this app is mainly a tool with which you manage data on your own device and send requests directly to third parties, and the developer usually does not receive such wallet data; however, whether there is collection, processing, use or any other obligation must still be judged case by case for the actual features, control, incident handling and recipients, and cannot be excluded across the board just because processing is "local".

This policy describes item by item, according to the actual flows, the categories of data on the device, the features using them, the recipients, the periods, the regions and the effect of not providing data; it should not be read as the developer claiming to be the sole collector of each item. For contact data the developer actually holds under the law, the rights of the data subject under the law are not limited by this policy. Rights under Article 3 of the Personal Data Protection Act and other mandatory provisions are not waived in advance by using this app.

This app may handle credentials or documents from the Taiwan area, mainland China and other regions. Such technical compatibility does not mean that those documents have the same legal effect in different regions, nor that the developer decides for every third party which law applies to its data processing. Cross-region transfers and the related responsibilities must still be determined individually according to the actual use, the operators and the rules that apply in each place.

This app may be downloaded by users outside the Taiwan area or be compatible with services abroad; but whether a foreign data protection law (including the GDPR) applies depends on the actual business activities, whether users there are targeted, the roles in data processing and the related territorial requirements. This policy does not claim GDPR certification, nor does it exclude obligations abroad that must be observed under the law.

## 10. Minors

This app is intended for people **aged 18 or over** and is not directed at minors. Minors should not enable or use this app on their own; a legal representative's consent does not remove age limits set by third parties. If you find that the developer obtained personal data of a minor through the direct contact channels that should not be kept, you can ask for it to be handled under section 14.

## 11. Security measures and reminders

This app provides on-device encryption, hardware key protection where available, presentation confirmation and technical trust decisions, but cannot completely exclude compromised devices, lost keys, malicious verifiers, wrong certificates or third-party data leaks. Please turn on the screen lock, keep your PIN safe, get versions only from Google Play or the trusted release locations of this project on GitHub, and check the actual recipient and what is sent.

## 12. Third-party policies and future changes in operation

Third-party issuers, verifiers, government websites, trust information publishers, Microsoft, timestamp services and servers deployed by users each decide how they handle data. Providing open-source server code does not automatically make the developer the operator of such a server; but anyone who runs or hosts a server must still meet their obligations according to the data processing they actually do.

If the developer later provides a default or public server, accounts, cloud backup, telemetry or any other feature that receives data, this policy, the data safety declaration and the necessary consent should be updated before the feature is enabled or released, stating the operator, data types, purposes, retention period, deletion and contact channels.

## 13. Policy updates and confirmation

When this policy changes materially, the version and effective date are updated and you are asked to read and confirm it again the next time you start the app; for typo fixes that do not affect the substance, the version may stay the same. You must accept this policy and the Terms of Use separately to use the app; but **accepting this policy does not replace the consent individual services need, nor does it give third parties any permission beyond what the features need**. All versions can be read in the `docs/legal` folder of the project on GitHub.

## 14. Contact

For general comments, please use GitHub Issues: https://github.com/mctea01/my-Bonds-fork-android/issues . For personal data rights, security vulnerabilities or matters containing sensitive information, do not post them publicly; contact the developer privately at the developer e-mail address listed on this app's Google Play store page.
