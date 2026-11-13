package diw.wallet.app.legal

/**
 * The English translation of [LegalTextsZh]: the same documents, ids, versions and sections. The Traditional Chinese
 * text prevails where the two differ (said at the top of each English text); keep both in step when a text changes.
 */
internal object LegalTextsEn {
    const val DEVELOPER = "LIN, CHE-CHUAN"
    private const val SOURCE_URL = LegalTexts.SOURCE_URL
    private const val ISSUES_URL = LegalTexts.ISSUES_URL
    private const val DATE = "2026-11-05"
    private const val EN = "en"

    val terms = document(
        "terms-of-use", "DIW MY WALLET Terms of Use", 1, DATE,
        listOf(
            "DIW MY WALLET is a free, open-source wallet and electronic document tool provided by an individual developer. It is not issued, certified or endorsed by the Ministry of Digital Affairs, the Ministry of the Interior, the National Development Council, Microsoft, the European Union or any issuing authority.",
            "Adding, presenting and signing may send the data you choose and the necessary protocol information to third parties; this app does not guarantee that a credential or signature is valid.",
            "Check who is verifying, which fields will be presented and which document you are signing, and keep your device, keys and PINs safe. Derived credentials you make yourself are not credentials issued by an authority.",
            "This app is provided free of charge and as is; the limitations of liability apply only as far as the law allows and do not exclude liability that cannot be excluded by law.",
        ),
        EN,
    ) {
        section(
            "Parties and acceptance",
            p("DIW MY WALLET (\"this app\") includes the Android, Windows and Linux versions published by the individual developer $DEVELOPER (\"the developer\"). " +
                "You should have the chance to read these terms and the Privacy Policy before use; on first start you must accept these terms and the Privacy Policy with two separate checkboxes before you can continue. " +
                "If you do not accept either document, you cannot use this app. Accepting the Privacy Policy is a required confirmation of how this app handles data and does not replace the separate consent that enables a dedicated service."),
            p("This app is intended for people aged 18 or over and is not directed at minors. People under 18 should not enable or use this app on their own; where use is genuinely necessary in a particular case, " +
                "first check whether the applicable law, the issuing authority and the service terms allow it, and obtain the necessary consent and help of a legal representative. A legal representative's consent does not mean that any third-party service allows use by minors."),
        )
        section(
            "Definitions",
            list(
                "\"You\" or \"the user\": the person who installs or operates this app; when presenting credentials also called \"the holder\".",
                "\"Issuer\": an authority or organization that issues, provides or manages digital credentials, and its services.",
                "\"Verifier\": a person, authority or organization, and its systems, that asks you to present a credential, receives data or verifies a proof.",
                "\"Third-party service\": an issuing, verification, signing, timestamp, identity verification, lookup or relay service not operated by the developer, including servers you set up yourself.",
                "\"Dedicated statement\": a document that additionally explains the data flows, risks and choice to enable a particular service; accepting a statement enables only the matching feature.",
            ),
        )
        section(
            "Features and scope",
            p("Following the public standards and compatible protocols it supports, this app can receive, keep, present and verify digital credentials; import and keep electronic documents; check electronic signatures, revocation status and timestamps; sign documents with certificate cards, certificate files or remote services; " +
                "create self-issued derived credentials; and, where supported, produce zero-knowledge proofs. Supported formats include OpenID4VCI, OpenID4VP, ISO/IEC 18013-5, ISO/IEC 18013-7, SD-JWT VC, " +
                "ISO mdoc and W3C VC. Features may differ between versions, and some need the camera, NFC, Bluetooth, USB, the network or third-party services."),
            p("This app may handle electronic credentials or documents from the Taiwan area, mainland China and other regions; whether one is supported depends on its file format, technical protocol and the actual features. Being technically able to import, verify or display a document does not mean that the developer considers it legally effective in any particular region, " +
                "nor that its issuing authority has certified or endorsed this app."),
            p("The developer may add, change, suspend or remove features for maintenance, security, legal, compatibility or other reasonable reasons; for published versions, it cannot be guaranteed that every third-party service stays available. Changes that require updating the legal documents follow section 12."),
        )
        section(
            "Independence, compatibility and names",
            p("This app is not issued, certified, authorized or endorsed by the Ministry of Digital Affairs, the Ministry of the Interior, the National Development Council, Microsoft, the European Union (including the EUDI Wallet programmes) or any other issuing authority. " +
                "Technical compatibility does not create any cooperation, agency, affiliation or service engagement between them and this app. Working with their services does not give this app any official status or qualification."),
            p("Some features are compatible implementations based on public documents, open-source code or observable protocol behaviour, and may stop working when the other side changes its specifications, verification mechanisms or access policies. Some offline credential formats or protocols are compatible with Bonds, an open-source project of an individual developer; this means technical compatibility only. " +
                "Bonds provides no central service for this app, and the compatibility constitutes no cooperation or endorsement."),
            p("Names, logos or trademarks of government authorities, standards, products and services mentioned in this app are used only to identify the services or describe compatibility; the rights belong to their respective owners, and unless there is an explicit written basis, no licence, approval or association is implied."),
        )
        section(
            "Open-source licences",
            p("The source code of this app is provided under the Apache License 2.0 stated in its repository and under the licences of the third-party components used. Your rights to use, modify and redistribute the source code are governed by those open-source licences; these terms do not change or take away those licences. " +
                "These terms describe the conditions and risks of using the versions published by the developer; for versions modified or published by others, their publishers should explain and are responsible for any added features, data handling and publication, without affecting liability under the law."),
            p("Source code: $SOURCE_URL"),
        )
        section(
            "What users should observe",
            list(
                "Keep, receive, present, verify and sign credentials or documents only where it is lawful and you are entitled to; do not impersonate others, falsify data or access others' systems without authorization.",
                "Protect your device with suitable access control and keep the app PIN, certificate cards, card readers and related passwords safe; if a device or certificate is lost, ask the issuing authority to suspend, revoke or reissue it as appropriate.",
                "Before presenting, confirm the verifier and the purpose of the data, and check the fields and the necessary protocol information to be disclosed; before signing, check the document content, the file name and the official confirmation screen. If you cannot confirm who is verifying or what is being signed, do not continue.",
                "Keep verifiable originals and the necessary backups of important documents separately; before using test environments, third-party services or servers you set up yourself, assess their reliability and data security.",
                "When you use third-party services, you must also follow the rules and laws that apply to them.",
            ),
        )
        section(
            "Legal effect of credentials, check results and electronic signatures",
            p("The issuance of a credential, the correctness of identity data, its validity period, its revocation and the conditions for accepting it are decided by the issuing authority, the verifier and the applicable regulations. The T1 to T4 trust levels, certificate chains, signatures, status or revocation check results shown by this app " +
                "are technical assessments based on the data available at the time; they are affected by the data sources, settings, connection state and implementation limits, and are not official certification, a legal expert opinion or a guarantee that a credential is valid."),
            p("Derived credentials made from document content (including ID cards compatible with the Bonds format) are statements issued by the user, not national ID cards, official electronic credentials or substitutes for them issued by a government authority. Verifiers may decide under the law and their own rules whether to accept them."),
            p("The effect of electronic documents and electronic signatures is decided by the law that actually applies to the document and transaction, the certificate conditions and the circumstances; where the law of the Taiwan area applies, the Electronic Signatures Act and related rules should also be consulted. A \"verified\" result shown by this app does not by itself give any particular legal effect. " +
                "Data produced in test environments must not be used as production certificates or production signatures; any evidential value they may have is still decided under the applicable law."),
        )
        section(
            "Third-party services and dedicated statements",
            p("Depending on what you do or on the related verification features, this app may connect to issuers, verifiers, document websites, signing and timestamp services, trust or status lists, blockchain nodes and servers you set up yourself. The data handling, service conditions and retention of such services " +
                "are handled by their actual operators under their own rules; the developer cannot control their operation and does not fulfil their legal obligations for them."),
            p("The TWDIW digital wallet, Microsoft Entra Verified ID, the mobile citizen digital certificate, MyData and, once actually released, the zkPassport compatible features each have their own dedicated statement. " +
                "You can decline each of them; declining disables only the matching integration and leaves other features unaffected. Completed receiving, presentations, signatures and data already received by third parties are not erased automatically when you withdraw later. See each dedicated statement and the Privacy Policy."),
        )
        section(
            "Risks, disclaimers and liability",
            p("This app is free and provided \"as is\" and \"as available\". Unless mandatory law provides otherwise or the developer makes an explicit written commitment, the developer gives no further warranty of the availability of any particular third party, compliance with standards, timeliness of data or fitness for a particular purpose. Please note in particular the risks of device damage, " +
                "unrecoverable keys, invalid credentials, intercepted transmissions, third-party service outages and failed signatures or verifications."),
            p("If damage arises from using this app, each party's liability is determined by the specific facts, the degree of fault and the applicable law. **These terms do not exclude or limit in advance the developer's liability for intent, gross negligence, or any other liability that cannot be excluded or limited by law**; " +
                "nor do they limit the claims or consumer rights users have under the law. The risk descriptions above do not mean that users must bear damage for which the developer is responsible under the law."),
        )
        section(
            "Data, keys and stopping use",
            p("Credentials, documents, keys, settings and interaction records are, as a rule, stored on the device you use. You can delete data with the features of the app and stop using it; uninstalling on Android usually removes the app's private data, while on computers you may have to delete its data folder separately. " +
                "Data you exported, backed up separately or sent to third parties is not deleted along with it; deleted keys and documents may be unrecoverable. See the Privacy Policy for details."),
            p("The developer may stop publishing, updating or providing some versions for legal, security, technical maintenance or end-of-maintenance reasons; this does not mean that the developer can access the data on your device remotely."),
        )
        section(
            "Consent to each service and withdrawal",
            p("Dedicated statements can be accepted, declined or withdrawn one by one under Settings > Legal and consent. After withdrawal, further feature requests for that dedicated service and automatic lookups started by that integration stop; transactions already started, sent or completed, and data that third parties kept earlier under the law or their policies, " +
                "are not revoked retroactively. To have third-party data deleted, ask that third party."),
            p("These terms and the Privacy Policy are the basic documents that must be accepted before using this app and are not subject to the \"disable one feature only\" mechanism above; if you no longer accept their required conditions, you can stop using this app."),
        )
        section(
            "Updates to the documents",
            p("If these terms change materially, the version and effective date are updated and you are asked to confirm again the next time you open the app; for fixes of typos that do not affect rights and obligations, the version may stay the same. Revisions do not retroactively change the legal effect of acts already completed. " +
                "All published versions can be read in the `docs/legal` folder of the project on GitHub."),
        )
        section(
            "Governing law and disputes",
            p("These terms are governed by the laws currently in force in the Taiwan area. Legal relationships involving other regions are still handled under the applicable conflict-of-laws rules and mandatory provisions. Disputes arising from these terms are handled by the court with jurisdiction under the law; **where the Consumer Protection Act or other laws provide otherwise, " +
                "those provisions apply**. This section does not designate a particular court, nor does it exclude other rights and protections that cannot be excluded by law."),
        )
        section(
            "Contact",
            p("For general suggestions and questions, please use GitHub Issues: $ISSUES_URL . For matters involving personal data, certificates, vulnerabilities or other security information, do not post them publicly; " +
                "contact the developer privately at the developer e-mail address listed on this app's page in the Google Play store."),
        )
    }

    val privacy = document(
        "privacy-policy", "DIW MY WALLET Privacy Policy", 2, "2026-11-11",
        listOf(
            "This app needs no developer account and has no ads, usage analytics, crash reporting or built-in tracking; the developer currently runs no back-end server that receives wallet credentials, documents or usage records.",
            "Credentials, keys, documents, settings and consent records are stored mainly in the app's protected private storage on the device; but features such as presenting, signing, lookups or background verification may send the necessary data to third parties.",
            "Some HTTP lookups and the offline transfers compatible with the Bonds format have no transport encryption; third parties may still obtain your IP address, what you looked up or the data you agreed to present.",
            "The TWDIW digital wallet, Microsoft Entra Verified ID, the mobile citizen digital certificate, MyData and similar features must be enabled separately. You can withdraw each consent, but data already sent is not deleted from third parties.",
        ),
        EN,
    ) {
        section(
            "Scope and terms",
            p("This policy explains how DIW MY WALLET (\"this app\", including the Android, Windows and Linux versions) published by the individual developer $DEVELOPER handles data on the device, " +
                "and when it sends data to third parties. Terms such as \"user\", \"holder\", \"issuer\", \"verifier\" and \"third-party service\" are defined in section 2 of the Terms of Use."),
            p("This policy is written to explain transparently the app's actual data flows, retention and user choices, with reference to the principles of notice and data subject rights emphasized by the Personal Data Protection Act currently in force in the Taiwan area. Whether the developer or another operator bears legal personal data obligations for a particular processing activity " +
                "is still determined by the facts of who actually controls, obtains and uses the data and by the applicable law; this policy does not exclude in advance any liability under the law, nor does it mean that the developer controls every third party."),
            p("The data flows of this app are a different matter from information you give the developer directly through GitHub Issues or e-mail; third parties have their own privacy policies and legal obligations."),
        )
        section(
            "Data the developer actually obtains",
            p("This app requires no developer account; as currently designed, it contains no ads, app usage analytics, crash reporting or user tracking SDKs, and by default it does not upload the credentials, private keys, documents or interaction records in the wallet to any server run by the developer. " +
                "This app has no default back end of its own; servers you enter yourself are not services the developer necessarily runs."),
            p("If you contact the developer through GitHub Issues or e-mail, the developer obtains the name, contact details, description and attachments you provide, and may use and keep them as reasonably needed to solve the problem and handle security reports; GitHub " +
                "and e-mail providers also process them under their own policies. Do not post national ID numbers, certificates, keys, private documents or other sensitive content in public issues. You can make requests about that contact data through the original channel, and the developer handles them according to the applicable law and the data actually held."),
            p("Even though the developer does not receive wallet data, when the app sends data off the device as part of a feature, the Google Play data safety declaration may still treat that transfer as \"collection\"; this is a separate question from whether the developer keeps the data."),
        )
        section(
            "Data kept on the device and its uses",
            list(
                "**Credentials and certificate data:** digital credentials, identifying fields, photos or card images, issuer information, status lookup results and self-issued derived credentials.",
                "**Private keys and protection data:** the private keys the wallet and signing need; Android uses the Android Keystore or StrongBox when available, otherwise software keys may be protected with the app PIN. " +
                "The security available depends on the device and the type of key.",
                "**Electronic documents and verification data:** imported or downloaded PDFs, official electronic documents, OpenCerts and other files, and signatures, certificate chains, timestamps, revocation data, verification results, zkPDF evidence and the like.",
                "**Interaction records:** the other party, the time of the interaction, the credential used and the names of the disclosed fields; as currently designed, field values are not kept in these records. Credentials and documents themselves may still contain full personal data.",
                "**Settings and caches:** the MyData national ID number and date of birth you choose to keep, server addresses you specify, trust lists, translation caches and the like.",
                "**Consent records of the legal documents:** the version of each document, whether you accepted or declined, and the time, kept on the device only.",
            ),
            p("This data is used for display on the device, verification, signing, trust decisions, feature settings and keeping your choices. As a rule it is in the app's private storage, encrypted with the device keys on Android and with the protection provided by the app PIN on computers; " +
                "not every kind of key can be hardware-isolated on every device. The Android version has the system's automatic backup of this app switched off; documents you export yourself, other backup tools or handing data to third parties are outside this limitation."),
        )
        section(
            "Data sent off the device",
            p("Data is sent when you start a related operation, or when this app performs a necessary lookup to complete credential or document status checks, trust decisions or other enabled features; not every lookup needs a separate presentation confirmation. The other side of the connection can usually obtain your source IP address, " +
                "the time of the connection and the content of the request, and may infer from this which issuer issued a credential you hold. How long and for what the data is actually kept is decided by the recipient's policies and regulations."),
            list(
                "**Receiving credentials:** sends the data needed for authorization, the holder DID or public key, key attestations and the information the issuer asks for; data you fill in on the issuer's web pages is received by that website.",
                "**Presenting and verifying:** depending on your choice, sends the credential, the fields you agree to disclose, holder identification, necessary protocol information and the presentation proof to the verifier or the other device; QR codes, NFC or Bluetooth may be used to set up the connection or to carry the data directly. " +
                "Different protocols may disclose different metadata; \"only the selected fields are sent\" should not be read as meaning that no other necessary protocol data is sent.",
                "**Status, issuer information and trust lookups:** depending on the settings, obtains credential status, DID documents, OCSP, CRLs, issuer information, Adobe AATL, the EU EUTL, " +
                "mdoc trust lists and test trust anchors from issuers, DID hosts and third-party publishers; some lookups happen automatically, and some updates can be switched off in the settings.",
                "**Document timestamps:** sends a timestamp request to the timestamp authority you choose (DigiCert by default), containing a SHA-256 hash computed from the document being processed, not the full document; the request may also contain fields the protocol requires.",
                "**Document signing:** certificate cards on the device sign on the device. Remote CSC services may receive the hash to be signed, a description (which may include the file name) and sign-in or authorization data. For signing with the mobile citizen digital certificate, see its dedicated statement.",
                "**OpenCerts online verification:** sends lookups about the certificate store or domain to public Ethereum nodes and DNS over HTTPS services; after you choose \"Show in the issuer's style\", " +
                "the whole certificate is sent over HTTPS to the display website the certificate names, which may contain third-party code and handle data in its own way.",
                "**DID resolution:** where external resolution is needed, such as `did:ion`, the DID document may be requested from the Microsoft DID resolution service or the hosts involved.",
                "**External document websites:** when you open a government or other document source website in the in-app browser, that website receives what you enter directly; this app keeps the files you choose to download or import.",
                "**Zero-knowledge proofs:** proofs such as zkPDF can be computed on the device; flows that use zkTLS or otherwise need a connection may connect to the target website or notary, relay or verification services and send the proof, necessary protocol information and the data you agree to provide. " +
                "Some proof or evidence formats may include document content or the signed version, so they cannot all be assumed never to send documents.",
                "**Servers you set up yourself:** there is no default server. When you enter a server address yourself and use its features, its operator may receive relay messages, zkTLS verification data, access tokens, or the national ID number, file name description, " +
                "signing attributes and returned certificate needed for mobile citizen digital certificate signing. Whether the server can read what is sent depends on the feature and the encryption used.",
                "**System Credential Manager:** on the device, the Android version can register the names, images and display fields of presentable credentials with the system picker of Android or Google Play services, " +
                "so that other apps or websites can ask to use the credentials. This is an integration with the device's system and does not mean that the data has been uploaded to a developer server.",
            ),
            p("These features may involve names, e-mail addresses, national ID numbers and other user identifiers, addresses, dates of birth, nationality, gender, photos, files and documents; if a credential or document you choose to send contains financial, health or similar information, the recipient may obtain that content as well. " +
                "Whether particular data types must be declared in app stores depends on what is actually sent and on the platform's definitions."),
        )
        section(
            "Transport and remaining risks",
            p("Most online receiving, presenting and remote signing connections use HTTPS, and ISO/IEC 18013-5 proximity presentation sets up an encrypted channel under the protocol. But **not every transmission has transport-layer encryption**:"),
            list(
                "Some timestamp, OCSP, CRL, certificate or related lookups may use HTTP addresses provided by third parties; onlookers may learn what is requested, certificate serial numbers or hashes, and may also interfere with the transmission. Signed responses help verify integrity, " +
                "but this does not mean that all HTTP content is safe or that the privacy of the lookup is protected.",
                "Some Bluetooth or local network offline presentations compatible with the Bonds format have no connection-level encryption; third parties nearby or on the same network may capture the fields you disclose, so avoid using them in untrusted environments or for highly sensitive information.",
                "Test services or local or LAN endpoints you specify may allow HTTP; whether they are safe to use depends on the network environment.",
            ),
            p("The developer reduces risks with security measures in the software, but does not guarantee that all third-party communication or recipients meet the same security standards."),
        )
        section(
            "Dedicated services and individual choices",
            p("The following integrations need you to read their dedicated statements and choose whether to accept them: the TWDIW digital wallet of the Ministry of Digital Affairs, Microsoft Entra Verified ID, the mobile citizen digital certificate of the Ministry of the Interior, and MyData of the Ministry of Digital Affairs. " +
                "The zkPassport compatible features have their own dedicated statement, which lists the parts offered; a feature that is not actually provided is not enabled by showing its text in advance."),
            p("Declining or withdrawing a dedicated statement stops only further connections and features of that particular integration, and the other standards-compatible features remain available. Credentials and documents kept earlier stay on the device as a rule; data sent to third parties earlier and signatures, presentations or applications already completed " +
                "are not deleted or invalidated automatically by withdrawal. You can choose again under Settings > Legal and consent."),
        )
        section(
            "Device permissions",
            list(
                "**Camera:** for scanning QR codes, and for recognizing the machine readable zone of travel documents such as e-passports to fill in the document number, date of birth and expiry date needed to read the chip; recognition runs on the device in real time with the built-in Tesseract engine, and images are neither kept nor sent.",
                "**NFC:** for reading certificate cards and chip documents such as e-passports by tapping, and for proximity presentation or verification.",
                "**Bluetooth:** for proximity transfers; Android 11 and earlier may also ask for location permission to use Bluetooth, but this app does not use that permission to read or record your location.",
                "**Biometrics:** for user confirmation on the device; this app does not obtain or keep biometric templates.",
                "**USB:** for connecting compatible smart card readers.",
                "**Network:** for the third-party connections described above that you start or that features need.",
            ),
            p("Refusing a permission may make the matching feature unavailable and usually does not affect other features. Permission requirements differ between operating systems and versions."),
        )
        section(
            "Retention, deletion and data subject rights",
            p("Credentials, documents, records and settings on the device are, as a rule, kept until you delete them, reset or remove the app. You can remove items with the delete operations the app provides; uninstalling on Android usually deletes the app's private data, " +
                "while Windows and Linux users may also have to remove the app's data folder. Deletion may be irreversible. Data you exported yourself, backed up with other tools or that third parties already obtained is not deleted along with it."),
            p("You can use the features of this app to view, export or delete data on the device; for issued data that needs correcting, contact the original issuing authority. If data has been received by a verifier, a document website, a signing provider, MyData or a server you set up yourself, ask that actual holder how to exercise rights such as access, " +
                "correction, stopping use and deletion. The developer cannot delete data on behalf of third parties, nor guarantee how soon they delete it."),
            p("For contact data the developer receives directly through GitHub or e-mail, you can ask through the channels in section 14 for access, correction, stopping use or deletion; the developer handles the request according to the data actually held and the applicable law, and may keep related records where the law requires."),
        )
        section(
            "Data protection law and responsibilities",
            p("The duty to give notice under Article 8 of the Personal Data Protection Act currently in force in the Taiwan area presupposes that a government or non-government agency actually collects personal data from the data subject. Based on the current design, this app is mainly a tool with which you manage data on your own device " +
                "and send requests directly to third parties, and the developer usually does not receive such wallet data; however, whether there is collection, processing, use or any other obligation must still be judged case by case for the actual features, control, incident handling and recipients, and cannot be excluded across the board just because processing is \"local\"."),
            p("This policy describes item by item, according to the actual flows, the categories of data on the device, the features using them, the recipients, the periods, the regions and the effect of not providing data; it should not be read as the developer claiming to be the sole collector of each item. For contact data the developer actually holds under the law, " +
                "the rights of the data subject under the law are not limited by this policy. Rights under Article 3 of the Personal Data Protection Act and other mandatory provisions are not waived in advance by using this app."),
            p("This app may handle credentials or documents from the Taiwan area, mainland China and other regions. Such technical compatibility does not mean that those documents have the same legal effect in different regions, nor that the developer decides for every third party which law applies to its data processing. Cross-region transfers and the related responsibilities " +
                "must still be determined individually according to the actual use, the operators and the rules that apply in each place."),
            p("This app may be downloaded by users outside the Taiwan area or be compatible with services abroad; but whether a foreign data protection law (including the GDPR) applies depends on the actual business activities, whether users there are targeted, the roles in data processing and the related territorial requirements. " +
                "This policy does not claim GDPR certification, nor does it exclude obligations abroad that must be observed under the law."),
        )
        section(
            "Minors",
            p("This app is intended for people **aged 18 or over** and is not directed at minors. Minors should not enable or use this app on their own; a legal representative's consent does not remove age limits set by third parties. " +
                "If you find that the developer obtained personal data of a minor through the direct contact channels that should not be kept, you can ask for it to be handled under section 14."),
        )
        section(
            "Security measures and reminders",
            p("This app provides on-device encryption, hardware key protection where available, presentation confirmation and technical trust decisions, but cannot completely exclude compromised devices, lost keys, malicious verifiers, wrong certificates or third-party data leaks. Please turn on the screen lock, keep your PIN safe, " +
                "get versions only from Google Play or the trusted release locations of this project on GitHub, and check the actual recipient and what is sent."),
        )
        section(
            "Third-party policies and future changes in operation",
            p("Third-party issuers, verifiers, government websites, trust information publishers, Microsoft, timestamp services and servers deployed by users each decide how they handle data. Providing open-source server code does not automatically make the developer the operator of such a server; " +
                "but anyone who runs or hosts a server must still meet their obligations according to the data processing they actually do."),
            p("If the developer later provides a default or public server, accounts, cloud backup, telemetry or any other feature that receives data, this policy, the data safety declaration and the necessary consent should be updated before the feature is enabled or released, stating the operator, data types, purposes, retention period, deletion and contact channels."),
        )
        section(
            "Policy updates and confirmation",
            p("When this policy changes materially, the version and effective date are updated and you are asked to read and confirm it again the next time you start the app; for typo fixes that do not affect the substance, the version may stay the same. You must accept this policy and the Terms of Use separately to use the app; " +
                "but **accepting this policy does not replace the consent individual services need, nor does it give third parties any permission beyond what the features need**. All versions can be read in the `docs/legal` folder of the project on GitHub."),
        )
        section(
            "Contact",
            p("For general comments, please use GitHub Issues: $ISSUES_URL . For personal data rights, security vulnerabilities or matters containing sensitive information, do not post them publicly; " +
                "contact the developer privately at the developer e-mail address listed on this app's Google Play store page."),
        )
    }

    private val twdiw = document(
        "twdiw", "TWDIW Digital Wallet Statement", 1, DATE,
        listOf(
            "The TWDIW digital wallet (Taiwan Digital Identity Wallet) platform is operated by the Ministry of Digital Affairs; issuing, verification and over-the-counter interactions may also involve other authorities, organizations and public blockchain nodes.",
            "**This app is not the official digital wallet and is not issued, certified or endorsed by the Ministry of Digital Affairs.** To stay compatible with certain interfaces it may connect with the `moda_dw` identifier and a compatible User-Agent; this does not mean that this app really is the official client.",
            "In the current compatible design, TWDIW cards share the holder key and related identifying information, which may let different verifiers link presentation records; the platform may also refuse unofficial implementations.",
            "You can decline or withdraw, which disables only the TWDIW integration; stored cards are not deleted, and other standard protocol features are not affected.",
        ),
        EN,
    ) {
        section(
            "Service and relationship",
            p("The Taiwan Digital Identity Wallet (TWDIW) is a digital credential platform built by the Ministry of Digital Affairs. Once you enable it, this app can, through the supported compatible flows, browse the card catalogue, " +
                "apply for and receive cards from the platform's issuers, present to registered verifiers (including static QR codes and custom fields), use the related over-the-counter barcode services, and use the platform's trust lists to assess issuers and verifiers."),
            p("This app is a third-party compatible tool provided by the individual developer $DEVELOPER, not an official app of the Ministry of Digital Affairs; the Ministry of Digital Affairs, issuing authorities and verifiers do not become partners, licensors or guarantors of this app through technical interoperability."),
        )
        section(
            "Operators and data flows",
            list(
                "**Receiving:** this app may send the holder DID, public key, signed proofs and the identifying information the platform or issuer asks for to issuers related to `wallet.gov.tw`; data you enter on the issuer's website is handled by that website.",
                "**Presenting:** sends the fields you select, the holder DID and the presentation proof to verifiers registered on the platform; with custom fields or static QR codes, what you fill in and the necessary protocol information may also be sent.",
                "**Over-the-counter services:** following the specific flow, submits the required presentation to the service provider's system, and the platform or service provider returns a barcode or confirmation.",
                "**Platform trust and status:** downloads the trust data of the production and official test environments and queries on-chain registration from public Arbitrum One nodes (such as `arb1.arbitrum.io`); for stored TWDIW cards, " +
                "the current design may check the issuer again every 12 hours and query status regularly.",
            ),
            p("Each recipient can obtain the request, your source IP address and the time of the connection; from the request content, it may also infer which authorities or organizations you interact with. How the data is actually kept depends on the operator concerned."),
        )
        section(
            "Centralization, identification and privacy risks",
            list(
                "The platform controls its trust registry and service interfaces; issuers and verifiers each manage the issuing, acceptance, suspension or revocation of credentials. If any of them stops the service or changes its rules, the related features may stop working.",
                "In the current compatible design, TWDIW cards share one holder key, and the related holder DID or re-identifiable information may let different verifiers match and link several presentations; **selective disclosure of fields is not anonymity or untraceability**.",
                "The platform, issuers, verifiers and node operators may record the request time, source and related identifying information.",
                "Using test environments, third-party verification or over-the-counter services does not guarantee obtaining production credentials or acceptance by a particular business.",
            ),
        )
        section(
            "Important notice about the unofficial compatible implementation",
            p("This app implements the compatible flows from public standards, the official published code and the actual interface behaviour. To interoperate with the platform, some flows may use the official wallet identifier `moda_dw` and a compatible User-Agent in their requests; " +
                "you can change the applicable settings under Settings > Interoperability."),
            p("**These identifiers may make the platform treat the requests as coming from the official wallet type, but this app is in fact not the official wallet and has no official certification.** Compatibility cannot be taken as proof of authorization for any service; the platform may refuse, interrupt or limit requests because of client identification, service terms, " +
                "security policies or technical updates. Do not represent this app's unofficial status to others as official approval. Before production use, check the service rules and whether third-party clients are allowed."),
        )
        section(
            "Effects of declining or withdrawing",
            list(
                "Disables the TWDIW card catalogue, receiving cards, platform verification and over-the-counter integration; scanning such a QR code or opening such a link shows that this integration is not enabled.",
                "This app does not connect to `wallet.gov.tw` or the Arbitrum lookup nodes for the TWDIW integration, no longer uses the platform trust lists to reassess the related DIDs, and does not query TWDIW card status.",
                "Stored cards stay on the device; in the current design they cannot be presented to platform verifiers at `wallet.gov.tw` addresses. Earlier trust results may stay at their last update and cannot be treated as currently valid.",
                "Other standard features such as OpenID4VCI, OpenID4VP and ISO/IEC 18013-5 are not disabled by this withdrawal; if they connect independently to operators on the same underlying network, they work according to their own features and policies.",
            ),
        )
        section(
            "Consent and withdrawal",
            p("Choosing \"Accept and enable\" means that you have read the above about the unofficial status, data flows and linkability risks, and ask this app to enable the TWDIW compatible features; it is not a condition for using other features of the app. You can withdraw under Settings > Legal and consent; " +
                "after withdrawal, this app starts no new service requests through this integration. Transactions completed or sent before withdrawal and data the other side obtained are not undone or deleted automatically; to exercise data rights against a third party, contact the actual recipient."),
        )
    }

    private val msVerifiedId = document(
        "microsoft-verified-id", "Microsoft Entra Verified ID Statement", 1, DATE,
        listOf(
            "Microsoft Entra Verified ID is a credential service provided by Microsoft; the organizations involved may also take part in issuing, verifying and keeping data.",
            "This app handles Verified ID requests according to public documents and compatible protocols; **it is not Microsoft Authenticator and is not certified, authorized or endorsed by Microsoft**.",
            "In the current design, Verified ID compatible cards share the holder key and identifying information, and presentation records may be linked by different verifiers.",
            "Declining disables Verified ID receiving, presentation and status lookups, while stored cards are kept; general standard protocol features are not affected.",
        ),
        EN,
    ) {
        section(
            "Service",
            p("Microsoft Entra Verified ID is a Microsoft service for organizations to issue and verify verifiable credentials. Once you enable it, " +
                "this app can receive cards issued by organizations through compatible `openid-vc` links or QR codes, including signing in to the organization, entering self-asserted fields or presenting other cards as the flow requires, and can answer verification requests that use the Verified ID service."),
        )
        section(
            "Operators and data transfers",
            list(
                "**Receiving:** requests and responses may pass through Microsoft's Verified ID cloud service and the organization's systems, and may contain the holder DID, public key, authorization tokens, self-asserted fields " +
                "and other cards or proofs you choose to provide.",
                "**Presenting:** may send the selected credentials and fields, the holder DID, signatures and necessary protocol information to Microsoft's services and the verifying organization.",
                "**Identity and DID resolution:** this app may read the Linked Domains configuration and DID documents of the organization's domain; " +
                "to resolve `did:ion`, it may send DID lookups to Microsoft resolution endpoints (such as `discover.did.msidentity.com`).",
                "**Status lookups:** where the service requires it, this app may query the revocation status of credentials from Microsoft or the organization.",
            ),
            p("Microsoft and each organization handle the data they actually receive under their own service terms and privacy policies; when connecting, they may obtain your IP address, the time of the connection and related identifying information."),
        )
        section(
            "Service and traceability risks",
            list(
                "Microsoft and the organizations involved may learn when receiving or verification requests take place and with whom; if the service changes or stops, presenting or verifying may no longer be possible.",
                "Credentials can be revoked by the authorized issuing organization; their status depends on the data and lookup results the service provides.",
                "In the current compatible design, several Verified ID cards share the holder key; the same DID or re-identifiable information may let verifiers link presentations across contexts. Disclosing only selected fields does not guarantee anonymity.",
            ),
        )
        section(
            "Unofficial compatible implementation",
            p("This app is an independently developed compatible tool, not Microsoft Authenticator, and has no affiliation, cooperation, certification, authorization or endorsement relationship with Microsoft. Names or trademarks such as Microsoft, Entra, " +
                "Verified ID and Microsoft Authenticator belong to their owners; this app mentions them only to identify the service and describe interoperability."),
            p("The protocols or security requirements may change, and Microsoft or organizations may refuse this app's unofficial implementation; the developer does not guarantee that every request works."),
        )
        section(
            "After declining or withdrawing",
            list(
                "This app does not handle Verified ID `openid-vc` card links, QR codes or the specific presentation requests, and does not connect to Microsoft's Verified ID service for this integration.",
                "Stored Verified ID cards are not deleted, but no automatic status lookups are made for them through this integration.",
                "General standard requests such as OpenID4VP still work; any independent DID resolution or trust lookup feature follows its general data flows and settings, and disabling this integration should not be read as blocking all Microsoft domains.",
            ),
        )
        section(
            "Consent and withdrawal",
            p("\"Accept and enable\" means that you understand the cross-service transfers, unofficial compatibility and identification linkability risks above and choose to use this integration. You can withdraw under Settings > Legal and consent to stop further requests of this integration; interactions sent or completed before withdrawal " +
                "do not become invalid and are not deleted automatically from Microsoft or organization systems. Other features of the app keep working."),
        )
    }

    private val mobileMoica = document(
        "mobile-moica", "Mobile Citizen Digital Certificate Signing Statement", 1, DATE,
        listOf(
            "This feature uses the mobile citizen digital certificate service of the Ministry of the Interior to let you confirm a signature in the official mobile citizen digital certificate app; this app is not published, certified or endorsed by the Ministry of the Interior.",
            "**The developer of this project currently has no service provider (SP) account for the Ministry of the Interior's mobile citizen digital certificate service, and provides no ready-to-use built-in SP in its published versions.** The \"built-in SP\" integration code in the source is only a reserved implementation " +
                "for publishers of derived versions (forks) who lawfully obtain authorization in the future to assess and configure themselves; it does not mean that this app has been approved for the integration.",
            "An actual signing request must go through an SP that is lawfully qualified for the integration; where configured in compliance, the source may be a server you set up yourself, an SP entered by hand by an authorized holder, or an SP lawfully configured by a derived version. **The presence of the feature or your acceptance of this statement " +
                "does not mean that SP authorization has been obtained or that signing will succeed.**",
            "The Ministry of the Interior receives your national ID number, the signing description (which may include the file name), the attributes to be signed and the document hash, but not the full document to be signed; when a server is in between, its operator may also obtain the above data and the returned results.",
            "Declining disables only this signing method; citizen digital certificate cards, certificate files and other signing methods are not affected.",
        ),
        EN,
    ) {
        section(
            "Service and confirmation flow",
            p("This project provides **integration code and an entry point** for signing with the mobile citizen digital certificate, but the developer currently has no SP of their own and does not guarantee that the official published versions have a usable integration source. **Only when an SP lawfully qualified for the integration is actually configured and the related services are available** " +
                "can you choose this method on the document signing screen, with this app sending the request to the Ministry of the Interior's service through that SP. You must confirm in the official mobile citizen digital certificate app; after the Ministry of the Interior returns the certificate, the signature value and the transaction result, " +
                "this app verifies them following the supported procedure and writes the signature into the document."),
            list(
                "**Push confirmation:** the Ministry of the Interior pushes a confirmation request to the official app you registered; the computer versions use this method.",
                "**App to app:** on supported phones, the official app is opened with a one-time ticket and, after you confirm, returns to this app; the one-time ticket does not contain the SP key.",
            ),
            p("In the current design, the first signature in each run usually needs the certificate to be obtained before signing, so two official confirmations may be needed; the certificate data is kept only in memory for this run, and reuse across runs is not guaranteed."),
        )
        section(
            "SP sources, eligibility and identifying information",
            p("An SP is a service provider that has applied to the Ministry of the Interior for the integration and holds a service code and the related keys. **Obtaining and using the account and keys, and whether others may be entrusted with the integration, are governed by the scope approved by the Ministry of the Interior, the integration application rules, contracts and other applicable rules**; the fact that an account can technically be used " +
                "does not mean that any publisher, server or user is entitled to provide services in the name of that SP."),
            p("**Current publication facts:** the developer of this project, $DEVELOPER, has not obtained an SP account or keys; the official published versions of this project provide no built-in SP held by the developer, and there is no default SP server run by the developer. " +
                "The integration code is kept in the source to allow technical extension by future derived versions, not to claim that this version is approved by the Ministry of the Interior or has a usable SP."),
            p("The following are **sources that may appear once a particular version is lawfully authorized and actually configured**; this project does not currently provide all of them:"),
            list(
                "**Server SP you set up:** you set the address of a `diw-wallet-server` deployment that supports the mobile citizen digital certificate yourself and use the access token it provides. The data path is \"this app to the server to the Ministry of the Interior\", " +
                "and the SP key is kept on the server. The actual holder of the SP and the data processor is the deploying or operating party approved to use that SP, **not necessarily the developer of this app**; the deployer must still make sure that its integration and relaying meet the approval conditions.",
                "**Built-in SP configured by a derived version (reserved for the future):** the source keeps a technical flow to configure an SP at build time, mainly for future fork developers who have lawfully obtained SP integration eligibility to assess. If their derived version actually configures one, " +
                "requests may go from that version directly to the Ministry of the Interior in the name of the SP it is approved to use. **The official published versions of this project currently configure no such SP**; publishers of derived versions must themselves confirm their eligibility, the approved systems and purposes, whether this kind of client deployment is allowed, " +
                "and the necessary personal data and security obligations. An SP secret key embedded in a public program may be extracted; that the code can support the configuration must not be mistaken for permission to do so.",
                "**SP entered by hand (developer and test setting):** people with lawful eligibility can turn on \"Enter an SP account by hand\" under Settings > Developer and testing, enter the service code and AES key themselves, choose the matching environment and send requests directly to the Ministry of the Interior. " +
                "In the current design, the key is used only in memory for this run and is not written to the device. This entry is only for people entitled to use that SP; do not enter accounts or keys obtained without authorization.",
            ),
            p("The signing screen should let you identify the **SP source, the production or test environment, and, where available and confirmed, the SP provider's name or identification** used this time. If only the source type can be shown and the actual holder cannot be confirmed, do not treat the SP's identity as verified. " +
                "In the current design, when manual entry is on, the manual source is used by default; otherwise a configured server's SP takes precedence, and a built-in SP can appear only if that published version **actually configures one with lawful authorization**. **If no lawful and usable SP is available, signing cannot be completed, " +
                "and it should not be shown to users as directly usable.**"),
        )
        section(
            "Production and test environments",
            list(
                "**Production:** uses the Ministry of the Interior's production interface `fidoapi.moi.gov.tw`. Through a server SP, the current design has this app check that the first certificate obtained is issued by MOICA G3; " +
                "other verification follows the mechanisms actually supported. These technical checks do not replace confirming that the SP authorization is valid.",
                "**Test (UAT):** uses `fido-test.moi.gov.tw` and still requires test integration eligibility under the Ministry of the Interior's rules. Test certificates and test signatures must not be passed off as production signatures, " +
                "and any individual evidential value they may have is still decided under the applicable law.",
                "**Sources and environments:** if a future derived version lawfully configures a built-in SP, the environment follows that version's release settings; a manual SP is specified by the entitled user, and a server SP follows the environment the server publishes. " +
                "In the current design, this app checks that the environment information the server provides is consistent with this request, but this check alone cannot establish that the other side is lawfully authorized.",
            ),
        )
        section(
            "Data sent to the Ministry of the Interior and servers",
            p("Following the signing flow, this app sends the following data to the Ministry of the Interior, which handles it under its rules:"),
            list(
                "Your national ID number.",
                "The signing description the official app may show: `DIW MY WALLET signature: ` (in the language of the app) followed by the file name, limited to 60 characters in the current design; **the file name itself may contain names, case names or other sensitive information**.",
                "The signing attributes to be signed, including the document hash and the information signing needs, but not the full document content.",
                "Protocol information such as the confirmation method, time limit and SP service code.",
            ),
            p("The Ministry of the Interior returns the certificate (which may contain the name, identity fields and the like), the signature value and the transaction result. With a direct integration, this app verifies the response with the related key; through a server, some checks may be done by the server, and this app verifies the supported signatures and certificate chain on the device."),
            p("**If a server you specify is used, its operator can also access the above request and response data.** The server code provided by the project is designed to keep data in memory temporarily, avoid persistent logging and limit concurrency, but deployers may modify the code, add logs or use different configurations; " +
                "the developer cannot verify the actual retention or security measures of every third-party server. Before choosing a server, check its operator, privacy information and authorization."),
        )
        section(
            "Main risks and legal effect",
            list(
                "The Ministry of the Interior and the SP holder can learn from the request the signing time, the SP, the national ID number and the description that may contain the file name; when a server relays, its operator may learn them too.",
                "The Ministry of the Interior may suspend an SP, change the interface or limit unapproved uses; servers may also stop their service, making signing fail.",
                "**Only when a future derived version actually configures an SP** do the risks of extraction, abuse and joint suspension arise from building an SP secret key into a public app. **This project currently has no built-in SP key, " +
                "and does not recommend that any derived version publish a production SP secret key in a recoverable form.**",
                "The SP only stands for the source of the integration service; it does not mean that the SP holder signs the document on your behalf. The effect of a document signature still depends on the validity of the certificate, your confirmation in the official app, the signing result and rules such as the Electronic Signatures Act, " +
                "and must not be guaranteed solely by this app's verification result or the SP source.",
            ),
        )
        section(
            "Unofficial status and SP responsibilities",
            p("This app is not an official app published, certified, authorized or endorsed by the Ministry of the Interior. **The developer of this project currently has no SP; the technical implementation of a built-in SP in the source is only a reference and extension point for future fork developers and does not mean that the Ministry of the Interior has approved the integration." +
                "** The integration was implemented with reference to open-source code and specifications lawfully available, and does not mean that the Ministry of the Interior allows any SP account to be used in this app. Third-party server operators, people entering an SP by hand and publishers of derived versions who actually provide an SP should, according to their roles, confirm their approved eligibility, " +
                "the scope of the integration, key custody and personal data security; users must also not use unauthorized SP information. These descriptions of responsibilities do not exclude any party's liability under the law for its own publication, design or data processing."),
        )
        section(
            "After declining or withdrawing",
            list(
                "This app does not offer this mobile citizen digital certificate document signing flow, and does not send signing requests to the Ministry of the Interior or such requests to the server you specified for this feature.",
                "Sign-in and verification flows in which other websites send you to the official mobile citizen digital certificate app themselves are services started independently by those websites and are outside this disabling.",
                "Citizen digital certificate cards on the device, certificate files, CSC remote signing and other methods are not affected.",
            ),
        )
        section(
            "Consent and withdrawal",
            p("\"Accept and enable\" means that you understand the SP sources, the flows of personal data and file names, the differences between production and test environments and the unofficial risks, and allow this signing integration to be offered to you **when a lawful and usable SP source exists**; **this consent does not provide an SP account, " +
                "turn the reserved code into a usable service automatically, or replace the approval the Ministry of the Interior requires**. You can withdraw at any time under Settings > Legal and consent to stop later signing requests of this kind. Signatures already sent or completed, and data the Ministry of the Interior, the SP or the server kept earlier under the law, " +
                "are not cancelled or deleted automatically by withdrawal."),
        )
    }

    private val myData = document(
        "mydata", "MyData Statement", 1, DATE,
        listOf(
            "The MyData personal data self-use platform is currently built, run and managed by the **Ministry of Digital Affairs**; individual data is the responsibility of the authorities or organizations that provide it.",
            "This app opens the MyData web pages in the in-app browser, can help fill in the national ID number and date of birth you choose to keep, and downloads, extracts and keeps the documents.",
            "The identity verification, consent and download requests you complete on the MyData web pages are handled by MyData and the data providers under their rules; this app cannot delete records those third parties already hold.",
            "This app is not published, certified or endorsed by the Ministry of Digital Affairs or the data providers; declining disables only the MyData integration, and stored documents and derived credentials are kept.",
        ),
        EN,
    ) {
        section(
            "Features and users",
            p("MyData (the personal data self-use platform) lets users obtain personalized documents provided by authorities or organizations after identity verification and consent. Once enabled, you can use the MyData entry this app provides under Documents > Get from a website " +
                "to sign in on MyData's own website and download the household registration, tax, labour and health insurance and other documents available to you; some documents can be used to make derived credentials compatible with the Bonds format yourself."),
            p("A derived credential is a statement you produce yourself, not a national ID card or official digital credential issued by a government authority."),
        )
        section(
            "Operators, data flows and retention",
            list(
                "**Operator:** the MyData platform is currently built, run and managed by the Ministry of Digital Affairs; the document content is provided by each data-providing authority or organization. The related identity verification and data use records are handled under the policies of the platform and each authority.",
                "**Signing in in the browser:** this app opens the MyData web pages in the in-app browser; the citizen digital certificate, mobile citizen digital certificate or other verification method you choose on the pages, and the consent, applications and data handling on the pages, are the responsibility of the websites or services concerned.",
                "**Autofill on the device:** if you choose to keep your national ID number and date of birth, the current design lets this app fill them into the matching MyData pages for the MyData web pages to process, " +
                "and use the national ID number to open protected PDFs after download. This setting does not make this app send the data to any website other than MyData.",
                "**Document download:** this app can extract the ZIP downloaded from MyData on the device, keep the supported PDF documents in it, and delete the ZIP file after extraction. Documents you export separately are not controlled by the app's delete operations.",
            ),
            p("MyData, the data providers or their contracted services can learn your sign-in, application and access times, IP address and the related data types; check the retention periods in the service terms and privacy policy the platform publishes at the time."),
        )
        section(
            "Privacy and feature risks",
            list(
                "The MyData platform and the data-providing authorities may keep the necessary usage records; withdrawing this consent in this app does not delete third-party records retroactively.",
                "The autofill on the device uses sensitive identifiers such as the national ID number and date of birth; protect your device and app PIN well, and remove the saved autofill data when you no longer need it.",
                "When the MyData web pages, sign-in rules, download formats or ZIP or PDF protection change, autofill, extraction or document parsing may fail; the document content and its legal uses are governed by the original providing authority and the relevant regulations.",
                "Downloaded household registration, income, health insurance and similar documents may contain highly sensitive information; if you then present, share or make proofs from them with other features, the disclosure risk depends on that specific operation.",
            ),
        )
        section(
            "Unofficial compatible implementation",
            p("This app has no affiliation, cooperation, certification, authorization or endorsement relationship with the Ministry of Digital Affairs or the data-providing authorities. The website navigation, autofill help and download parsing are a compatible implementation of the public website's flow; this does not mean that MyData authorizes this app as an official integration, " +
                "nor does it guarantee that it keeps working after the website changes. The MyData name is used only to identify the service connected to."),
        )
        section(
            "After declining or withdrawing",
            list(
                "The MyData entry under Get documents and the integration that makes ID cards from MyData documents are disabled, and this app does not open the MyData web pages for this feature.",
                "The national ID number and date of birth saved earlier stay on the device but are no longer used for this autofill; you can delete them under Settings > Documents and signatures.",
                "Downloaded documents and the derived credentials and ID cards you produced are not deleted automatically, and other document features are not affected.",
            ),
        )
        section(
            "Consent and withdrawal",
            p("Choosing \"Accept and enable\" means that you understand how the MyData platform and the data providers each handle data, and choose to use this app's integration; **this does not replace any identity verification or data provision consent required on the MyData web pages each time**. " +
                "You can withdraw under Settings > Legal and consent to stop further requests of this integration; documents downloaded before withdrawal and operations completed by third parties do not become invalid and are not deleted automatically."),
        )
    }

    private val zkPassport = document(
        "zkpassport", "zkPassport Statement", 4, "2026-11-12",
        listOf(
            "**This app offers two uses:** verifying others, where this app creates a zkPassport request, the other person answers with zero-knowledge proofs from a zkPassport compatible app, and this app verifies them on the device; and answering requests, where you open someone else's zkPassport request with this app, choose a stored e-passport, and this app makes the proofs on the device (or, if you choose, has your own prover make them) and returns them to the requester.",
            "Both uses connect to third parties: the zkPassport relay service, the circuit and certificate package download servers and a public node for the Ethereum registry contract (which you can replace with your own node in settings). They may see your IP address, the connection time and some metadata.",
            "When you answer a request, the requester only receives what the consent screen lists; but the domain, service name and purpose in a request are entered by the requester, and this app cannot confirm the requester's real identity.",
            "Declining means the zkPassport service is not used; NFC reading and local verification of e-passports are not affected.",
        ),
        EN,
    ) {
        section(
            "What is offered",
            p("zkPassport is a third-party zero-knowledge proof protocol and related services for electronic passports."),
            p("**Verifying others:** you choose the fields the other person discloses (the document type and issuing country are always disclosed) and conditions such as age, nationality, issuing country and bound data, and this app creates a request link and QR code; the other person reads their e-passport chip with a zkPassport compatible app, which produces proofs and returns them through the relay service, " +
                "and this app checks every proof and its public inputs on the device. When the server of this app you have set up offers an OPRF key, this app also accepts salted identifiers made with that key; salted identifiers made with other keys are not accepted."),
            p("**Answering requests:** after you scan or open a zkPassport request link with this app, this app first connects to the relay service to learn the requester's origin, then shows a consent screen: the domain, service name and purpose the requester states, what the proofs would establish, and the stored e-passports you can use. " +
                "When you agree, this app makes the proofs on the device from the chip data of that passport read earlier and kept on the device (the SOD, DG1 and, when kept, the DG2 photo hash), and sends them to the requester through the relay service; when you decline, the requester is only told that you declined. " +
                "When the origin the relay service reports differs from the domain the request names, this app warns that the link may have been passed on by another site and sends only after you confirm again."),
            p("**Handing off to your own prover:** when the device cannot make the proofs or you prefer not to, you can choose on the consent screen to have your own prover make them: a proving service you set up yourself and reach with a dedicated token, or a temporary prover started with `diw-server prover` on a computer in the same local network and paired with a one-time pairing code. " +
                "This app then sends the SOD and DG1 of that passport (all the machine-readable zone data, such as name, passport number, date of birth and expiry) with the request to that prover, without the DG2 photo; the proofs come back to this app and are still sent to the requester through the relay service."),
            p("**Not offered yet:** cloud proving (modes that need zkPassport's servers to make the proofs) and FaceMatch face matching; answers also do not use salted identifiers. Requests that ask for these can only be declined. When features or data flows change materially, this statement is updated and you are asked to choose again."),
        )
        section(
            "Third-party operators and data flows",
            list(
                "**Relay service (`bridge.zkpassport.id`):** forwards requests and proofs between you and the other person. Messages are encrypted with keys the two sides exchange, but the encryption protocol is designed by a third party and this app cannot guarantee its strength; the service can still observe IP addresses, connection times, " +
                "session identifiers and transfer sizes. When verifying others, so that the other person's app accepts the request, this app connects with the domain you entered as its origin; when answering requests, this app compares against the requester's origin the relay service reports.",
                "**Circuit downloads (`circuits2.zkpassport.id`):** the circuit manifest, verification keys and the circuits needed to make proofs are downloaded and kept in a local cache; the server may record your IP address, the version and the kinds of circuits fetched, and infer from them the signature algorithm of the document. " +
                "When answering requests, what can be inferred is the signature algorithm of your own passport, and possibly the range of issuing countries.",
                "**Certificate package downloads (`certificates.zkpassport.id`):** the list of CSCA public keys for a certificate tree root is downloaded, its root recomputed on this device before use, and kept in a local cache; the server may record your IP address and the root fetched. " +
                "When verifying others it is used to compare the issuing country's CSCA with this app's trust anchors; when answering requests it is used on this device to find the CSCA of your passport, the whole list is downloaded and none of your passport data is sent.",
                "**Public Ethereum node:** the zkPassport registry contract is queried to confirm that the certificate tree and circuit manifest were valid on the proof date. By default a public node service is used (`ethereum-rpc.publicnode.com`, or a Sepolia test network node in test mode), " +
                "which you can replace with your own node in settings; the node operator may learn the contract, time and roots queried.",
                "**zkPassport online verification API (`verifier.zkpassport.id`, off by default, only for verifying others):** only when you enable it in settings and the local Barretenberg verification fails are the whole proofs, the request conditions and the result the other person's app returned sent to that service for its decision; " +
                "the result is then marked as decided by that service.",
                "**This app's server:** when verifying others, this app reads the public OPRF key information (`/info`) of the server you have set up, without sending any proof content. You set up the server yourself; it is not operated by zkPassport.",
                "**Your own prover (used only when you choose it):** you run it yourself; it is not operated by zkPassport or the developer of this app. This project's prover program handles passport data in memory only, deletes a result once it is read and deletes unread jobs after 10 minutes; " +
                "the temporary prover accepts local network connections only, encrypts traffic with a TLS certificate made for that run and carried in the pairing code, and clears its pairings and data when closed. Modified programs or other people's computers cannot be guaranteed to do the same, so use only your own computer. The prover itself connects to Ethereum nodes and the circuit and certificate package download servers.",
            ),
            p("The services the other person's app connects to (such as its proving or download flows) are decided by that app and are outside this statement. When you answer a request, how the requester keeps, uses or passes on the proofs is decided by the requester and is outside this statement."),
        )
        section(
            "What you receive when verifying others and its limits",
            list(
                "**Only committed values are used:** the fields and conditions shown come from the public inputs of verified proofs; the plaintext result the other person's app sends alongside is not relied on.",
                "**Identifier:** the proofs usually carry an identifier derived from the passport data, the domain and the purpose, which stays the same for the same domain and purpose and can recognize the same passport when it is presented again; it is not the passport number, but it is linkable information and should be handled with care. " +
                "Salted identifiers are accepted only with the OPRF key of this app's server.",
                "**Domain and requester identity:** the domain in a request is entered by the requester, and the other person's app shows it but cannot confirm it; when verifying, this app only confirms that the proofs were made for that domain, which does not mean that anyone's real identity has been confirmed.",
                "**Scope of trust:** verification confirms that the proofs match the certificate tree and circuits in the zkPassport registry; when the issuing country's CSCA is also among this app's trust anchors, a higher trust is shown. A zero-knowledge proof only guarantees properties under a particular circuit, and **does not mean that any identity or claim is recognized by a government**.",
                "**Test mode:** accepts proofs from zkPassport test passports and uses the test network registry; results are marked as tests and should not be used for real checks.",
                "**Service availability:** third parties may change or stop their services under their own rules; when a service or node cannot be reached, verification fails rather than skipping a check.",
            ),
        )
        section(
            "What you provide when answering requests and its limits",
            list(
                "**What is sent:** the requester receives the proofs and their public inputs: the disclosed fields the consent screen lists, whether each condition holds (for example that you are at least a certain age, not your date of birth), bound data, and an identifier that stays the same for the requester's domain and purpose. " +
                "A requester with the same domain and purpose can use the identifier to recognize the same passport presented again; identifiers differ between domains.",
                "**What is not sent:** the raw chip data, fields that are not listed and the passport photo itself are not sent to the requester; when the proofs are made on this device, making them does not send passport data to any server; when you choose your own prover, the SOD and DG1 go only to the prover you chose.",
                "**The requester's identity cannot be confirmed:** the domain, service name, purpose and logo are entered by the requester; the origin the relay service reports only shows which site the link was opened from, and does not mean that the requester's real identity or purpose has been confirmed. Answer only requests you trust.",
                "**Unsupported passports:** the signature algorithms of some passports are not supported by zkPassport's circuits yet; this app then tells the requester that the passport is not supported and sends nothing else.",
                "**Records:** this app keeps, in the history on the device, the requester's domain and origin, the file name of the passport used, what the proofs established and (when your own prover is used) its address, but not the proofs themselves; you can delete the history in the app.",
                "**Test requests:** when a request is marked as a test, the requester accepts test passports and uses the test network registry.",
            ),
        )
        section(
            "Unofficial compatible implementation",
            p("This app has no cooperation, certification, authorization, agency or endorsement relationship with zkPassport or its operators. The compatible features are implemented from its public and suitably licensed code, circuits and interfaces; an open-source licence does not necessarily grant permission to use third-party online services or a trademark licence. " +
                "The zkPassport name is used only to identify the supported protocol or service."),
        )
        section(
            "After declining or withdrawing",
            list(
                "This app does not connect to the zkPassport relay service, circuit and certificate package downloads, Ethereum nodes or the online verification service for this integration, and the zkPassport feature of the verify tab shows that it is not enabled; opening a zkPassport request link shows this statement first.",
                "Independent e-passport NFC reading, local signature verification and document keeping are not disabled by declining this.",
            ),
        )
        section(
            "Consent and withdrawal",
            p("Choosing \"Accept and enable\" means that you understand how the third parties above handle data, and choose to use this app's zkPassport verification and answering; each answer still needs your confirmation on the consent screen. You can withdraw under Settings > Legal and consent to stop further requests; " +
                "data sent earlier, completed verifications or answers, and the records of third parties or requesters are not deleted automatically by withdrawal."),
        )
    }

    val statements: List<IntegrationStatement> = listOf(
        IntegrationStatement(Integration.TWDIW, "TWDIW digital wallet", "Ministry of Digital Affairs", twdiw),
        IntegrationStatement(Integration.MS_VERIFIED_ID, "Microsoft Verified ID", "Microsoft", msVerifiedId),
        IntegrationStatement(Integration.MOBILE_MOICA, "Mobile citizen digital certificate", "Ministry of the Interior", mobileMoica),
        IntegrationStatement(Integration.MYDATA, "MyData", "Ministry of Digital Affairs", myData),
        IntegrationStatement(Integration.ZKPASSPORT, "zkPassport", "zkPassport", zkPassport),
    )

    val set = LegalTextSet(EN, DEVELOPER, terms, privacy, statements)
}
