# Microsoft Entra Verified ID Statement

Version 1, effective 2026-11-05

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- Microsoft Entra Verified ID is a credential service provided by Microsoft; the organizations involved may also take part in issuing, verifying and keeping data.
- This app handles Verified ID requests according to public documents and compatible protocols; **it is not Microsoft Authenticator and is not certified, authorized or endorsed by Microsoft**.
- In the current design, Verified ID compatible cards share the holder key and identifying information, and presentation records may be linked by different verifiers.
- Declining disables Verified ID receiving, presentation and status lookups, while stored cards are kept; general standard protocol features are not affected.

## 1. Service

Microsoft Entra Verified ID is a Microsoft service for organizations to issue and verify verifiable credentials. Once you enable it, this app can receive cards issued by organizations through compatible `openid-vc` links or QR codes, including signing in to the organization, entering self-asserted fields or presenting other cards as the flow requires, and can answer verification requests that use the Verified ID service.

## 2. Operators and data transfers

- **Receiving:** requests and responses may pass through Microsoft's Verified ID cloud service and the organization's systems, and may contain the holder DID, public key, authorization tokens, self-asserted fields and other cards or proofs you choose to provide.
- **Presenting:** may send the selected credentials and fields, the holder DID, signatures and necessary protocol information to Microsoft's services and the verifying organization.
- **Identity and DID resolution:** this app may read the Linked Domains configuration and DID documents of the organization's domain; to resolve `did:ion`, it may send DID lookups to Microsoft resolution endpoints (such as `discover.did.msidentity.com`).
- **Status lookups:** where the service requires it, this app may query the revocation status of credentials from Microsoft or the organization.

Microsoft and each organization handle the data they actually receive under their own service terms and privacy policies; when connecting, they may obtain your IP address, the time of the connection and related identifying information.

## 3. Service and traceability risks

- Microsoft and the organizations involved may learn when receiving or verification requests take place and with whom; if the service changes or stops, presenting or verifying may no longer be possible.
- Credentials can be revoked by the authorized issuing organization; their status depends on the data and lookup results the service provides.
- In the current compatible design, several Verified ID cards share the holder key; the same DID or re-identifiable information may let verifiers link presentations across contexts. Disclosing only selected fields does not guarantee anonymity.

## 4. Unofficial compatible implementation

This app is an independently developed compatible tool, not Microsoft Authenticator, and has no affiliation, cooperation, certification, authorization or endorsement relationship with Microsoft. Names or trademarks such as Microsoft, Entra, Verified ID and Microsoft Authenticator belong to their owners; this app mentions them only to identify the service and describe interoperability.

The protocols or security requirements may change, and Microsoft or organizations may refuse this app's unofficial implementation; the developer does not guarantee that every request works.

## 5. After declining or withdrawing

- This app does not handle Verified ID `openid-vc` card links, QR codes or the specific presentation requests, and does not connect to Microsoft's Verified ID service for this integration.
- Stored Verified ID cards are not deleted, but no automatic status lookups are made for them through this integration.
- General standard requests such as OpenID4VP still work; any independent DID resolution or trust lookup feature follows its general data flows and settings, and disabling this integration should not be read as blocking all Microsoft domains.

## 6. Consent and withdrawal

"Accept and enable" means that you understand the cross-service transfers, unofficial compatibility and identification linkability risks above and choose to use this integration. You can withdraw under Settings > Legal and consent to stop further requests of this integration; interactions sent or completed before withdrawal do not become invalid and are not deleted automatically from Microsoft or organization systems. Other features of the app keep working.
