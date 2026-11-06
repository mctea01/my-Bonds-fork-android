# MyData Statement

Version 1, effective 2026-11-05

> This English text is a translation of the Traditional Chinese original. If the two differ, the Chinese text prevails.

## Key points

- The MyData personal data self-use platform is currently built, run and managed by the **Ministry of Digital Affairs**; individual data is the responsibility of the authorities or organizations that provide it.
- This app opens the MyData web pages in the in-app browser, can help fill in the national ID number and date of birth you choose to keep, and downloads, extracts and keeps the documents.
- The identity verification, consent and download requests you complete on the MyData web pages are handled by MyData and the data providers under their rules; this app cannot delete records those third parties already hold.
- This app is not published, certified or endorsed by the Ministry of Digital Affairs or the data providers; declining disables only the MyData integration, and stored documents and derived credentials are kept.

## 1. Features and users

MyData (the personal data self-use platform) lets users obtain personalized documents provided by authorities or organizations after identity verification and consent. Once enabled, you can use the MyData entry this app provides under Documents > Get from a website to sign in on MyData's own website and download the household registration, tax, labour and health insurance and other documents available to you; some documents can be used to make derived credentials compatible with the Bonds format yourself.

A derived credential is a statement you produce yourself, not a national ID card or official digital credential issued by a government authority.

## 2. Operators, data flows and retention

- **Operator:** the MyData platform is currently built, run and managed by the Ministry of Digital Affairs; the document content is provided by each data-providing authority or organization. The related identity verification and data use records are handled under the policies of the platform and each authority.
- **Signing in in the browser:** this app opens the MyData web pages in the in-app browser; the citizen digital certificate, mobile citizen digital certificate or other verification method you choose on the pages, and the consent, applications and data handling on the pages, are the responsibility of the websites or services concerned.
- **Autofill on the device:** if you choose to keep your national ID number and date of birth, the current design lets this app fill them into the matching MyData pages for the MyData web pages to process, and use the national ID number to open protected PDFs after download. This setting does not make this app send the data to any website other than MyData.
- **Document download:** this app can extract the ZIP downloaded from MyData on the device, keep the supported PDF documents in it, and delete the ZIP file after extraction. Documents you export separately are not controlled by the app's delete operations.

MyData, the data providers or their contracted services can learn your sign-in, application and access times, IP address and the related data types; check the retention periods in the service terms and privacy policy the platform publishes at the time.

## 3. Privacy and feature risks

- The MyData platform and the data-providing authorities may keep the necessary usage records; withdrawing this consent in this app does not delete third-party records retroactively.
- The autofill on the device uses sensitive identifiers such as the national ID number and date of birth; protect your device and app PIN well, and remove the saved autofill data when you no longer need it.
- When the MyData web pages, sign-in rules, download formats or ZIP or PDF protection change, autofill, extraction or document parsing may fail; the document content and its legal uses are governed by the original providing authority and the relevant regulations.
- Downloaded household registration, income, health insurance and similar documents may contain highly sensitive information; if you then present, share or make proofs from them with other features, the disclosure risk depends on that specific operation.

## 4. Unofficial compatible implementation

This app has no affiliation, cooperation, certification, authorization or endorsement relationship with the Ministry of Digital Affairs or the data-providing authorities. The website navigation, autofill help and download parsing are a compatible implementation of the public website's flow; this does not mean that MyData authorizes this app as an official integration, nor does it guarantee that it keeps working after the website changes. The MyData name is used only to identify the service connected to.

## 5. After declining or withdrawing

- The MyData entry under Get documents and the integration that makes ID cards from MyData documents are disabled, and this app does not open the MyData web pages for this feature.
- The national ID number and date of birth saved earlier stay on the device but are no longer used for this autofill; you can delete them under Settings > Documents and signatures.
- Downloaded documents and the derived credentials and ID cards you produced are not deleted automatically, and other document features are not affected.

## 6. Consent and withdrawal

Choosing "Accept and enable" means that you understand how the MyData platform and the data providers each handle data, and choose to use this app's integration; **this does not replace any identity verification or data provision consent required on the MyData web pages each time**. You can withdraw under Settings > Legal and consent to stop further requests of this integration; documents downloaded before withdrawal and operations completed by third parties do not become invalid and are not deleted automatically.
