package diw.wallet.app.android

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.text.StaticLayout
import android.text.TextPaint
import android.text.TextUtils
import androidx.compose.ui.graphics.asAndroidBitmap
import diw.wallet.app.CardArtSpec
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.bluetooth.BluetoothManager
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.view.WindowManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.browser.customtabs.CustomTabsIntent
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import com.google.android.gms.identitycredentials.RegisterCreationOptionsRequest
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import com.google.android.gms.identitycredentials.RegistrationRequest
import com.google.android.gms.tasks.Task
import diw.wallet.app.DcApiRegistration
import diw.wallet.app.BondsLinkPeripheral
import diw.wallet.app.ExternalKeys
import diw.wallet.app.KeyBackend
import diw.wallet.app.KeyProtection
import diw.wallet.app.NfcReaderList
import diw.wallet.app.PickedFile
import diw.wallet.app.PinOrPlatformUnlock
import diw.wallet.app.PlatformServices
import diw.wallet.app.WalletModel
import diw.wallet.app.softwareBackend
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.storage.EncryptedStorage
import diw.wallet.core.storage.ValueCipher
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.crypto.Algorithm
import org.multipaz.digitalcredentials.DigitalCredentials
import org.multipaz.digitalcredentials.getDefault
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.Logger
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.Reason
import org.multipaz.securearea.AndroidKeystoreCreateKeySettings
import org.multipaz.securearea.AndroidKeystoreDefaultKeyUnlockDataProvider
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.UserAuthenticationType
import org.multipaz.storage.Storage
import org.multipaz.storage.android.AndroidStorage
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.time.Clock
import diw.wallet.core.document.sign.CleartextHttp
import diw.wallet.core.document.sign.KtorSignedDataHttp
import diw.wallet.core.document.sign.SignedDataHttp
import diw.wallet.core.document.sign.SignedDataRoutes
import kotlin.time.Duration

/** AES-256-GCM with a non-exportable Android Keystore key; output is iv(12) || ciphertext || tag. */
class KeystoreValueCipher(private val alias: String = "diw-storage-v1") : ValueCipher {
    private val key: SecretKey by lazy {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            generateKey()
        }
    }

    override suspend fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        c.updateAAD(aad)
        return c.iv + c.doFinal(plaintext)
    }

    override suspend fun decrypt(ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, ciphertext, 0, 12))
        c.updateAAD(aad)
        return c.doFinal(ciphertext, 12, ciphertext.size - 12)
    }
}

class AndroidPlatform(private val context: Context) : PlatformServices {
    override val platformName = "Android ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})"
    override val oid4vciRedirectUri = "diw-wallet://oid4vci/callback"

    /** Prompt model of the activity in the foreground; biometric prompts need one. */
    @Volatile var promptModel: AndroidPromptModel? = null

    /** The activity in the foreground, for window flags and permission requests. */
    @Volatile var activity: Activity? = null

    override val bondsLink: BondsLinkPeripheral by lazy { AndroidBondsLink(context) { activity } }

    /** File picking and saving through the activity's result launchers; set while MainActivity exists. */
    @Volatile var fileAccess: AndroidFileAccess? = null

    override suspend fun pickFile(): PickedFile? = fileAccess?.pick()

    override suspend fun pickImage(): PickedFile? = fileAccess?.pick(arrayOf("image/*"))

    override suspend fun pickFiles(): List<PickedFile> = fileAccess?.pickMany().orEmpty()

    override suspend fun saveFile(name: String, mediaType: String, bytes: ByteArray): Boolean = fileAccess?.save(name, mediaType, bytes) ?: false

    override val embeddedBrowser: Boolean get() = true

    override suspend fun renderPdf(bytes: ByteArray, maxPages: Int, widthPx: Int): List<ImageBitmap> = withContext(Dispatchers.IO) {
        // PdfRenderer reads a seekable file descriptor; the copy lives in the app's cache only while it draws.
        val file = java.io.File.createTempFile("preview", ".pdf", context.cacheDir)
        try {
            file.writeBytes(bytes)
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { fd ->
                PdfRenderer(fd).use { renderer ->
                    (0 until minOf(maxPages, renderer.pageCount)).map { i ->
                        renderer.openPage(i).use { page ->
                            val height = (widthPx.toLong() * page.height / maxOf(page.width, 1)).toInt().coerceIn(1, widthPx * 4)
                            val bitmap = Bitmap.createBitmap(widthPx, height, Bitmap.Config.ARGB_8888)
                            bitmap.eraseColor(android.graphics.Color.WHITE)
                            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            bitmap.asImageBitmap()
                        }
                    }
                }
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Logger.w(TAG, "PDF preview failed", e)
            emptyList()
        } finally {
            file.delete()
        }
    }

    override suspend fun renderCardArt(spec: CardArtSpec): ByteArray? = withContext(Dispatchers.Default) {
        val w = CardArtSpec.WIDTH
        val h = CardArtSpec.HEIGHT
        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        val card = Path().apply { addRoundRect(RectF(0f, 0f, w.toFloat(), h.toFloat()), 36f, 36f, Path.Direction.CW) }
        canvas.clipPath(card)
        canvas.drawColor(spec.background)
        val pad = 32f
        // An issuer card face covers the card (centre crop) as in the official TWDIW wallet; shades at the top and the
        // bottom keep the title and the issuer readable on any image, so the text is always white.
        val face = spec.face?.asAndroidBitmap()
        if (face != null) {
            val scale = maxOf(w.toFloat() / face.width, h.toFloat() / face.height)
            val sw = (w / scale).toInt().coerceAtMost(face.width)
            val sh = (h / scale).toInt().coerceAtMost(face.height)
            val src = Rect((face.width - sw) / 2, (face.height - sh) / 2, (face.width + sw) / 2, (face.height + sh) / 2)
            canvas.drawBitmap(face, src, RectF(0f, 0f, w.toFloat(), h.toFloat()), Paint(Paint.FILTER_BITMAP_FLAG))
            val shade = 0x8C000000.toInt()
            canvas.drawRect(0f, 0f, w.toFloat(), h * 0.45f, Paint().apply {
                shader = LinearGradient(0f, 0f, 0f, h * 0.45f, shade, 0, Shader.TileMode.CLAMP)
            })
            canvas.drawRect(0f, h * 0.7f, w.toFloat(), h.toFloat(), Paint().apply {
                shader = LinearGradient(0f, h * 0.7f, 0f, h.toFloat(), 0, shade, Shader.TileMode.CLAMP)
            })
        }
        val foreground = if (face != null) android.graphics.Color.WHITE else spec.foreground
        // The picture (a document page or a portrait) fills the right part of the card and fades into the background.
        val textRight = spec.picture?.takeIf { face == null }?.asAndroidBitmap()?.let { pic ->
            val left = w * 0.6f
            val area = RectF(left, 0f, w.toFloat(), h.toFloat())
            val scale = maxOf(area.width() / pic.width, area.height() / pic.height)
            val sw = area.width() / scale
            val src = Rect(((pic.width - sw) / 2).toInt().coerceAtLeast(0), 0, ((pic.width + sw) / 2).toInt().coerceAtMost(pic.width),
                (area.height() / scale).toInt().coerceAtMost(pic.height))
            canvas.drawBitmap(pic, src, area, Paint(Paint.FILTER_BITMAP_FLAG))
            val fade = Paint().apply {
                shader = LinearGradient(left, 0f, left + 96f, 0f, spec.background, spec.background and 0x00FFFFFF, Shader.TileMode.CLAMP)
            }
            canvas.drawRect(left, 0f, left + 96f, h.toFloat(), fade)
            left - 8f
        } ?: (w - pad)
        var top = pad
        spec.logo?.takeIf { face == null }?.asAndroidBitmap()?.let { logo ->
            val size = 72f
            val scale = size / maxOf(logo.width, logo.height)
            val dst = RectF(pad, pad, pad + logo.width * scale, pad + logo.height * scale)
            canvas.save()
            canvas.clipPath(Path().apply { addRoundRect(dst, 12f, 12f, Path.Direction.CW) })
            canvas.drawBitmap(logo, null, dst, Paint(Paint.FILTER_BITMAP_FLAG))
            canvas.restore()
            top = pad + size + 20f
        }
        val width = (textRight - pad).toInt().coerceAtLeast(120)
        val titlePaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            color = foreground
            textSize = 44f
            typeface = Typeface.DEFAULT_BOLD
        }
        val title = StaticLayout.Builder.obtain(spec.title, 0, spec.title.length, titlePaint, width)
            .setMaxLines(if (top > pad) 2 else 3).setEllipsize(TextUtils.TruncateAt.END).build()
        canvas.save()
        canvas.translate(pad, top)
        title.draw(canvas)
        canvas.restore()
        val issuerPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            color = (foreground and 0x00FFFFFF) or (0xD9 shl 24)
            textSize = 26f
        }
        val issuer = TextUtils.ellipsize(spec.issuer, issuerPaint, width.toFloat(), TextUtils.TruncateAt.END).toString()
        canvas.drawText(issuer, pad, h - pad - 8f, issuerPaint)
        spec.badge?.let { badge ->
            val badgePaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply { color = android.graphics.Color.WHITE; textSize = 24f; typeface = Typeface.DEFAULT_BOLD }
            val bw = badgePaint.measureText(badge) + 28f
            val box = RectF(w - pad - bw, pad, w - pad, pad + 40f)
            canvas.drawRoundRect(box, 20f, 20f, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFFC2410C.toInt() })
            canvas.drawText(badge, box.left + 14f, box.bottom - 12f, badgePaint)
        }
        java.io.ByteArrayOutputStream().use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        }
    }

    override val externalKeys: ExternalKeys by lazy { AndroidKeys(context) { activity } }

    override val mobileMoicaReturnUrl = "diw-wallet://moica/return"

    override fun openExternal(url: String): Boolean = try {
        val intent = if (url.startsWith("intent:")) Intent.parseUri(url, Intent.URI_INTENT_SCHEME).addCategory(Intent.CATEGORY_BROWSABLE).setComponent(null)
        else Intent(Intent.ACTION_VIEW, Uri.parse(url))
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (_: android.content.ActivityNotFoundException) {
        false
    } catch (_: java.net.URISyntaxException) {
        false
    }

    @Volatile private var nfcPresentationActive = false

    override fun nfcPresentationUnavailableReason(): String? {
        val adapter = NfcAdapter.getDefaultAdapter(context) ?: return "此裝置沒有 NFC"
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) return "此裝置不支援 NFC 卡片模擬"
        if (!adapter.isEnabled) return "NFC 未開啟，請到系統設定開啟"
        return null
    }

    override suspend fun proximityTransportUnavailableReason(): String? {
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter ?: return "此裝置沒有藍牙"
        val needed = if (android.os.Build.VERSION.SDK_INT >= 31) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
        } else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        val missing = needed.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) {
            activity?.let { a -> a.runOnUiThread { a.requestPermissions(missing.toTypedArray(), PROXIMITY_PERMISSION_REQUEST) } }
            return "請允許「附近的裝置」權限"
        }
        if (!adapter.isEnabled) return "藍牙未開啟"
        return null
    }

    override fun setNfcPresentationActive(active: Boolean) {
        nfcPresentationActive = active
        val a = activity ?: return
        a.runOnUiThread { if (active) applyNfcPreference(a) else releaseNfcPreference(a) }
    }

    /** The reader mode of an in-person verification in progress; Android ends reader mode when the activity pauses. */
    @Volatile var readerMode: ((Activity) -> Unit)? = null

    override suspend fun nfcReaders(): NfcReaderList = AndroidNfcReaders.list(context, this)

    /**
     * While the proximity screen is open, taps go to this wallet rather than another wallet with the same AIDs; while
     * a verification waits for a tap, reader mode is turned on again.
     */
    fun applyNfcPreference(a: Activity) {
        readerMode?.let { enable -> runCatching { enable(a) } }
        if (!nfcPresentationActive) return
        val adapter = NfcAdapter.getDefaultAdapter(context) ?: return
        runCatching { CardEmulation.getInstance(adapter).setPreferredService(a, ComponentName(context, WalletNfcService::class.java)) }
    }

    fun releaseNfcPreference(a: Activity) {
        val adapter = NfcAdapter.getDefaultAdapter(context) ?: return
        runCatching { CardEmulation.getInstance(adapter).unsetPreferredService(a) }
    }

    override fun keepScreenOn(on: Boolean) {
        val a = activity ?: return
        a.runOnUiThread {
            val attrs = a.window.attributes
            if (on) {
                a.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                attrs.screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL
            } else {
                a.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                attrs.screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE
            }
            a.window.attributes = attrs
        }
    }

    private val deviceSecure: Boolean
        get() = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true

    override suspend fun openStorage(): Storage = withContext(Dispatchers.IO) {
        val file = File(context.noBackupFilesDir, "diw-wallet-v1.db")
        EncryptedStorage(AndroidStorage(file.absolutePath), KeystoreValueCipher())
    }

    override suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?): List<KeyBackend> {
        val keystore = AndroidKeystoreSecureArea.create(storage)
        val software = softwareBackend(storage, pinPrompt)
        val secure = deviceSecure
        fun hw(strongBox: Boolean) = KeyBackend(keystore, if (strongBox) KeyProtection.STRONGBOX else KeyProtection.TEE) { challenge, userAuth ->
            AndroidKeystoreCreateKeySettings.Builder(attestationChallenge(challenge))
                .setUseStrongBox(strongBox)
                .apply {
                    // Without a screen lock Android cannot bind keys to the user; such keys are not created (software takes over).
                    if (userAuth) setUserAuthenticationRequired(true, Duration.ZERO, setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC))
                }
                .build()
        }
        val hardware = buildList {
            if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) add(hw(true))
            add(hw(false))
        }
        // No screen lock: user-bound hardware keys are impossible, so new credentials use App PIN software keys first.
        return if (secure) hardware + software else listOf(software) + hardware
    }

    /**
     * KeyMint rejects attestation challenges over 128 bytes (INVALID_INPUT_LENGTH, surfacing as "Error creating key");
     * longer issuer nonces, such as the 720-byte JWE c_nonce of issuer.eudiw.dev, are bound by their SHA-256 instead.
     */
    private fun attestationChallenge(challenge: ByteString): ByteString =
        if (challenge.size <= MAX_ATTESTATION_CHALLENGE) challenge else ByteString(PlatformCrypto.sha256(challenge.toByteArray()))

    override fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider =
        PinOrPlatformUnlock(pinPrompt, object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(secureArea: SecureArea, alias: String, algorithm: Algorithm, unlockReason: Reason): KeyUnlockData {
                val pm = promptModel ?: throw KeyLockedException("請先開啟錢包畫面再進行驗證")
                return withContext(pm) { AndroidKeystoreDefaultKeyUnlockDataProvider.getKeyUnlockData(secureArea, alias, algorithm, unlockReason) }
            }
        })

    override fun httpClient(): HttpClient = HttpClient(OkHttp) { followRedirects = false }

    // The release network security configuration refuses clear text; http time stamps, OCSP, CRLs and AIA
    // certificates go through a plain socket instead, since each reply is checked by its signature.
    override fun signedDataHttp(http: HttpClient): SignedDataHttp = SignedDataRoutes(KtorSignedDataHttp(http), CleartextHttp())

    /**
     * Opens an issuer, sign-in or application page in a Custom Tab inside the wallet's own task, above MainActivity.
     * These pages end with a deep link back to the wallet (OpenID4VCI callback, TWDIW offer, Verified ID sign-in);
     * MainActivity is singleTask, so bringing it back finishes the tab above it and the page closes by itself. A tab
     * started in a new task would stay open behind the wallet, so that is only the fallback when no activity is shown.
     */
    override fun openBrowser(url: String) {
        val tab = CustomTabsIntent.Builder().setShowTitle(true).build()
        val host = activity?.takeIf { !it.isFinishing && !it.isDestroyed }
        if (host != null) {
            // Callers may be on a background coroutine (the authorization code flow); activities start on the UI thread.
            host.runOnUiThread { tab.launchUrl(host, Uri.parse(url)) }
        } else {
            tab.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            tab.launchUrl(context, Uri.parse(url))
        }
    }

    override fun openRedirect(url: String) {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    private val dcApiLock = Mutex()

    override suspend fun registerDigitalCredentials(model: WalletModel, force: Boolean) = dcApiLock.withLock {
        // The system picker shows each credential with its card art; credentials without one get it first.
        runCatching { model.ensureCardArt() }.onFailure { if (it is CancellationException) throw it; Logger.w(TAG, "Card art failed", it) }
        val now = Clock.System.now()
        model.dcApiRegistration.value = try {
            val dc = DigitalCredentials.getDefault()
            if (!dc.registerAvailable) {
                DcApiRegistration(0, notListable(model), emptySet(), "此裝置沒有提供 Digital Credentials API 註冊", now)
            } else {
                // OpenID4VP goes through the DIW request validation layer and org-iso-mdoc (ISO/IEC 18013-7 Annex C) through
                // the wallet's mdoc consent; both use the wallet's own screens.
                val protocols = dc.supportedProtocols.filter { it.startsWith("openid4vp") || it == "org-iso-mdoc" }.toSet()
                dc.register(model.documentStore, model.documentTypes, protocols, force)
                // Multipaz only logs the system's answer and remembers the data as registered either way, so the
                // Digital Credentials entry is registered again here and the answer awaited.
                val appName = context.applicationInfo.loadLabel(context.packageManager).toString()
                val database = credentialDatabase(appName, model, protocols)
                val matcher = withContext(Dispatchers.IO) { context.assets.open(MATCHER_ASSET).use { it.readBytes() } }
                IdentityCredentialManager.getClient(context)
                    .registerCredentials(RegistrationRequest(Cbor.encode(database), matcher, DIGITAL_CREDENTIAL_TYPE, "", emptyList()))
                    .awaitResult()
                val issuance = runCatching { registerIssuance(appName) }
                    .onFailure { if (it is CancellationException) throw it; Logger.e(TAG, "Digital Credentials issuance registration failed", it) }
                val entries = database["credentials"].asArray
                DcApiRegistration(
                    entries.size, notListable(model), protocols, null, now,
                    issuance = issuance.isSuccess, issuanceError = issuance.exceptionOrNull()?.let { it.message ?: it::class.simpleName },
                    entries = entries.map { describeEntry(it) },
                )
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Logger.e(TAG, "Digital Credentials registration failed", e)
            DcApiRegistration(0, runCatching { notListable(model) }.getOrDefault(0), emptySet(), e.message ?: e::class.simpleName, now)
        }
    }

    /**
     * Lets web pages and apps save credentials into the wallet (navigator.credentials.create with OpenID4VCI): the
     * creation entry the system lists, and the CMWallet issuance matcher that shows it for openid4vci-v1 and
     * openid4vci1.0 requests. Requests arrive at DcApiActivity with the CREATE_CREDENTIAL action.
     */
    private suspend fun registerIssuance(appName: String) {
        val matcher = withContext(Dispatchers.IO) { context.assets.open(ISSUANCE_MATCHER_ASSET).use { it.readBytes() } }
        val options = creationOptions(appName, "存入 $appName", launcherIconPng())
        IdentityCredentialManager.getClient(context)
            .registerCreationOptions(RegisterCreationOptionsRequest(options, matcher, DIGITAL_CREDENTIAL_TYPE, ISSUANCE_ID, ""))
            .awaitResult()
    }

    /** The issuance matcher's data: a little-endian offset to the JSON, the icon, then the JSON naming the entry and its icon. */
    private fun creationOptions(title: String, subtitle: String, icon: ByteArray): ByteArray {
        val json = buildJsonObject {
            put("display", buildJsonObject {
                put("title", JsonPrimitive(title))
                put("subtitle", JsonPrimitive(subtitle))
                put("icon", buildJsonObject { put("start", JsonPrimitive(4)); put("length", JsonPrimitive(icon.size)) })
            })
        }.toString().encodeToByteArray()
        val offset = 4 + icon.size
        val head = byteArrayOf(offset.toByte(), (offset shr 8).toByte(), (offset shr 16).toByte(), (offset shr 24).toByte())
        return head + icon + json
    }

    /** The launcher icon as a 96 x 96 PNG for the system's entry. */
    private fun launcherIconPng(): ByteArray {
        val drawable = context.packageManager.getApplicationIcon(context.applicationInfo)
        val bitmap = Bitmap.createBitmap(96, 96, Bitmap.Config.ARGB_8888)
        drawable.setBounds(0, 0, 96, 96)
        drawable.draw(Canvas(bitmap))
        return java.io.ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
    }

    /**
     * The credential database multipaz-dcapi registers, in the format its matcher reads. The library keeps
     * calculateCredentialDatabase internal, so it is called through its JVM signature (the class is kept by R8).
     */
    private suspend fun credentialDatabase(appName: String, model: WalletModel, protocols: Set<String>): DataItem {
        val method = Class.forName("org.multipaz.digitalcredentials.DigitalCredentialsExt_androidKt").getMethod(
            "calculateCredentialDatabase", String::class.java, DocumentStore::class.java, DocumentTypeRepository::class.java,
            Set::class.java, Continuation::class.java,
        )
        return suspendCoroutineUninterceptedOrReturn<Any?> { c ->
            try {
                method.invoke(null, appName, model.documentStore, model.documentTypes, protocols, c)
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }
        } as DataItem
    }

    /**
     * One registered credential as the matcher reads it, so the holder can see why a request finds nothing (a
     * different doctype or vct, or no claims when the wallet could not read them).
     */
    private fun describeEntry(item: DataItem): String {
        val title = item.getOrNull("title")?.asTstr ?: "證件"
        item.getOrNull("mdoc")?.let { mdoc ->
            val claims = mdoc.getOrNull("namespaces")?.asMap?.values?.sumOf { it.asMap.size } ?: 0
            return "$title：mdoc ${mdoc.getOrNull("docType")?.asTstr.orEmpty()}，$claims 個欄位"
        }
        item.getOrNull("sdjwt")?.let { sdJwt ->
            val claims = sdJwt.getOrNull("claims")?.asMap?.size ?: 0
            return "$title：SD-JWT VC ${sdJwt.getOrNull("vct")?.asTstr.orEmpty()}，$claims 個欄位"
        }
        return title
    }

    /** Documents held only as W3C VCs: the platform matcher offers mdoc and SD-JWT VC credentials only. */
    private suspend fun notListable(model: WalletModel): Int = model.documentStore.listDocuments().count { doc ->
        doc.getCertifiedCredentials().none { it is MdocCredential || it is SdJwtVcCredential }
    }

    private suspend fun <T> Task<T>.awaitResult(): T = suspendCancellableCoroutine { c ->
        addOnSuccessListener { c.resume(it) }
        addOnFailureListener { c.resumeWithException(it) }
    }

    private companion object {
        const val TAG = "AndroidPlatform"
        /** Matcher shipped in multipaz-dcapi; the system runs it against each request to list matching credentials. */
        const val MATCHER_ASSET = "identitycredentialmatcher.wasm"
        const val DIGITAL_CREDENTIAL_TYPE = "androidx.credentials.TYPE_DIGITAL_CREDENTIAL"
        /** Issuance matcher from the CMWallet sample (Apache-2.0, matcher/issuance/provision.c). */
        const val ISSUANCE_MATCHER_ASSET = "openid4vci_provision.wasm"
        const val ISSUANCE_ID = "openid4vci"
        const val MAX_ATTESTATION_CHALLENGE = 128
        const val PROXIMITY_PERMISSION_REQUEST = 7302
    }
}
