package com.artemchep.keyguard.android

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import com.artemchep.keyguard.common.io.bind
import com.artemchep.keyguard.common.model.AddPrivilegedAppRequest
import com.artemchep.keyguard.common.model.DPrivilegedApp
import com.artemchep.keyguard.common.service.crypto.CryptoGenerator
import com.artemchep.keyguard.common.service.gpmprivapps.PrivilegedAppsService
import com.artemchep.keyguard.common.service.tld.TldService
import com.artemchep.keyguard.util.webauthn.WebAuthnRpIdValidator
import com.artemchep.keyguard.util.webauthn.canonicalizeWebAuthnRpId
import com.artemchep.keyguard.util.webauthn.isValidCanonicalWebAuthnRpId
import io.ktor.client.HttpClient
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import java.lang.IllegalStateException

class PasskeyUtils(
    private val cryptoService: CryptoGenerator,
    privilegedAppsService: PrivilegedAppsService,
    tldService: TldService,
    httpClient: HttpClient,
) {
    companion object {
        // WebAuthn PRF 规定的上下文标签，末尾必须包含一个零字节。
        internal val PRF_LABEL = "WebAuthn PRF\u0000".toByteArray(Charsets.UTF_8)

        /**
         * The minimum time the 'passkey is doing work' screen should
         * be shown. This is needed just to make to user interface less
         * junky.
         */
        private const val PASSKEY_PROCESSING_MIN_TIME_MS = 800L

        suspend fun <T> withProcessingMinTime(
            block: suspend () -> T,
        ): T = coroutineScope {
            val artificialDelayDeferred = async {
                delay(PASSKEY_PROCESSING_MIN_TIME_MS)
            }
            val result = block()
            artificialDelayDeferred.await()
            result
        }
    }

    private val callingAppOriginResolver = AndroidCallingAppOriginResolver(
        cryptoService = cryptoService,
        privilegedAppsService = privilegedAppsService,
    )
    private val webAuthnRpIdValidator = WebAuthnRpIdValidator(
        domainLookup = { host -> tldService.getDomainName(host).bind() },
        httpClient = httpClient,
    )
    private val androidAssetLinksRpBinding = AndroidAssetLinksRpBinding(
        httpClient = httpClient,
    )

    @RequiresApi(Build.VERSION_CODES.P)
    fun callingAppPrivilegedRequest(
        appInfo: CallingAppInfo,
    ): AddPrivilegedAppRequest = callingAppOriginResolver.privilegedRequest(appInfo)

    @RequiresApi(Build.VERSION_CODES.P)
    suspend fun callingAppOrigin(
        appInfo: CallingAppInfo,
        privilegedApps: List<DPrivilegedApp>,
    ): String = callingAppOriginResolver.origin(
        appInfo = appInfo,
        privilegedApps = privilegedApps,
    )

    /**
     * Validates that the origin is known to the relaying party and
     * we can give a response to this request.
     */
    suspend fun requireRpMatchesOrigin(
        rpId: String,
        origin: String,
        packageName: String,
    ): Unit = runCatching {
        val normalizedRpId = webAuthnRpIdValidator.requireValidRpId(rpId)
        when {
            // WebAuthn L3 permits HTTP only for localhost web origins; the
            // web validator below enforces that host restriction.
            // See https://www.w3.org/TR/webauthn-3/#rp-id
            origin.startsWith("https:", ignoreCase = true) ||
                origin.startsWith("http:", ignoreCase = true) ->
                webAuthnRpIdValidator.requireRpMatchesOrigin(
                    rpId = normalizedRpId,
                    origin = origin,
                )

            origin.startsWith("android:", ignoreCase = true) ->
                androidAssetLinksRpBinding.requireRpMatchesOrigin(
                    rpId = normalizedRpId,
                    origin = origin,
                    packageName = packageName,
                )

            else -> throw IllegalStateException("Request origin has an unknown scheme.")
        }
    }.getOrElse {
        val detailMessage = it.localizedMessage
            ?: it.message
        val fullMessage =
            "Failed to verify the relation with the `$rpId` relaying party. $detailMessage" +
                "\n\n" + getGenericServiceFailureMessage(rpId)
        throw IllegalStateException(fullMessage)
    }

    /**
     * Resolves the ceremony RP ID and verifies that the caller is allowed to
     * use it before creating an attestation or assertion.
     *
     * WebAuthn binds every credential operation to an RP ID. For web origins,
     * an explicit RP ID must be equal to, or a registrable domain suffix of,
     * the caller origin's effective domain unless related-origin validation
     * succeeds. This helper performs the local RP ID defaulting step and then
     * delegates to [requireRpMatchesOrigin] for web-origin or Android-origin
     * binding checks.
     *
     * Spec:
     * - https://www.w3.org/TR/webauthn-3/#rp-id
     * - https://www.w3.org/TR/webauthn-3/#sctn-createCredential
     * - https://www.w3.org/TR/webauthn-3/#sctn-discover-from-external-source
     */
    suspend fun resolveAndValidateRpId(
        rpId: String?,
        origin: String,
        packageName: String,
    ): String {
        val resolvedRpId = resolveRpId(
            rpId = rpId,
            origin = origin,
        )
        requireRpMatchesOrigin(
            rpId = resolvedRpId,
            origin = origin,
            packageName = packageName,
        )
        return resolvedRpId
    }

    /**
     * Returns the canonical RP ID that should be used for a WebAuthn request.
     *
     * If the request supplies `rp.id` for create() or `rpId` for get(), the
     * caller-supplied value is canonicalized and returned for later validation.
     * If it is absent, WebAuthn defaults the RP ID to the caller origin's
     * effective domain; this client accepts HTTPS web origins and the
     * WebAuthn `http://localhost[:port]` development exception.
     */
    fun resolveRpId(
        rpId: String?,
        origin: String,
    ): String = webAuthnRpIdValidator.resolveRpId(
        rpId = rpId,
        origin = origin,
    )

    /**
     * Converts an RP ID candidate into the local canonical form used for
     * comparisons, credential lookup, and `rpIdHash` input.
     */
    fun canonicalizeRpId(
        value: String,
    ): String = canonicalizeWebAuthnRpId(value)

    /**
     * Checks whether [rpId] has the canonical RP ID syntax accepted by this
     * client before origin scoping is evaluated.
     */
    fun isValidCanonicalRpId(
        rpId: String,
    ): Boolean = isValidCanonicalWebAuthnRpId(rpId)

    /** 为新凭据生成独立且不可预测的 32 字节 PRF 密钥。 */
    fun generatePrfSecret(): ByteArray = cryptoService.seed(32)

    /** 使用该凭据独立保存的密钥计算 WebAuthn PRF 输出。 */
    fun computePrf(
        prfSecretBytes: ByteArray,
        prfInput: ByteArray,
    ): ByteArray = computeWebAuthnPrf(
        cryptoService = cryptoService,
        prfSecretBytes = prfSecretBytes,
        prfInput = prfInput,
    )

    /** Android 二维码 Hybrid 请求已在 PC 端完成 WebAuthn PRF 输入哈希，禁止再次哈希。 */
    fun computePrfFromHashedInput(
        prfSecretBytes: ByteArray,
        hashedPrfInput: ByteArray,
    ): ByteArray = computeWebAuthnPrfFromHashedInput(
        cryptoService = cryptoService,
        prfSecretBytes = prfSecretBytes,
        hashedPrfInput = hashedPrfInput,
    )

    private fun getGenericServiceFailureMessage(rpId: String): String =
        "This seems to be an issue with the service provider `$rpId`. Please reach out to their support team."
}

/**
 * 软件认证器中的 PRF 计算：先对带上下文标签的输入做 SHA-256，
 * 再以凭据独立保存的随机密钥执行 HMAC-SHA-256。
 */
internal fun computeWebAuthnPrf(
    cryptoService: CryptoGenerator,
    prfSecretBytes: ByteArray,
    prfInput: ByteArray,
): ByteArray {
    val prfSalt = cryptoService.hashSha256(PasskeyUtils.PRF_LABEL + prfInput)
    return cryptoService.hmacSha256(
        key = prfSecretBytes,
        data = prfSalt,
    )
}

/** 对 Hybrid 通道传入的 32 字节已哈希 PRF 输入直接执行凭据级 HMAC。 */
internal fun computeWebAuthnPrfFromHashedInput(
    cryptoService: CryptoGenerator,
    prfSecretBytes: ByteArray,
    hashedPrfInput: ByteArray,
): ByteArray {
    require(hashedPrfInput.size == 32) {
        "Hybrid PRF input must be a 32-byte SHA-256 value."
    }
    return cryptoService.hmacSha256(
        key = prfSecretBytes,
        data = hashedPrfInput,
    )
}
