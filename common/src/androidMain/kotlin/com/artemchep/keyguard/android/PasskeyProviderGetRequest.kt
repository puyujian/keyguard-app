package com.artemchep.keyguard.android

import android.annotation.SuppressLint
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.domerrors.EncodingError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import com.artemchep.keyguard.common.model.DPrivilegedApp
import com.artemchep.keyguard.common.model.DSecret
import com.artemchep.keyguard.common.service.passkey.toWebAuthnCredential
import com.artemchep.keyguard.common.service.text.Base64Service
import com.artemchep.keyguard.common.service.text.decodeOrNull
import com.artemchep.keyguard.util.webauthn.PasskeyBase64
import com.artemchep.keyguard.util.webauthn.PasskeyCredentialId
import com.artemchep.keyguard.util.webauthn.WebAuthnAssertionRequest
import com.artemchep.keyguard.util.webauthn.WebAuthnAuthenticator
import com.artemchep.keyguard.util.webauthn.WebAuthnCallerContext
import com.artemchep.keyguard.util.webauthn.WebAuthnEncodingException
import com.artemchep.keyguard.util.webauthn.WebAuthnNotAllowedException
import com.artemchep.keyguard.util.webauthn.parseWebAuthnAllowedCredentialDescriptors
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

class PasskeyProviderGetRequest(
    private val json: Json,
    private val passkeyUtils: PasskeyUtils,
    private val authenticator: WebAuthnAuthenticator,
    private val base64Service: Base64Service,
) {

    @SuppressLint("RestrictedApi")
    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    suspend fun processGetCredentialsRequest(
        request: ProviderGetCredentialRequest,
        credential: DSecret.Login.Fido2Credentials,
        userVerified: Boolean,
        privilegedApps: List<DPrivilegedApp>,
    ): GetCredentialResponse {
        val opt = request.credentialOptions.first() as GetPublicKeyCredentialOption
        val js = PublicKeyCredentialRequestOptions(opt.requestJson)

        val origin = passkeyUtils.callingAppOrigin(
            appInfo = request.callingAppInfo,
            privilegedApps = privilegedApps,
        )
        val packageName = request.callingAppInfo.packageName
        val rpId = passkeyUtils.resolveAndValidateRpId(
            rpId = requestRpIdOrNull(opt.requestJson),
            origin = origin,
            packageName = packageName,
        )
        val responseJson = mapGetWebAuthnExceptions {
            authenticator.getAssertion(
                request = WebAuthnAssertionRequest(
                    challenge = js.challenge,
                    userVerification = js.userVerification,
                    allowedCredentials = parseWebAuthnAllowedCredentialDescriptors(opt.requestJson, json),
                ),
                context = WebAuthnCallerContext(origin, rpId, packageName),
                credential = credential.toWebAuthnCredential(),
                userVerified = userVerified,
                clientDataHash = opt.clientDataHash,
            )
        }
        val prfEvalInput = resolvePasskeyPrfEvalInput(
            requestJson = opt.requestJson,
            credentialIdBytes = PasskeyCredentialId.encode(credential.credentialId),
            json = json,
        )
        val prfSecretBytes = if (userVerified) {
            decodeStoredPrfSecretOrNull(
                encoded = credential.prfSecret,
                decode = base64Service::decodeOrNull,
            )
        } else {
            null
        }
        val prfExtensionResult = try {
            createGetPasskeyPrfExtensionResult(
                evalInput = prfEvalInput?.evalInput,
                userVerified = userVerified,
                prfSecretBytes = prfSecretBytes,
                computePrf = if (prfEvalInput?.alreadyHashed == true) {
                    passkeyUtils::computePrfFromHashedInput
                } else {
                    passkeyUtils::computePrf
                },
            )
        } finally {
            prfSecretBytes?.fill(0)
        }
        val authenticationResponseJson = withPasskeyPrfExtensionResult(responseJson, prfExtensionResult, json)
        return GetCredentialResponse(PublicKeyCredential(authenticationResponseJson))
    }

    private fun requestRpIdOrNull(
        requestJson: String,
    ): String? {
        val body = json.parseToJsonElement(requestJson) as? JsonObject
            ?: return null
        if (!body.containsKey("rpId")) {
            return null
        }

        val primitive = body["rpId"] as? JsonPrimitive
        return primitive?.contentOrNull.orEmpty()
    }
}

// https://www.w3.org/TR/webauthn-3/#prf-extension
@Serializable
internal data class GetPasskeyPrfRequestOptions(
    val extensions: GetPasskeyExtensions? = null,
)

@Serializable
internal data class GetPasskeyExtensions(
    val prf: GetPasskeyPrfExtension? = null,
    // Android 的二维码 Hybrid 通道无法还原已经在 PC 端哈希的 PRF 输入，
    // 因此会以同样结构的合成扩展交给手机上的凭据提供方。
    val prfAlreadyHashed: GetPasskeyPrfExtension? = null,
)

@Serializable
internal data class GetPasskeyPrfExtension(
    val eval: GetPasskeyPrfEvalInput? = null,
    val evalByCredential: Map<String, GetPasskeyPrfEvalInput> = emptyMap(),
)

@Serializable
internal data class GetPasskeyPrfEvalInput(
    val first: String,
    val second: String? = null,
)

internal data class ResolvedGetPasskeyPrfEvalInput(
    val evalInput: GetPasskeyPrfEvalInput,
    val alreadyHashed: Boolean,
)

/** 优先选择当前 credentialId 对应的 evalByCredential 输入，再回退到通用 eval。 */
internal fun resolvePasskeyPrfEvalInput(
    requestJson: String,
    credentialIdBytes: ByteArray,
    json: Json,
    encodeCredentialId: (ByteArray) -> String = PasskeyBase64::encodeToString,
): ResolvedGetPasskeyPrfEvalInput? {
    val options = runCatching {
        json.decodeFromString<GetPasskeyPrfRequestOptions>(requestJson)
    }.getOrNull()
    val extensions = options?.extensions ?: return null
    val (prf, alreadyHashed) = when {
        extensions.prf != null && extensions.prfAlreadyHashed != null -> return null
        extensions.prf != null -> extensions.prf to false
        extensions.prfAlreadyHashed != null -> extensions.prfAlreadyHashed to true
        else -> return null
    }
    val credentialId = encodeCredentialId(credentialIdBytes)
    val evalInput = prf.evalByCredential[credentialId] ?: prf.eval ?: return null
    return ResolvedGetPasskeyPrfEvalInput(
        evalInput = evalInput,
        alreadyHashed = alreadyHashed,
    )
}

/**
 * 构造认证响应的 PRF 对象。请求存在但凭据是旧数据或未完成用户验证时，
 * 返回空对象，普通通行密钥签名仍然保持成功。
 */
internal fun createGetPasskeyPrfExtensionResult(
    evalInput: GetPasskeyPrfEvalInput?,
    userVerified: Boolean,
    prfSecretBytes: ByteArray?,
    computePrf: (prfSecretBytes: ByteArray, prfInput: ByteArray) -> ByteArray,
    decodeInput: (String) -> ByteArray = PasskeyBase64::decode,
    encodeOutput: (ByteArray) -> String = PasskeyBase64::encodeToString,
): JsonObject? {
    evalInput ?: return null
    return buildJsonObject {
        if (userVerified && prfSecretBytes != null) {
            put("results", buildJsonObject {
                put(
                    "first",
                    computeAndEncodePasskeyPrf(
                        prfSecretBytes = prfSecretBytes,
                        prfInputBase64 = evalInput.first,
                        computePrf = computePrf,
                        decodeInput = decodeInput,
                        encodeOutput = encodeOutput,
                    ),
                )
                evalInput.second?.let { second ->
                    put(
                        "second",
                        computeAndEncodePasskeyPrf(
                            prfSecretBytes = prfSecretBytes,
                            prfInputBase64 = second,
                            computePrf = computePrf,
                            decodeInput = decodeInput,
                            encodeOutput = encodeOutput,
                        ),
                    )
                }
            })
        }
    }
}

internal fun decodeStoredPrfSecretOrNull(
    encoded: String?,
    decode: (String) -> ByteArray?,
): ByteArray? {
    val decoded = encoded?.let(decode) ?: return null
    if (decoded.size == 32) {
        return decoded
    }
    decoded.fill(0)
    return null
}

internal inline fun <T> mapGetWebAuthnExceptions(
    block: () -> T,
): T {
    try {
        return block()
    } catch (e: WebAuthnEncodingException) {
        throw GetPublicKeyCredentialDomException(
            domError = EncodingError(),
            errorMessage = e.message.orEmpty(),
        ).apply {
            initCause(e)
        }
    } catch (e: WebAuthnNotAllowedException) {
        throw GetPublicKeyCredentialDomException(
            domError = NotAllowedError(),
            errorMessage = e.message.orEmpty(),
        ).apply {
            initCause(e)
        }
    }
}
