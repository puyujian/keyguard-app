package com.artemchep.keyguard.android

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
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
import com.artemchep.keyguard.common.service.crypto.CryptoGenerator
import com.artemchep.keyguard.common.service.crypto.PasskeyCrypto
import com.artemchep.keyguard.common.service.crypto.PasskeySignResult
import com.artemchep.keyguard.common.service.crypto.PasskeySignatureAlgorithm
import com.artemchep.keyguard.common.service.text.Base64Service
import com.artemchep.keyguard.common.service.text.decodeOrNull
import com.artemchep.keyguard.common.service.webauthn.PasskeyBase64
import com.artemchep.keyguard.common.service.webauthn.PasskeyCredentialId
import com.artemchep.keyguard.common.service.webauthn.WebAuthnEncodingException
import com.artemchep.keyguard.common.service.webauthn.WebAuthnNotAllowedException
import com.artemchep.keyguard.common.service.webauthn.requireCredentialAllowedByRequestOptions as requireWebAuthnCredentialAllowedByRequestOptions
import com.artemchep.keyguard.common.service.webauthn.requireCredentialRpIdMatchesRequest as requireWebAuthnCredentialRpIdMatchesRequest
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import org.kodein.di.DirectDI
import org.kodein.di.instance

private const val MAX_ENCODED_PASSKEY_KEY_CHARS = 5_464

class PasskeyProviderGetRequest(
    private val context: Context,
    private val json: Json,
    private val base64Service: Base64Service,
    private val cryptoService: CryptoGenerator,
    private val passkeyCrypto: PasskeyCrypto,
    private val passkeyUtils: PasskeyUtils,
) {
    constructor(
        directDI: DirectDI,
    ) : this(
        context = directDI.instance<Application>(),
        json = directDI.instance(),
        base64Service = directDI.instance(),
        cryptoService = directDI.instance(),
        passkeyCrypto = directDI.instance(),
        passkeyUtils = directDI.instance(),
    )

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

        val challenge = PasskeyBase64.encodeToString(js.challenge)
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
        requireCredentialRpIdMatchesRequest(
            credential = credential,
            rpId = rpId,
        )
        requireCredentialAllowedByRequestOptions(
            credential = credential,
            requestJson = opt.requestJson,
            json = json,
        )

        val credentialIdBytes = PasskeyCredentialId.encode(credential.credentialId)

        val counter = kotlin.run {
            val tmp = credential.counter ?: 0
            if (tmp > 0) {
                // Modern Bitwarden seems to use 0 for passkeys without a signature
                // counter. Non-zero counters are legacy; we preserve them but
                // do not increment them because keeping counters monotonic
                // across devices requires sync coordination.
                tmp
            } else {
                0
            }
        }
        val defaultAuthenticatorData = passkeyUtils.authData(
            rpId = rpId,
            counter = counter,
            credentialId = credentialIdBytes,
            credentialPublicKey = null,
            userVerification = passkeyUtils.userVerification(
                mode = js.userVerification,
                userVerified = userVerified,
            ),
            userPresence = true,
        )

        val clientDataJsonBytes = kotlin.run {
            val jsonObject = buildJsonObject {
                put("type", "webauthn.get")
                put("challenge", challenge)
                put("origin", origin)
                put("androidPackageName", packageName)
            }
            json.encodeToString(jsonObject)
                .toByteArray()
        }
        val clientDataJsonHash = opt.clientDataHash
            ?: cryptoService.hashSha256(clientDataJsonBytes)

        val signature = kotlin.run {
            requireSignableStoredKey(credential)
            val dataToSign = defaultAuthenticatorData + clientDataJsonHash
            val privateKeyPkcs8 = base64Service.decodeOrNull(credential.keyValue)
                ?: throw storedPasskeyKeyEncodingError()
            val result = try {
                passkeyCrypto.sign(
                    algorithm = PasskeySignatureAlgorithm.ES256,
                    privateKeyPkcs8 = privateKeyPkcs8,
                    data = dataToSign,
                )
            } finally {
                privateKeyPkcs8.fill(0)
                dataToSign.fill(0)
            }
            when (result) {
                is PasskeySignResult.Success -> result.signatureDer
                is PasskeySignResult.Error -> throw storedPasskeyKeyEncodingError()
            }
        }
        val encodedSignature = try {
            PasskeyBase64.encodeToString(signature)
        } finally {
            signature.fill(0)
        }

        val prfEvalInput = resolvePasskeyPrfEvalInput(
            requestJson = opt.requestJson,
            credentialIdBytes = credentialIdBytes,
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
                evalInput = prfEvalInput,
                userVerified = userVerified,
                prfSecretBytes = prfSecretBytes,
                computePrf = passkeyUtils::computePrf,
            )
        } finally {
            prfSecretBytes?.fill(0)
        }

        val r = assertionResponseJson(
            // 受信浏览器会提供它自己生成的 clientDataHash。此时必须省略本地拼装的
            // clientDataJSON，让 Credential Manager 把浏览器原始值补回响应；否则签名
            // 使用浏览器哈希、服务端却对本地 JSON 重算哈希，认证一定失败。
            clientDataJson = assertionClientDataJsonForResponse(
                clientDataJsonBytes = clientDataJsonBytes,
                clientDataHash = opt.clientDataHash,
            ),
            authenticatorData = PasskeyBase64.encodeToString(defaultAuthenticatorData),
            signature = encodedSignature,
            userHandle = credential.userHandle,
        )
        val authenticationResponse = buildJsonObject {
            put("id", PasskeyBase64.encodeToString(credentialIdBytes))
            put("rawId", credentialIdBytes)
            put("type", "public-key")
            put("authenticatorAttachment", "cross-platform")
            put("response", r)
            put("clientExtensionResults", buildJsonObject {
                prfExtensionResult?.let { put("prf", it) }
            })
        }
        val authenticationResponseJson = json.encodeToString(authenticationResponse)
        val passkeyCredential = PublicKeyCredential(authenticationResponseJson)
        return GetCredentialResponse(passkeyCredential)
    }

    /**
     * Rejects a stored credential this provider cannot produce an assertion
     * for: only an ES256 key — `public-key` / `ECDSA` / `P-256` — is signable
     * here, and the encoded key is length-capped before it reaches the Base64
     * decoder so a malformed vault entry cannot turn into an unbounded decode.
     */
    private fun requireSignableStoredKey(
        credential: DSecret.Login.Fido2Credentials,
    ) {
        val isEs256 = credential.keyType == "public-key" &&
            credential.keyAlgorithm == "ECDSA" &&
            credential.keyCurve == "P-256"
        if (!isEs256 || credential.keyValue.length > MAX_ENCODED_PASSKEY_KEY_CHARS) {
            throw storedPasskeyKeyEncodingError()
        }
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

    private fun JsonObjectBuilder.put(key: String, data: ByteArray) {
        put(key, PasskeyBase64.encodeToString(data))
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

/** 优先选择当前 credentialId 对应的 evalByCredential 输入，再回退到通用 eval。 */
internal fun resolvePasskeyPrfEvalInput(
    requestJson: String,
    credentialIdBytes: ByteArray,
    json: Json,
    encodeCredentialId: (ByteArray) -> String = PasskeyBase64::encodeToString,
): GetPasskeyPrfEvalInput? {
    val options = runCatching {
        json.decodeFromString<GetPasskeyPrfRequestOptions>(requestJson)
    }.getOrNull()
    val prf = options?.extensions?.prf ?: return null
    val credentialId = encodeCredentialId(credentialIdBytes)
    return prf.evalByCredential[credentialId] ?: prf.eval
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

private fun storedPasskeyKeyEncodingError() = GetPublicKeyCredentialDomException(
    domError = EncodingError(),
    errorMessage = "The stored passkey key is malformed or unsupported.",
)

internal fun assertionResponseJson(
    clientDataJson: String?,
    authenticatorData: String,
    signature: String,
    userHandle: String?,
): JsonObject = buildJsonObject {
    clientDataJson?.let { put("clientDataJSON", it) }
    put("authenticatorData", authenticatorData)
    put("signature", signature)
    userHandle
        ?.takeIf { it.isNotEmpty() }
        ?.let { put("userHandle", it) }
}

internal fun assertionClientDataJsonForResponse(
    clientDataJsonBytes: ByteArray,
    clientDataHash: ByteArray?,
    encode: (ByteArray) -> String = PasskeyBase64::encodeToString,
): String? = if (clientDataHash == null) {
    encode(clientDataJsonBytes)
} else {
    null
}

internal fun requireCredentialRpIdMatchesRequest(
    credential: DSecret.Login.Fido2Credentials,
    rpId: String,
) = requireWebAuthnCredentialRpIdMatchesRequest(
    credential = credential,
    rpId = rpId,
)

internal fun requireCredentialAllowedByRequestOptions(
    credential: DSecret.Login.Fido2Credentials,
    requestJson: String,
    json: Json,
    decodeCredentialId: (String) -> ByteArray = PasskeyBase64::decode,
) = mapGetWebAuthnExceptions {
    requireWebAuthnCredentialAllowedByRequestOptions(
        credential = credential,
        requestJson = requestJson,
        json = json,
        decodeCredentialId = decodeCredentialId,
    )
}

private inline fun <T> mapGetWebAuthnExceptions(
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
