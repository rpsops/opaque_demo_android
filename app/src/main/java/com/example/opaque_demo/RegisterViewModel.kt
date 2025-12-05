package com.example.opaque_demo

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.model.PayloadWrapper
import com.example.opaque_demo.model.RequestPayload
import com.example.opaque_demo.model.ServerPayloadWrapper
import com.example.opaque_demo.model.ServerResponsePayload
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import se.digg.opaque_ke_uniffi.clientLoginFinish
import se.digg.opaque_ke_uniffi.clientLoginStart
import se.digg.opaque_ke_uniffi.clientRegistrationFinish
import se.digg.opaque_ke_uniffi.clientRegistrationStart
import se.digg.opaque_ke_uniffi.serverLoginFinish
import se.digg.opaque_ke_uniffi.serverLoginStart
import se.digg.opaque_ke_uniffi.serverRegistrationFinish
import se.digg.opaque_ke_uniffi.serverRegistrationStart
import se.digg.opaque_ke_uniffi.serverSetup
import java.io.IOException
import java.io.InputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Instant

class RegisterViewModel : ViewModel() {

    private val client = OkHttpClient()

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    var authz: ByteArray = ByteArray(16)


    /**
     * Register the authentication code for the device
     * This should already be available on the server. This is just to be able to run a registerPin
     */
    fun registerAuthentication(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val serverPublicKey = getServerPublicKey(context)
            val clientPrivateKey = getClientPrivateKey(context)

            SecureRandom().nextBytes(authz)
            val encryptedPayload = encryptBytes(authz, serverPublicKey)

            val nonce = generateNonce()

            val payloadWrapper =
                getPayloadWrapper("register-authorization", nonce, encryptedPayload)

            val signedJws = createSignedJws(payloadWrapper, clientPrivateKey)

            val registerResponse = sendString(signedJws.serialize())
            // We don't care about the result. This is just for testing
        }
    }

    /**
     * Register a pin (123) for the device
     */
    fun registerPin(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {

            val serverPublicKey = getServerPublicKey(context)
            val clientPrivateKey = getClientPrivateKey(context)

            // Client start
            val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

            // create the payload
            val evaluatePayload =
                RequestPayload("opaque", "evaluate", null, clientRegStartResult.registrationRequest)

            // encrypt the payload
            val encryptedPayload = encryptPayload(evaluatePayload, serverPublicKey)

            val evalNonce = generateNonce()

            // wrap the payload
            val evaluatePayloadWrapper =
                getPayloadWrapper("pin_registration", evalNonce, encryptedPayload)

            // sign the payload
            val signedJws = createSignedJws(evaluatePayloadWrapper, clientPrivateKey)

            // send evaluate to server
            val serverEvaluateResponse = sendString(signedJws.serialize())

            // handle server evaluate response
            val serverPayloadWrapper = extractPayloadWrapper(
                serverEvaluateResponse,
                serverPublicKey
            )

            val registrationResponse = decryptServerPayload(serverPayloadWrapper, clientPrivateKey)

            // Client finish
            val clientRegFinishResult = clientRegistrationFinish(
                byteArrayOf(1, 2, 3),
                clientRegStartResult.clientRegistration,
                registrationResponse.resp!!
            )

            // create the payload
            val finalizePayload =
                RequestPayload("opaque", "finalize", authz, clientRegFinishResult.registrationUpload)

            val finalizeNonce = generateNonce()

            // wrap the payload
            val finalizePayloadWrapper =
                getPayloadWrapper(
                    "pin_registration",
                    finalizeNonce,
                    encryptPayload(finalizePayload, serverPublicKey)
                )

            // sign the payload
            val signedFinalizeJws = createSignedJws(finalizePayloadWrapper, clientPrivateKey)

            // send finalize to server
            val serverFinalizeResponse = sendString(signedFinalizeJws.serialize())

            // handle server finalize response
            val serverFinalizePayloadWrapper = extractPayloadWrapper(
                serverFinalizeResponse,
                serverPublicKey
            )

            val serverFinalizePayload =
                decryptServerPayload(serverFinalizePayloadWrapper, clientPrivateKey)

            Log.d("OpaqueDemo", "RegisterPin is : ${serverFinalizePayload.msg!!}")
        }
    }

    private fun getPayloadWrapper(type: String, nonce: String, encryptedPayload: ByteArray) =
        PayloadWrapper(
            "https://wallets/digg.se/1234567890",
//            "a25d8884-c77b-43ab-bf9d-1279c08d860d",
            "wallet-hsm-key-1",
            "hsm",
            type,
            null,
            "1.0",
            nonce,
            Instant.now(),
            "device",
            encryptedPayload
        )

    /**
     * Extract and verify the payloadWrapper from the server response
     */
    private fun extractPayloadWrapper(
        serverResponse: String,
        serverPublicKey: ECPublicKey
    ): ServerPayloadWrapper {

        val serverResponseJws = JWSObject.parse(serverResponse)

        // verify signature
        val jwsVerifier = ECDSAVerifier(serverPublicKey)
        if (!serverResponseJws.verify(jwsVerifier)) {
            throw Exception("Invalid signature")
        }

        // get the PayloadWrapper
        val serverPayloadWrapper =
            Json.decodeFromString<ServerPayloadWrapper>(serverResponseJws.payload.toString())

        // todo check what else needs verifying. Nonce, iat....

        return serverPayloadWrapper
    }

    /**
     * Decrypt the inner payload. The content of the payload can vary depending on the concrete type in the server
     */
    private fun decryptServerPayload(
        serverPayloadWrapper: ServerPayloadWrapper,
        clientPrivateKey: ECPrivateKey
    ): ServerResponsePayload {
        val payloadJwe = JWEObject.parse(String(serverPayloadWrapper.data))
        val decryptor = ECDHDecrypter(clientPrivateKey)
        payloadJwe.decrypt(decryptor)
        val payload =
            Json.decodeFromString<ServerResponsePayload>(payloadJwe.payload.toString())
        return payload
    }

    private fun createSignedJws(
        payloadWrapper: PayloadWrapper,
        clientPrivateKey: ECPrivateKey
    ): JWSObject {
        // create JWSObject
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()
        val serializedPayload = Payload(Json.encodeToString(payloadWrapper).toByteArray())
        val jwsObject = JWSObject(
            header,
            serializedPayload
        )

        // sign JWS
        val signer = ECDSASigner(clientPrivateKey)
        jwsObject.sign(signer)
        return jwsObject
    }

    suspend fun sendString(data: String): String {
        return withContext(Dispatchers.IO) {
            val mediaType = "application/json; charset=utf-8".toMediaType()
            val body = data.toRequestBody(mediaType)
            val request = Request.Builder()
                .url("http://10.0.2.2:9010/rhsm-bff/service")
//                .url("http://10.0.2.2:8088/r2ps-api/service")
                .post(body)
                .build()

            try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.e("OpaqueDemo", "Unexpected code $response")
                        throw IOException("Unexpected code $response")
                    } else {
                        val responseString = response.body?.string() ?: ""
                        Log.d("OpaqueDemo", "Response: $responseString")
                        responseString
                    }
                }
            } catch (e: IOException) {
                Log.e("OpaqueDemo", "Network error", e)
                throw e
            }
        }
    }

    private fun encryptPayload(payload: RequestPayload, serverPublicKey: ECPublicKey): ByteArray {
        val payloadBytes = Json.encodeToString(payload).toByteArray()
        return encryptBytes(payloadBytes, serverPublicKey)
    }

    private fun encryptBytes(payload: ByteArray, serverPublicKey: ECPublicKey): ByteArray {
        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM).build()
        val jweObject = JWEObject(header, Payload(payload))
        val encrypter = ECDHEncrypter(serverPublicKey)
        jweObject.encrypt(encrypter)
        return jweObject.serialize().toByteArray()
    }

    private fun getServerPublicKey(context: Context): ECPublicKey {
        val inputStream: InputStream = context.resources.openRawResource(R.raw.serverkey)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream)
        return certificate.publicKey as ECPublicKey
    }

    private fun getClientPrivateKey(context: Context): ECPrivateKey {
        val password = "Test1234".toCharArray()
        val alias = "wallet-hsm"
        val keyStore = KeyStore.getInstance("PKCS12")
        context.resources.openRawResource(R.raw.wallethsm).use { inputStream ->
            keyStore.load(inputStream, password)
        }
        return keyStore.getKey(alias, password) as ECPrivateKey
    }

    private fun generateNonce(): String {
        val nonceBytes = ByteArray(32)
        SecureRandom().nextBytes(nonceBytes)
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes)
    }


    /**
     * Run the opaque process locally, without calling any server
     */
    fun localRegister() {
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        val serverSetup = serverSetup();
        val serverRegStartResult =
            serverRegistrationStart(
                serverSetup,
                clientRegStartResult.registrationRequest,
                byteArrayOf(1, 2)
            )

        val clientRegFinishResult = clientRegistrationFinish(
            byteArrayOf(1, 2, 3),
            clientRegStartResult.clientRegistration,
            serverRegStartResult
        )

        val passwordFile =
            serverRegistrationFinish(clientRegFinishResult.registrationUpload)

        val startTime = System.currentTimeMillis()

        val clientLoginStart = clientLoginStart(byteArrayOf(1, 2, 3))

        val endClient1 = System.currentTimeMillis()
        val serverLoginStart = serverLoginStart(
            serverSetup,
            passwordFile,
            clientLoginStart.credentialRequest,
            byteArrayOf(1, 2)
        )

        val startClient = System.currentTimeMillis()
        val clientLoginFinish = clientLoginFinish(
            serverLoginStart.credentialResponse,
            clientLoginStart.clientRegistration,
            byteArrayOf(1, 2, 3)
        )
        val endClient2 = System.currentTimeMillis()

        val clientSessionKey = clientLoginFinish.sessionKey

        val serverLoginFinish = serverLoginFinish(
            serverLoginStart.serverLogin,
            clientLoginFinish.credentialFinalization
        )

        val serverSessionKey = serverLoginFinish

        val endTime = System.currentTimeMillis()
        Log.d("OpaqueDemo", "Opaque process took ${endTime - startTime} ms")
        Log.d(
            "OpaqueDemo",
            "Client took ${(endClient1 - startTime) + (endClient2 - startClient)} ms"
        )
        _result.value =
            "Opaque process took ${endTime - startTime} ms\n Client took ${(endClient1 - startTime) + (endClient2 - startClient)} ms"
    }
}
