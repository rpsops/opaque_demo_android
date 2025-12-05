package com.example.opaque_demo

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
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
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Instant

class RegisterViewModel : ViewModel() {

    private val client = OkHttpClient()

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    fun register() {
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

    fun testJWS(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {

            val serverPublicKey = getServerPublicKey(context)
            val clientPrivateKey = getClientPrivateKey(context)


            // Client start
            val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

            // create the payload
            val evaluatePayload =
                Payload("opaque", "evaluate", null, clientRegStartResult.registrationRequest)

            // encrypt the payload
            val encryptedPayload = encryptPayload(evaluatePayload, serverPublicKey)

            // wrap the payload
            val evaluatePayloadWrapper = PayloadWrapper(
                "https://wallets/digg.se/1234567890",
//            "a25d8884-c77b-43ab-bf9d-1279c08d860d",
                "wallet-hsm-key-1",
                "hsm",
                "pin_registration",
                null,
                "1.0",
                "1234567890",
                Instant.now(),
                "device",
                encryptedPayload
            )

            // sign the payload
            val signedJws = getSignedJws(evaluatePayloadWrapper, clientPrivateKey)

            // send evaluate to server
            val serverEvaluateResponse = sendString(signedJws.serialize())

            // handle server evaluate response
            val serverPayloadWrapper = extractPayloadWrapper(
                serverEvaluateResponse,
                serverPublicKey,
                clientPrivateKey
            )

            val registrationResponse = decryptServerPayload(serverPayloadWrapper, clientPrivateKey)

            // Client finish
            val clientRegFinishResult = clientRegistrationFinish(
                byteArrayOf(1, 2, 3),
                clientRegStartResult.clientRegistration,
                registrationResponse
            )

            val authz =
                byteArrayOf(122, -109, 88, 9, -124, -50, -25, 31, 28, 96, 45, -1, -58, 40, -67, 77)

            // create the payload
            val finalizePayload =
                Payload("opaque", "finalize", authz, clientRegFinishResult.registrationUpload)

            // wrap the payload
            val finalizePayloadWrapper = PayloadWrapper(
                "https://wallets/digg.se/1234567890",
//            "a25d8884-c77b-43ab-bf9d-1279c08d860d",
                "wallet-hsm-key-1",
                "hsm",
                "pin_registration",
                null,
                "1.0",
                "1234567890",
                Instant.now(),
                "device",
                encryptPayload(finalizePayload, serverPublicKey)
            )

            // sign the payload
            val signedFinalizeJws = getSignedJws(finalizePayloadWrapper, clientPrivateKey)

            // send finalize to server
            val serverFinalizeResponse = sendString(signedFinalizeJws.serialize())

            // handle server finalize response
            val serverFinalizePayloadWrapper = extractPayloadWrapper(
                serverEvaluateResponse,
                serverPublicKey,
                clientPrivateKey
            )

            val serverFinalizePayload =
                decryptServerPayload(serverFinalizePayloadWrapper, clientPrivateKey)

            print(serverFinalizePayload)

        }
    }

    private fun extractPayloadWrapper(
        serverResponse: String,
        serverPublicKey: ECPublicKey,
        clientPrivateKey: ECPrivateKey
    ): ServerPayloadWrapper {

        val serverResponseJws = JWSObject.parse(serverResponse)

        // verify signature
        val jwsVerifier = ECDSAVerifier(serverPublicKey)
        if (!serverResponseJws.verify(jwsVerifier)) {
            throw Exception("Invalid signature")
        }

        // get the PayloadWrapper
        val serverPayload = serverResponseJws.payload.toString()
        val serverPayloadWrapper = Json.decodeFromString<ServerPayloadWrapper>(serverPayload)

        // todo check what else needs verifying. Nonce, iat....

        return serverPayloadWrapper
    }

    private fun decryptServerPayload(
        serverPayloadWrapper: ServerPayloadWrapper,
        clientPrivateKey: ECPrivateKey
    ): ByteArray {
        // decrypt the inner payload and return it as byteArray
        val payloadJwe = JWEObject.parse(String(serverPayloadWrapper.data))
        val decryptor = ECDHDecrypter(clientPrivateKey)
        payloadJwe.decrypt(decryptor)
        val payload =
            Json.decodeFromString<ServerResponsePayload>(payloadJwe.payload.toString())
        return payload.resp
    }

    private fun getSignedJws(
        payloadWrapper: PayloadWrapper,
        clientPrivateKey: ECPrivateKey
    ): JWSObject {
        // create JWSObject
        // todo hard coded
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()
        val serializedPayload =
            com.nimbusds.jose.Payload(Json.encodeToString(payloadWrapper).toByteArray())
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

    private fun encryptPayload(payload: Payload, serverPublicKey: ECPublicKey): ByteArray {

        val payloadBytes = Json.encodeToString(payload).toByteArray()

        // todo check is contentType is really useful here
        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .contentType("application/octet-stream").build()


        val jweObject = JWEObject(header, com.nimbusds.jose.Payload(payloadBytes))

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

    // we're probably not going to use context
    @Serializable
    private data class PayloadWrapper(
        val client_id: String,
        val kid: String,
        val context: String,
        val type: String,
        val pake_session_id: String?,
        val ver: String,
        val nonce: String,
        @Serializable(with = InstantEpochSecondsSerializer::class)
        val iat: Instant,
        val enc: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val data: ByteArray
    )

    @Serializable
    private data class ServerPayloadWrapper(
        val ver: String,
        val nonce: String,
        @Serializable(with = InstantEpochSecondsSerializer::class)
        val iat: Instant,
        val enc: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val data: ByteArray
    )

    private object InstantEpochSecondsSerializer : KSerializer<Instant> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Instant", PrimitiveKind.LONG)

        override fun serialize(encoder: Encoder, value: Instant) =
            encoder.encodeLong(value.epochSecond)

        override fun deserialize(decoder: Decoder): Instant =
            Instant.ofEpochSecond(decoder.decodeLong())
    }

    private object Base64ByteArraySerializer : KSerializer<ByteArray> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("Base64ByteArray", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: ByteArray) {
            encoder.encodeString(java.util.Base64.getEncoder().encodeToString(value))
        }

        override fun deserialize(decoder: Decoder): ByteArray {
            return java.util.Base64.getDecoder().decode(decoder.decodeString())
        }
    }

    @Serializable
    private data class Payload(
        val protocol: String,
        val state: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val authorization: ByteArray?,
        @Serializable(with = Base64ByteArraySerializer::class)
        val req: ByteArray
    )

    @Serializable
    private data class ServerResponsePayload(
        @Serializable(with = Base64ByteArraySerializer::class)
        val resp: ByteArray
    )


}
