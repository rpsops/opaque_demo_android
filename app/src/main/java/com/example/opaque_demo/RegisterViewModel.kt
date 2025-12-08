package com.example.opaque_demo

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.model.RequestPayload
import com.example.opaque_demo.network.OpaqueService
import com.example.opaque_demo.security.OpaqueCryptoManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import se.digg.opaque_ke_uniffi.clientLoginFinish
import se.digg.opaque_ke_uniffi.clientLoginStart
import se.digg.opaque_ke_uniffi.clientRegistrationFinish
import se.digg.opaque_ke_uniffi.clientRegistrationStart
import se.digg.opaque_ke_uniffi.serverLoginFinish
import se.digg.opaque_ke_uniffi.serverLoginStart
import se.digg.opaque_ke_uniffi.serverRegistrationFinish
import se.digg.opaque_ke_uniffi.serverRegistrationStart
import se.digg.opaque_ke_uniffi.serverSetup
import java.security.SecureRandom

class RegisterViewModel : ViewModel() {

    private val service = OpaqueService()

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    var authz: ByteArray = ByteArray(16)


    /**
     * Register the authentication code for the device
     * This should already be available on the server. This is just to be able to run a registerPin
     */
    fun registerAuthentication(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context)

            SecureRandom().nextBytes(authz)
            val encryptedPayload = cryptoManager.encryptBytes(authz)

            val nonce = cryptoManager.generateNonce()

            val signedJws =
                cryptoManager.createSignedJws("register-authorization", nonce, encryptedPayload)

            val registerResponse = service.sendRequest(signedJws.serialize())
            // We don't care about the result. This is just for testing
        }
    }

    /**
     * Register a pin (123) for the device
     */
    fun registerPin(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context)

            // Client start
            val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

            // create the payload
            val evaluatePayload =
                RequestPayload("opaque", "evaluate", null, clientRegStartResult.registrationRequest)

            // encrypt the payload
            val encryptedPayload = cryptoManager.encryptPayload(evaluatePayload)

            val evalNonce = cryptoManager.generateNonce()

            // sign the payload
            val signedJws =
                cryptoManager.createSignedJws("pin_registration", evalNonce, encryptedPayload)

            // send evaluate to server
            val serverEvaluateResponse = service.sendRequest(signedJws.serialize())

            // handle server evaluate response
            val serverPayloadWrapper = cryptoManager.extractPayloadWrapper(serverEvaluateResponse)

            val registrationResponse = cryptoManager.decryptServerPayload(serverPayloadWrapper)

//            val hex = registrationResponse.resp!!.joinToString("") { "%02x".format(it) }
//            Log.d("OpaqueDemo", "Hex value is : $hex")

            // Client finish
            val clientRegFinishResult = clientRegistrationFinish(
                byteArrayOf(1, 2, 3),
                clientRegStartResult.clientRegistration,
                registrationResponse.resp!!
            )

            // create the payload
            val finalizePayload =
                RequestPayload(
                    "opaque",
                    "finalize",
                    authz,
                    clientRegFinishResult.registrationUpload
                )

            val finalizeNonce = cryptoManager.generateNonce()

            // wrap and sign the payload
            val finalizeEncryptedPayload = cryptoManager.encryptPayload(finalizePayload)
            val signedFinalizeJws = cryptoManager.createSignedJws(
                "pin_registration",
                finalizeNonce,
                finalizeEncryptedPayload
            )

            // send finalize to server
            val serverFinalizeResponse = service.sendRequest(signedFinalizeJws.serialize())

            // handle server finalize response
            val serverFinalizePayloadWrapper =
                cryptoManager.extractPayloadWrapper(serverFinalizeResponse)

            val serverFinalizePayload =
                cryptoManager.decryptServerPayload(serverFinalizePayloadWrapper)

            Log.d("OpaqueDemo", "RegisterPin is : ${serverFinalizePayload.msg!!}")
        }
    }

    fun createSession(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context)

            val clientLoginStart = clientLoginStart(byteArrayOf(1, 2, 3))

            Log.d("OpaqueDemo", clientLoginStart.credentialRequest.joinToString { "%02x".format(it) })
            Log.d("OpaqueDemo", "ClientLoginStart: ${clientLoginStart.credentialRequest.contentToString()}")

            // create the payload
            val evaluatePayload =
                RequestPayload("opaque", "evaluate", null, clientLoginStart.credentialRequest)

            // encrypt the payload
            val encryptedPayload = cryptoManager.encryptPayload(evaluatePayload)

            val evalNonce = cryptoManager.generateNonce()

            // sign the payload
            val signedJws =
                cryptoManager.createSignedJws("authenticate", evalNonce, encryptedPayload)

            // send evaluate to server
            val serverEvaluateResponse = service.sendRequest(signedJws.serialize())

            // handle server evaluate response
            val serverPayloadWrapper = cryptoManager.extractPayloadWrapper(serverEvaluateResponse)
            val loginEvaluateResponse = cryptoManager.decryptServerPayload(serverPayloadWrapper)

            val resp = loginEvaluateResponse.resp!!
            Log.d("OpaqueDemo", "Response is : ${resp.contentToString()}")
            val hex = resp.joinToString("") { "%02x".format(it) }
            Log.d("OpaqueDemo", "Hex value is : $hex")

            // client finish
            try {
                val clientLoginFinish = clientLoginFinish(
                    loginEvaluateResponse.resp,
                    clientLoginStart.clientRegistration,
                    byteArrayOf(1, 2, 3)
                )
                Log.d("OpaqueDemo", "Session created: ${clientLoginFinish.credentialFinalization}")
            } catch (e: Exception) {
                Log.d("OpaqueDemo", "Error creating session: $e")
            }


        }
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
