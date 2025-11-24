package com.example.opaque_demo

import android.util.Log
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import uniffi.opaque_ke_uniffi.clientLoginFinish
import uniffi.opaque_ke_uniffi.clientLoginStart
import uniffi.opaque_ke_uniffi.clientRegistrationFinish
import uniffi.opaque_ke_uniffi.clientRegistrationStart
import uniffi.opaque_ke_uniffi.serverLoginFinish
import uniffi.opaque_ke_uniffi.serverLoginStart
import uniffi.opaque_ke_uniffi.serverRegistrationFinish
import uniffi.opaque_ke_uniffi.serverRegistrationStart
import uniffi.opaque_ke_uniffi.serverSetup

class RegisterViewModel : ViewModel() {

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    fun register() {
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        val serverSetup = serverSetup();
        val serverRegStartResult =
            serverRegistrationStart(serverSetup, clientRegStartResult.registrationRequest, byteArrayOf(1, 2))

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

    fun createSession() {
        TODO("Not yet implemented")
    }

}
