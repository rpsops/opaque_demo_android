package com.example.opaque_demo

import androidx.lifecycle.ViewModel
import uniffi.opaque_ke_uniffi.clientRegistrationStart
import uniffi.opaque_ke_uniffi.serverRegistrationStart
import uniffi.opaque_ke_uniffi.serverSetup

class RegisterViewModel : ViewModel() {
    fun register() {
        val test = clientRegistrationStart(byteArrayOf(1, 2, 3))

        val serverSetup = serverSetup();
        val serverStart = serverRegistrationStart(serverSetup, test.message, byteArrayOf(1, 2))

    }

    fun createSession() {
        TODO("Not yet implemented")
    }

}
