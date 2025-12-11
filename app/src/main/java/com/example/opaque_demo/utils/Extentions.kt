package com.example.opaque_demo.utils

fun ByteArray.toHexString(): String =
    this.joinToString("") { "%02x".format(it) }
