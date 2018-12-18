package com.pe.utils

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import com.typesafe.scalalogging.LazyLogging
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

import scala.util.{Failure, Try}

object Encryption extends LazyLogging {
  private val defaultKey = AppConfig.encryptDefaultKey

  private val encoder = java.util.Base64.getEncoder
  private val decoder = java.util.Base64.getDecoder

  private val defaultEncryptCipher = this.createEncryptCipher(defaultKey)
  private val defaultDecryptCipher = this.createDecryptCipher(defaultKey)

  def oneWayEncryptSHA256(source: String): String = {
    val sh = MessageDigest.getInstance("SHA-256")
    sh.update(source.getBytes())

    val byteData = sh.digest()
    val sb = new StringBuffer()

    byteData.foreach { byte => sb.append(Integer.toString(byte&0xff) + 0x100, 16).substring(1) }
    sb.toString
  }

  def encrypt(source: String): String = {
    encoder.encodeToString(defaultEncryptCipher.doFinal(source.getBytes(StandardCharsets.UTF_8)))
  }

  def decrypt(encryptedSource: String): String = {
    new String(defaultDecryptCipher.doFinal(decoder.decode(encryptedSource)), StandardCharsets.UTF_8)
  }

  def encrypt(source: String, key: String): String = {
    encoder.encodeToString(this.createEncryptCipher(key).doFinal(source.getBytes(StandardCharsets.UTF_8)))
  }

  def decrypt(encryptedSource: String, key: String): String = {
    new String(this.createDecryptCipher(key).doFinal(decoder.decode(encryptedSource)), StandardCharsets.UTF_8)
  }

  private def createEncryptCipher(key: String): Cipher = {
    val encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    val keyBytes = key.getBytes(StandardCharsets.UTF_8)
    val keySpecBytes = new Array[Byte](16)

    if (keyBytes.length > 16) {
      keyBytes.slice(0, 16).copyToArray(keySpecBytes)
    } else {
      keyBytes.copyToArray(keySpecBytes)
    }

    val keySpec = new SecretKeySpec(keySpecBytes, "AES")
    val ivSpec = new IvParameterSpec(keySpecBytes)

    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    encryptCipher
  }

  private def createDecryptCipher(key: String): Cipher = {
    val decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    val keyBytes = key.getBytes(StandardCharsets.UTF_8)
    val keySpecBytes = new Array[Byte](16)

    if (keyBytes.length > 16) {
      keyBytes.slice(0, 16).copyToArray(keySpecBytes)
    } else {
      keyBytes.copyToArray(keySpecBytes)
    }

    val keySpec = new SecretKeySpec(keySpecBytes, "AES")
    val ivSpec = new IvParameterSpec(keySpecBytes)

    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    decryptCipher
  }
}
