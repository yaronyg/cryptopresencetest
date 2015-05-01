package org.thaliproject.cryptopresencetest.app;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class CryptoUtilities {
    static final int sizeOfTimeStampInBytes = 8;
    static final int oneHundredTwentyEightBitsInBytes = 16;

    public enum AesType { CBC, GCM }

    public static final int aes128BlockSizeInBytes = 16;

    static public AlgorithmParameterSpec getAlgorithmParameterSpec(AesType aesType, byte[] iv) {
        switch(aesType) {
            case CBC:
                return new IvParameterSpec(iv);
            case GCM:
                return new GCMParameterSpec(16 * Byte.SIZE, iv);
            default:
                throw new IllegalArgumentException("aesType isn't supported value");
        }
    }

    static public Cipher createAesCipher(AesType aesType) throws NoSuchPaddingException,
            NoSuchAlgorithmException {
        String instanceString;
        switch(aesType) {
            case CBC:
                instanceString = "AES/CBC/PKCS5Padding";
                break;
            case GCM:
                instanceString = "AES/GCM/NoPadding";
                break;
            default:
                throw new IllegalArgumentException("aesType isn't supported value");
        }

        return Cipher.getInstance(instanceString);
    }

    public static byte[] generateTimeStampAsBytes() {
        final ByteBuffer buffer = ByteBuffer.allocate(sizeOfTimeStampInBytes);
        return buffer.putLong(0, System.currentTimeMillis()).array();
    }

    public static SecretKeySpec[] generateHmacKeys(int numberOfKeysToGenerate,
                                                   int sizeOfKeyInBytes) {
        SecureRandom secureRandom = new SecureRandom();
        SecretKeySpec[] keys = new SecretKeySpec[numberOfKeysToGenerate];
        byte[] keyBytes = new byte[sizeOfKeyInBytes];
        for (int i = 0; i < numberOfKeysToGenerate; ++i) {
            secureRandom.nextBytes(keyBytes);
            keys[i] = new SecretKeySpec(keyBytes, "RAW");
        }
        return keys;
    }

    public static byte[] generate128BitHash(byte[] valueToHash, SecretKeySpec key, Mac hmac)
            throws InvalidKeyException {
        hmac.init(key);
        byte[] rawHashOutput = hmac.doFinal(valueToHash);
        if (rawHashOutput.length < oneHundredTwentyEightBitsInBytes) {
            throw new IllegalArgumentException("We got a hash function that didn't generate at least 128 bites of output");
        }
        return Arrays.copyOfRange(rawHashOutput, 0, oneHundredTwentyEightBitsInBytes);
    }
}
