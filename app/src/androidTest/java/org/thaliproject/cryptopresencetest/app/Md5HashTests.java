package org.thaliproject.cryptopresencetest.app;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.HashSet;

public class Md5HashTests extends BaseCryptoTest {
    static Mac hmac5;

    public void setUp() throws InvalidAlgorithmParameterException, NoSuchProviderException,
            NoSuchAlgorithmException {
        hmac5 = Mac.getInstance("HMACMD5");
    }


    public void testGenerateHMACMD5UsingDifferentKeys() throws Exception {
        final int keysToGenerate = 20;

        TestCommand.runAndLogTest("Generate " + keysToGenerate +
                " HMAC-MD5 Values using different keys", 100, new TestCommand() {
            SecretKeySpec[] keys;
            byte[] timeStampAsBytes = generateTimeStampAsBytes();

            @Override
            void setUpBeforeEachTest() {
                keys = generateHmacKeys(keysToGenerate,
                        twoHundredFiftySixBitKeyInBytes);
            }

            @Override
            void runTest() throws InvalidKeyException {
                for (SecretKeySpec key : keys) {
                    generateHmac(timeStampAsBytes, key, hmac5);
                }
            }
        });
    }

    public void testCheckHashesAgainstAddressBook() throws Exception {
        final int keysInAddressBook = 1000;
        final int numberOfHashesToCheck = 1;
        TestCommand.runAndLogTest("Check " + numberOfHashesToCheck + " hashes against " +
                keysInAddressBook + " keys, all comparisons fail", 100, new TestCommand() {
            SecretKeySpec[] addressBook =
                    generateHmacKeys(keysInAddressBook, twoHundredFiftySixBitKeyInBytes);
            HashSet<byte[]> hashesToCheck = new HashSet<>(numberOfHashesToCheck);
            byte[] timeStampAsBytes = generateTimeStampAsBytes();

            @Override
            void setUpBeforeEachTest() {
                for (int i = 0; i < numberOfHashesToCheck; ++i) {
                    byte[] hashToCheck = new byte[md5HashSizeInBytes];
                    secureRandom.nextBytes(hashToCheck);
                    hashesToCheck.add(hashToCheck);
                }
            }

            @Override
            void runTest() throws InvalidKeyException {
                for (SecretKeySpec key : addressBook) {
                    byte[] generatedHash =
                            generateHmac(timeStampAsBytes, key, hmac5);
                    if (hashesToCheck.contains(generatedHash)) {
                        fail();
                    }
                }
            }
        });
    }


    public static byte[] generateTimeStampAsBytes() {
        final ByteBuffer buffer = ByteBuffer.allocate(sizeOfTimeStampInBytes);
        return buffer.putLong(0, System.currentTimeMillis()).array();
    }

    public static SecretKeySpec[] generateHmacKeys(int numberOfKeysToGenerate, int sizeOfKeyInBytes) {
        SecretKeySpec[] keys = new SecretKeySpec[numberOfKeysToGenerate];
        byte[] keyBytes = new byte[sizeOfKeyInBytes];
        for (int i = 0; i < numberOfKeysToGenerate; ++i) {
            secureRandom.nextBytes(keyBytes);
            keys[i] = new SecretKeySpec(keyBytes, "RAW");
        }
        return keys;
    }

    public static byte[] generateHmac(byte[] valueToHash, SecretKeySpec key, Mac hmac)
            throws InvalidKeyException {
        hmac.init(key);
        return hmac.doFinal(valueToHash);
    }
}
