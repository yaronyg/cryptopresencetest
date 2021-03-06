package org.thaliproject.cryptopresencetest.performanceHack;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.HashSet;

public class HashAndHmacTests extends BaseCryptoTest {
    private final Mac hmac;
    private final String macAlgorithm = "HMACSHA256";

    public HashAndHmacTests() throws NoSuchAlgorithmException {
        super();
        hmac = Mac.getInstance(macAlgorithm);
    }

    public void testGenerateHMACUsingDifferentKeys() throws Exception {
        final int keysToGenerate = 20;

        PerfTest.runAndLogTest("Generate " + keysToGenerate + " " + macAlgorithm +
                " Values using different keys", 100, new PerfTest() {
            SecretKeySpec[] keys;
            final byte[] timeStampAsBytes = CryptoUtilities.generateTimeStampAsBytes();

            @Override
            void setUpBeforeEachPerfRun() {
                keys = CryptoUtilities.generateHmacKeys(keysToGenerate,
                        twoHundredFiftySixBitKeyInBytes);
            }

            @Override
            void runPerfTest() throws InvalidKeyException {
                for (SecretKeySpec key : keys) {
                    CryptoUtilities.generate128BitHash(timeStampAsBytes, key, hmac);
                }
            }
        });
    }

    public void testCheckHashesAgainstAddressBook() throws Exception {
        final int keysInAddressBook = 150;
        final int numberOfHashesToCheck = 20;
        PerfTest.runAndLogTest("Check " + numberOfHashesToCheck + " hashes using " +
                macAlgorithm + " against " +
                keysInAddressBook + " keys, all comparisons fail", 100, new PerfTest() {
            final SecretKeySpec[] addressBook =
                    CryptoUtilities.generateHmacKeys(keysInAddressBook,
                            twoHundredFiftySixBitKeyInBytes);
            final HashSet<byte[]> hashesToCheck = new HashSet<>(numberOfHashesToCheck);
            final byte[] timeStampAsBytes = CryptoUtilities.generateTimeStampAsBytes();

            @Override
            void setUpBeforeEachPerfRun() {
                for (int i = 0; i < numberOfHashesToCheck; ++i) {
                    byte[] hashToCheck = new byte[hashSizeInBytes];
                    secureRandom.nextBytes(hashToCheck);
                    hashesToCheck.add(hashToCheck);
                }
            }

            @Override
            void runPerfTest() throws InvalidKeyException {
                for (SecretKeySpec key : addressBook) {
                    byte[] generatedHash =
                            CryptoUtilities.generate128BitHash(timeStampAsBytes, key, hmac);
                    if (hashesToCheck.contains(generatedHash)) {
                        fail();
                    }
                }
            }
        });
    }


}
