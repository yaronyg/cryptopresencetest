package org.thaliproject.cryptopresencetest.app;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * When I was trying to figure out how to solve our discovery problem I played
 * around with ECDSA. In the end we didn't need it but I keep this code just
 * for reference incase I need it in the future.
 */
public class ECDSATests extends BaseCryptoTest {
    final ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
    final KeyPairGenerator keyPairGeneratorEcdsa;
    final KeyPair keyPair;
    final Signature ecdsaSign;

    public ECDSATests() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        super();

        keyPairGeneratorEcdsa = KeyPairGenerator.getInstance("ECDSA", "SC");
        keyPairGeneratorEcdsa.initialize(ecGenSpec, secureRandom);
        ecdsaSign = Signature.getInstance("SHA1withECDSA", "SC");
        keyPair = keyPairGeneratorEcdsa.generateKeyPair();
    }

    public void testCreate256BitECDSAKey() throws Exception {
        PerfTest.runAndLogTest("Create 256 Bit ECDSA Key", 100, new PerfTest() {
            @Override
            void runPerfTest() {
                keyPairGeneratorEcdsa.generateKeyPair();
            }
        });
    }

    public void testSignValueWith256BitECDSAKey() throws Exception {
        ecdsaSign.initVerify(keyPair.getPublic());
        ecdsaSign.initSign(keyPair.getPrivate());

        PerfTest.runAndLogTest("Sign beacon byte value with 256 bit ECDSA Key", 100,
                new PerfTest() {
                    final byte[] beaconValue = new byte[hashSizeInBytes];

                    @Override
                    public void setUpBeforeEachPerfRun() {
                        secureRandom.nextBytes(beaconValue);
                    }

                    @Override
                    public void runPerfTest() throws SignatureException {
                        ecdsaSign.update(beaconValue);
                        ecdsaSign.sign();
                    }
                });
    }

    public void testVerifySignedValueWith256BitECDSAKey() throws Exception {
        PerfTest.runAndLogTest("Verify beacon byte signature value with 256 bit ECDSA Key",
                100, new PerfTest() {
                    private byte[] signedValue;
                    final byte[] beaconValue = new byte[hashSizeInBytes];

                    @Override
                    public void setUpBeforeEachPerfRun() throws InvalidKeyException, SignatureException {
                        secureRandom.nextBytes(beaconValue);
                        ecdsaSign.initSign(keyPair.getPrivate());
                        ecdsaSign.update(beaconValue);
                        signedValue = ecdsaSign.sign();
                    }

                    @Override
                    public void runPerfTest() throws Exception {
                        ecdsaSign.initVerify(keyPair.getPublic());
                        ecdsaSign.update(beaconValue);
                        if (!ecdsaSign.verify(signedValue)) {
                            fail();
                        }
                    }
                });
    }

    public void testVerifyMultipleNonMatching256BitECDSASignedValues() throws Exception {
        final int tokensToTest = 10;
        final byte[][] signedValues = new byte[tokensToTest][];
        final byte[][] beaconValues = new byte[tokensToTest][hashSizeInBytes];
        final KeyPair verifyKeyPair = keyPairGeneratorEcdsa.generateKeyPair();
        final Signature ecdsaFailVerify = Signature.getInstance("SHA1withECDSA", "SC");
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaFailVerify.initVerify(verifyKeyPair.getPublic());

        PerfTest.runAndLogTest("Verify beacon byte signature value DOESN'T MATCH with 256 bit ECDSA Key" +
                        "against " + tokensToTest + "tokens.",
                10, new PerfTest() {
                    @Override
                    public void setUpBeforeEachPerfRun() throws SignatureException {
                        for (int i = 0; i < tokensToTest; ++i) {
                            secureRandom.nextBytes(beaconValues[i]);
                            ecdsaSign.update(beaconValues[i]);
                            signedValues[i] = ecdsaSign.sign();
                        }
                    }

                    @Override
                    public void runPerfTest() throws Exception {
                        for (int i = 0; i < tokensToTest; ++i) {
                            ecdsaFailVerify.update(beaconValues[i]);
                            if (ecdsaFailVerify.verify(signedValues[i])) {
                                fail();
                            }
                        }
                    }
                });

    }
}
