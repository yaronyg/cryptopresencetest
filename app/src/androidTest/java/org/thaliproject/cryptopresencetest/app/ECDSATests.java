package org.thaliproject.cryptopresencetest.app;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDSATests extends BaseCryptoTest {
    final ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
    KeyPairGenerator keyPairGeneratorEcdsa;
    KeyPair keyPair;
    final byte[] beaconValue = new byte[md5HashSizeInBytes];
    Signature ecdsaSign;


    public void setUp() throws InvalidAlgorithmParameterException, NoSuchProviderException,
            NoSuchAlgorithmException {
        keyPairGeneratorEcdsa = KeyPairGenerator.getInstance("ECDSA", "SC");
        keyPairGeneratorEcdsa.initialize(ecGenSpec, secureRandom);
        ecdsaSign = Signature.getInstance("SHA1withECDSA", "SC");
        keyPair = keyPairGeneratorEcdsa.generateKeyPair();
    }


    public void testCreate256BitECDSAKey() throws Exception {
        TestCommand.runAndLogTest("Create 256 Bit ECDSA Key", 100, new TestCommand() {
            @Override
            void runTest() {
                keyPairGeneratorEcdsa.generateKeyPair();
            }
        });
    }

    public void testSignValueWith256BitECDSAKey() throws Exception {
        ecdsaSign.initVerify(keyPair.getPublic());
        ecdsaSign.initSign(keyPair.getPrivate());

        TestCommand.runAndLogTest("Sign beacon byte value with 256 bit ECDSA Key", 100, new TestCommand() {
            @Override
            public void setUpBeforeEachTest() {
                secureRandom.nextBytes(beaconValue);
            }

            @Override
            public void runTest() throws SignatureException {
                ecdsaSign.update(beaconValue);
                ecdsaSign.sign();
            }
        });
    }

    public void testVerifySignedValueWith256BitECDSAKey() throws Exception {
        TestCommand.runAndLogTest("Verify beacon byte signature value with 256 bit ECDSA Key", 100, new TestCommand() {
            private byte[] signedValue;

            @Override
            public void setUpBeforeEachTest() throws InvalidKeyException, SignatureException {
                secureRandom.nextBytes(beaconValue);
                ecdsaSign.initSign(keyPair.getPrivate());
                ecdsaSign.update(beaconValue);
                signedValue = ecdsaSign.sign();
            }

            @Override
            public void runTest() throws Exception {
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
        final byte[][] beaconValues = new byte[tokensToTest][beaconValue.length];
        final KeyPair verifyKeyPair = keyPairGeneratorEcdsa.generateKeyPair();
        final Signature ecdsaFailVerify = Signature.getInstance("SHA1withECDSA", "SC");

        TestCommand.runAndLogTest("Verify beacon byte signature value DOESN'T MATCH with 256 bit ECDSA Key" +
                "against " + tokensToTest + "tokens.",
                10, new TestCommand() {

            @Override
            public void runOnceBeforeAllTests() throws InvalidKeyException {
                ecdsaSign.initSign(keyPair.getPrivate());
                ecdsaFailVerify.initVerify(verifyKeyPair.getPublic());
            }

            @Override
            public void setUpBeforeEachTest() throws SignatureException {
                for(int i = 0; i < tokensToTest; ++i) {
                    secureRandom.nextBytes(beaconValues[i]);
                    ecdsaSign.update(beaconValues[i]);
                    signedValues[i] = ecdsaSign.sign();
                }
            }

            @Override
            public void runTest() throws Exception {
                for(int i = 0; i < tokensToTest; ++i) {
                    ecdsaFailVerify.update(beaconValues[i]);
                    if (ecdsaFailVerify.verify(signedValues[i])) {
                        fail();
                    }
                }
            }
        });

    }
}
