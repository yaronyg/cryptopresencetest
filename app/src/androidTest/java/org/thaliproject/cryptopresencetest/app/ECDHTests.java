package org.thaliproject.cryptopresencetest.app;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDHTests extends BaseCryptoTest {
    public void testECDHTiming() throws Exception {
        final ECGenParameterSpec ecGenSpecForStaticDH = new ECGenParameterSpec("secp256k1");
        final KeyPairGenerator keyPairGeneratorStaticDH = KeyPairGenerator.getInstance("ECDH", "SC");

        keyPairGeneratorStaticDH.initialize(ecGenSpecForStaticDH, secureRandom);
        final int numberOfRunsPerTest = 1;
        TestCommand.runAndLogTest("Generate static-static ECDH key", 1000, new TestCommand() {
            KeyPair[] ephemeralKeyPair = new KeyPair[numberOfRunsPerTest];

            KeyPair[] yKeyPair = new KeyPair[numberOfRunsPerTest];
            KeyAgreement[] yKeyAgree = new KeyAgreement[numberOfRunsPerTest];

            @Override
            void setUpBeforeEachTest() throws NoSuchProviderException, NoSuchAlgorithmException,
                    InvalidKeyException {
                for(int i = 0; i < numberOfRunsPerTest; ++i) {
                    ephemeralKeyPair[i] = keyPairGeneratorStaticDH.generateKeyPair();
                    yKeyPair[i] = keyPairGeneratorStaticDH.generateKeyPair();
                    yKeyAgree[i] = KeyAgreement.getInstance("ECDH", "SC");
                    yKeyAgree[i].init(yKeyPair[i].getPrivate());
                }
            }

            @Override
            void runTest() throws Exception {
                for(int i = 0; i < numberOfRunsPerTest; ++i) {
                    yKeyAgree[i].doPhase(ephemeralKeyPair[i].getPublic(), true);
                    yKeyAgree[i].generateSecret();
                }
            }
        });

    }
}
