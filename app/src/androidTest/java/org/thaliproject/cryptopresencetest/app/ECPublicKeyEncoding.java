package org.thaliproject.cryptopresencetest.app;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class ECPublicKeyEncoding extends BaseCryptoTest {
    static final String ecName = "secp256k1";

    public void testEncodingAndDecodingECPublicECKey() throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeySpecException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "SC");
        final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecName);
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        final KeyPair testKeyPair = keyPairGenerator.generateKeyPair();

        byte[] x509EncodedPublicKey = testKeyPair.getPublic().getEncoded();

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(x509EncodedPublicKey);

        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "SC");
        ECPublicKey reconstitutedPublicKey =
                (ECPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);

        assertTrue(testKeyPair.getPublic().equals(reconstitutedPublicKey));
    }
}
