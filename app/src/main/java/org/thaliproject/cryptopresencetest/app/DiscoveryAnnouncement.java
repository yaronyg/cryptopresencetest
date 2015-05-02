package org.thaliproject.cryptopresencetest.app;

import android.support.annotation.NonNull;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.HKDFParameters;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

public class DiscoveryAnnouncement {
    public static final String keyGeneratorType = "ECDH";
    public static final String cryptoEngine = "SC";
    public static final String ecName = "secp256k1";
    public static final Digest bouncyDigest = new SHA256Digest();
    public static final String macName = "SHA256";
    public static final int hashSizeInBytes = 16; // We use SHA-256 but truncate
    public static final int ivSizeInBytes = 16; // AES 128 IV size
    public static final int aesKeySize = ivSizeInBytes;
    public static final String aesInstanceString = "AES/GCM/NoPadding";
    public static final int x509PubKeySizeInBytes = 88;

    @NonNull
    public static long createExpiration(long millisecondsIntoTheFutureToExpire) {
        final long minimumMillisIntoTheFuture = 60 * 1000;
        final long maximumMillisIntoTheFuture = 24 * 60 * 60 * 1000;

        if (millisecondsIntoTheFutureToExpire <= minimumMillisIntoTheFuture ||
                millisecondsIntoTheFutureToExpire >= maximumMillisIntoTheFuture) {
            throw new IllegalArgumentException(
                    "millisecondsIntoTheFutureToExpire must be great than" +
                    minimumMillisIntoTheFuture + "ms into the future and less than " +
                    maximumMillisIntoTheFuture + "ms");
        }

        return System.currentTimeMillis() + millisecondsIntoTheFutureToExpire;
    }

    @NonNull
    public static KeyPair createKeyPair() throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance(keyGeneratorType, cryptoEngine);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecName);
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    @NonNull
    public static byte[] createX509SubjectPublicKeyInfo(@NonNull ECPublicKey publicKey)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        validatePublicKey(publicKey, "publicKey");
        return publicKey.getEncoded();
    }

    @NonNull
    public static byte[] createIV() {
        final byte[] ivBytes = new byte[ivSizeInBytes];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        return ivBytes;
    }

    @NonNull
    public static byte[] createBeacon(@NonNull ECPublicKey pubKy, @NonNull KeyPair kx,
                                          @NonNull byte[] iv,
                                          @NonNull long expiration)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException,
            IllegalBlockSizeException {
        final int beaconHmacKeySize = 32;

        validatePublicKey(pubKy, "pubKy");
        validateKeyPair(kx, "kx");

        byte[] insideBeaconKeyIdInsideBeaconHmac =
                new byte[hashSizeInBytes * 2];

        // Creates InsideBeaconKeyId
        System.arraycopy(Mac.getInstance(macName).doFinal(kx.getPublic().getEncoded()),
                         0,
                         insideBeaconKeyIdInsideBeaconHmac,
                         0,
                         hashSizeInBytes);

        // Creates InsideBeaconHmac
        byte[] hkxy = generateECDHWithHKDF((ECPrivateKey) kx.getPrivate(),
                pubKy, iv, beaconHmacKeySize);

        ByteBuffer ivExpirationBuffer = ByteBuffer.allocate(hashSizeInBytes * 2);
        ivExpirationBuffer.put(iv);
        ivExpirationBuffer.putLong(expiration);
        ivExpirationBuffer.rewind(); // BUGBUG: Is this necessary?

        Mac hmac = Mac.getInstance("HMAC" + macName);
        SecretKeySpec hkxySecretKeySpec = new SecretKeySpec(hkxy, "RAW");
        hmac.init(hkxySecretKeySpec);
        System.arraycopy(hmac.doFinal(ivExpirationBuffer.array()),
                0,
                insideBeaconKeyIdInsideBeaconHmac,
                hashSizeInBytes,
                hashSizeInBytes);

        // Creates actual beacon value
        KeyPair ke = createKeyPair();
        byte[] hkey = generateECDHWithHKDF((ECPrivateKey) ke.getPrivate(),
                pubKy, iv, aesKeySize);

        SecretKeySpec hkeySecretKeySpec = new SecretKeySpec(hkey, "AES");
        Cipher cipher = Cipher.getInstance(aesInstanceString);

        // WARNING: The parameter spec is specific to GCM so if we change the algorithm
        // this will have to change as well.
        cipher.init(Cipher.ENCRYPT_MODE,
                hkeySecretKeySpec,
                new GCMParameterSpec(16 * Byte.SIZE, iv));

        return cipher.doFinal(insideBeaconKeyIdInsideBeaconHmac);
    }

    @NonNull
    private static byte[] generateECDHWithHKDF(@NonNull ECPrivateKey privateKey,
                                               @NonNull ECPublicKey publicKey,
                                               @NonNull byte[] iv,
                                               int bytesToGenerate)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(keyGeneratorType, cryptoEngine);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] nonUniformSecret = keyAgreement.generateSecret();

        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(bouncyDigest);
        HKDFParameters hkdfParameters = new HKDFParameters(nonUniformSecret, iv, null);
        hkdfBytesGenerator.init(hkdfParameters);
        byte[] uniformSecret = new byte[bytesToGenerate];
        hkdfBytesGenerator.generateBytes(uniformSecret, 0, uniformSecret.length);
        return uniformSecret;
    }

    private static void validatePublicKey(@NonNull ECPublicKey publicKey, String argName)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        final String publicKeyEncodingFormat = "X.509";

        if (!validatePublicKeyCurve(publicKey)) {
            throw new IllegalArgumentException(argName + " must be from curve" + ecName);
        }

        if (publicKey.getFormat().equals(publicKeyEncodingFormat)) {
            throw new IllegalArgumentException(argName + " must have X.509 as its encoding");
        }
    }

    private static void validateKeyPair(@NonNull KeyPair kx, String argName)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        if (!(kx.getPublic() instanceof ECPublicKey)) {
            throw new IllegalArgumentException(argName + " must be an EC Key");
        }

        validatePublicKey((ECPublicKey) kx.getPublic(), argName);
    }

    /**
     * This is an awful hack to check a public key type, don't do this in the real world!
     * @param publicKey key to check
     * @return true if the key is of the appropriate type for discovery, otherwise false
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private static boolean validatePublicKeyCurve(@NonNull ECPublicKey publicKey)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {

        KeyPair testKeyPair = createKeyPair();
        ECParameterSpec referenceSpec = ((ECPublicKey) testKeyPair.getPublic()).getParams();
        ECParameterSpec testSpec = publicKey.getParams();

        // I checked and ECParameterSpec does not support a custom equals so
        // I had to break things into parts
        return referenceSpec.getCofactor() == testSpec.getCofactor() &&
                referenceSpec.getCurve().equals(testSpec.getCurve()) &&
                referenceSpec.getGenerator().equals(testSpec.getGenerator()) &&
                referenceSpec.getOrder().equals(testSpec.getOrder());
    }
}
