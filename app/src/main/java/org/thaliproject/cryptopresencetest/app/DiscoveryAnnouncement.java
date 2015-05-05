package org.thaliproject.cryptopresencetest.app;

import android.support.annotation.NonNull;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.HKDFParameters;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Dictionary;
import java.util.Set;

public class DiscoveryAnnouncement {
    public static final String keyGeneratorType = "ECDH";
    public static final String cryptoEngine = "SC";
    public static final String ecName = "secp256k1";
    public static final Digest bouncyDigest = new SHA256Digest();
    public static final String macName = "SHA-256";
    public static final String hmacName = "HmacSHA256";
    public static final int hashSizeInBytes = 16; // We use SHA-256 but truncate
    public static final int ivSizeInBytes = 16; // AES 128 IV size
    public static final int aesKeySize = ivSizeInBytes;
    public static final int beaconHmacKeySize = 32;
    public static final String aesInstanceString = "AES/GCM/NoPadding";
    public static final int x509KeyEncodingInBytes = 88;
    public static final int beaconSize = 48;
    public static final long minimumMillisIntoTheFuture = 60 * 1000;
    public static final long maximumMillisIntoTheFuture = 24 * 60 * 60 * 1000;

    public static long createExpiration(long millisecondsIntoTheFutureToExpire) {
        final long expiration =
                System.currentTimeMillis() + millisecondsIntoTheFutureToExpire;
        validateExpiration(expiration);
        return expiration;
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
    public static byte[] createIV() {
        final byte[] ivBytes = new byte[ivSizeInBytes];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        return ivBytes;
    }

    @NonNull
    public static byte[] generateDiscoveryAnnouncement(
            @NonNull Set<ECPublicKey> listOfReceivingDevicesPublicKeys,
            @NonNull KeyPair kx, @NonNull byte[] iv, @NonNull KeyPair ke,
            long expiration) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException,
            BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        final int lengthOfBeacon = 48;
        validateKeyPair(kx, "kx");
        validateKeyPair(ke, "ke");

        ByteBuffer discoveryAnnouncementByteBuffer =
                ByteBuffer.allocate(Long.SIZE + ke.getPublic().getEncoded().length +
                    iv.length + (lengthOfBeacon * listOfReceivingDevicesPublicKeys.size()));

        discoveryAnnouncementByteBuffer.putLong(expiration);
        discoveryAnnouncementByteBuffer.put(ke.getPublic().getEncoded());
        discoveryAnnouncementByteBuffer.put(iv);

        byte[] insideBeaconKeyId = generateInsideBeaconKeyId((ECPublicKey)kx.getPublic());

        for(ECPublicKey pubKy : listOfReceivingDevicesPublicKeys) {
            validatePublicKey(pubKy, "pubKy");
            discoveryAnnouncementByteBuffer.put(
                    generateBeacon(pubKy, kx, ke, iv, expiration, insideBeaconKeyId));
        }

        byte[] discoveryAnnouncement = new byte[discoveryAnnouncementByteBuffer.position()];
        discoveryAnnouncementByteBuffer.rewind();
        discoveryAnnouncementByteBuffer.get(discoveryAnnouncement);
        return discoveryAnnouncement;
    }

    @NonNull
    public static byte[] generateDiscoveryAnnouncement(
            @NonNull Set<ECPublicKey> listOfReceivingDevicesPublicKeys,
            @NonNull KeyPair kx, long millisecondsInTheFutureToExpire)
            throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        return generateDiscoveryAnnouncement(listOfReceivingDevicesPublicKeys,
                kx, createIV(), createKeyPair(),
                createExpiration(millisecondsInTheFutureToExpire));
    }

    public static byte[] parseDiscoveryAnnouncement(
            @NonNull byte[] discoveryAnnouncement,
            @NonNull Dictionary<ByteBuffer, ECPublicKey> addressBook,
            @NonNull KeyPair ky) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(discoveryAnnouncement);

        final long expiration = byteBuffer.getLong();
        validateExpiration(expiration);

        final byte[] x509EncodedKey = new byte[x509KeyEncodingInBytes];
        byteBuffer.get(x509EncodedKey);
        ECPublicKey pubKe = transformX509EncodedKey(x509EncodedKey);

        final byte[] iv = new byte[ivSizeInBytes];
        byteBuffer.get(iv);

        byte[] rawBeacon = new byte[beaconSize];
        while(byteBuffer.hasRemaining()) {
            byteBuffer.get(rawBeacon);
            byte[] validatedCallerId = parseBeacon(rawBeacon, addressBook, ky, iv, pubKe,
                    expiration);
            if (validatedCallerId != null) {
                return validatedCallerId;
            }
        }
        return null;
    }

    protected static byte[] parseBeacon(@NonNull byte[] rawBeacon,
                                        @NonNull Dictionary<ByteBuffer, ECPublicKey> addressBook,
                                        @NonNull KeyPair ky,
                                        @NonNull byte[] iv,
                                        @NonNull ECPublicKey pubKe,
                                        long expiration) {
        try {
            byte[] hkey = generateECDHWithHKDF((ECPrivateKey) ky.getPrivate(),
                    pubKe, iv, aesKeySize);
            SecretKeySpec hkeySecretKeySpec = new SecretKeySpec(hkey, "AES");
            Cipher cipher = Cipher.getInstance(aesInstanceString);

            cipher.init(Cipher.DECRYPT_MODE, hkeySecretKeySpec,
                    new IvParameterSpec(iv));

            byte[] unencryptedBeacon = cipher.doFinal(rawBeacon);

            ByteBuffer unencryptedBeaconByteBuffer =
                    ByteBuffer.wrap(unencryptedBeacon);

            byte[] insideBeaconKeyId = new byte[hashSizeInBytes];
            unencryptedBeaconByteBuffer.get(insideBeaconKeyId);
            ECPublicKey pubKx = addressBook.get(ByteBuffer.wrap(insideBeaconKeyId));

            if (pubKx == null) {
                return null;
            }

            byte[] receivedInsideBeaconHmac = new byte[hashSizeInBytes];
            unencryptedBeaconByteBuffer.get(receivedInsideBeaconHmac);

            byte[] calculatedInsideBeaconHmac =
                    generateInsideBeaconHmac((ECPrivateKey) ky.getPrivate(),
                            pubKx, iv, expiration);

            if (Arrays.equals(receivedInsideBeaconHmac, calculatedInsideBeaconHmac)) {
                return insideBeaconKeyId;
            }

            return null;
        } catch(AEADBadTagException e) {
            return null;
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                IllegalBlockSizeException | BadPaddingException |
                InvalidAlgorithmParameterException |
                NoSuchPaddingException | InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @NonNull
    protected static ECPublicKey transformX509EncodedKey(@NonNull byte[] x509EncodedKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyGeneratorType, cryptoEngine);
            X509EncodedKeySpec x509EncodedKeySpec =
                    new X509EncodedKeySpec(x509EncodedKey);
            ECPublicKey ecPublicKey =
                    (ECPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            validatePublicKey(ecPublicKey, "x509EncodedKey");
            return ecPublicKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException |
                NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected static void validateExpiration(long expiration) {
        final long timeLeftToExpire = expiration - System.currentTimeMillis();

        if (timeLeftToExpire < minimumMillisIntoTheFuture ||
                timeLeftToExpire > maximumMillisIntoTheFuture) {
            throw new IllegalArgumentException("Illegal expiration");
        }
    }

    @NonNull
    protected static byte[] generateBeacon(
            @NonNull ECPublicKey pubKy, @NonNull KeyPair kx, @NonNull KeyPair ke,
            @NonNull byte[] iv, long expiration, @NonNull byte[] insideBeaconKeyId)
            throws NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        byte[] insideBeaconKeyIdInsideBeaconHmac =
                new byte[hashSizeInBytes * 2];

        // Creates InsideBeaconKeyId
        System.arraycopy(insideBeaconKeyId,
                0,
                insideBeaconKeyIdInsideBeaconHmac,
                0,
                hashSizeInBytes);

        // Creates InsideBeaconHmac
        byte[] insideBeaconHmac =
                generateInsideBeaconHmac((ECPrivateKey)kx.getPrivate(),
                        pubKy, iv, expiration);

        System.arraycopy(insideBeaconHmac,
                0,
                insideBeaconKeyIdInsideBeaconHmac,
                hashSizeInBytes,
                hashSizeInBytes);

        // Creates actual beacon value
        byte[] hkey = generateECDHWithHKDF((ECPrivateKey) ke.getPrivate(),
                pubKy, iv, aesKeySize);

        SecretKeySpec hkeySecretKeySpec = new SecretKeySpec(hkey, "AES");
        Cipher cipher = Cipher.getInstance(aesInstanceString);

        cipher.init(Cipher.ENCRYPT_MODE,
                hkeySecretKeySpec,
                new GCMParameterSpec(16 * Byte.SIZE, iv));

        return cipher.doFinal(insideBeaconKeyIdInsideBeaconHmac);
    }

    @NonNull
    protected static byte[] generateInsideBeaconKeyId(@NonNull ECPublicKey publicKey)
            throws NoSuchAlgorithmException {
        MessageDigest messageDigest =
                MessageDigest.getInstance(DiscoveryAnnouncement.macName);
        messageDigest.update(publicKey.getEncoded());
        byte[] fullSizeKeyHash = messageDigest.digest();
        byte[] keyIndex = new byte[DiscoveryAnnouncement.hashSizeInBytes];
        System.arraycopy(fullSizeKeyHash, 0, keyIndex, 0, keyIndex.length);
        return keyIndex;
    }


    @NonNull
    private static byte[] generateInsideBeaconHmac(@NonNull ECPrivateKey privateKey,
                                                   @NonNull ECPublicKey publicKey,
                                                   @NonNull byte[] iv,
                                                   long expiration)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        ByteBuffer ivExpirationBuffer = ByteBuffer.allocate(hashSizeInBytes * 2);
        ivExpirationBuffer.put(iv);
        ivExpirationBuffer.putLong(expiration);

        byte[] hkxy = generateECDHWithHKDF(privateKey, publicKey, iv, beaconHmacKeySize);
        Mac hmac = Mac.getInstance(hmacName);
        SecretKeySpec hkxySecretKeySpec = new SecretKeySpec(hkxy, "RAW");
        hmac.init(hkxySecretKeySpec);
        byte[] hmacBuffer = new byte[ivExpirationBuffer.position()];
        ivExpirationBuffer.rewind();
        ivExpirationBuffer.get(hmacBuffer);
        return Arrays.copyOf(hmac.doFinal(hmacBuffer), hashSizeInBytes);
    }

    @NonNull
    protected static byte[] generateECDHWithHKDF(@NonNull ECPrivateKey privateKey,
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

    protected static void validatePublicKey(@NonNull ECPublicKey publicKey, String argName) {
        final String publicKeyEncodingFormat = "X.509";

        try {
            if (validatePublicKeyCurve(publicKey) == false) {
                throw new IllegalArgumentException(argName + " must be from curve" + ecName);
            }

            if (publicKey.getFormat().equals(publicKeyEncodingFormat) == false) {
                throw new IllegalArgumentException(argName + " must have X.509 as its encoding");
            }

            if (publicKey.getAlgorithm().equals(keyGeneratorType) == false) {
                throw new IllegalArgumentException(argName +
                        " must have an algorithm of type " + keyGeneratorType);
            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected static void validateKeyPair(@NonNull KeyPair kx, String argName) {
        if (!(kx.getPublic() instanceof ECPublicKey)) {
            throw new IllegalArgumentException(argName + " must be an EC Key");
        }

        validatePublicKey((ECPublicKey) kx.getPublic(), argName);
    }

    /**
     * This is an awful hack to check a public key type, don't do this in the real world!
     * Note that if we want to use reflection there is, at least in Android, a private property
     * on the referenceSpec class called name.
     * @param publicKey key to check
     * @return true if the key is of the appropriate type for discovery, otherwise false
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    protected static boolean validatePublicKeyCurve(@NonNull ECPublicKey publicKey)
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
