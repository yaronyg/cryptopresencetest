package org.thaliproject.cryptopresencetest.performanceHack;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.HKDFParameters;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class CompareSizeInvariantOptionsTest extends BaseCryptoTest {
    private final int addressBookSize = 10000;
    private final int entriesInAnnouncement = 20;
    private final String ecName = "secp256k1";
    private final String macAlgorithm = "HMACSHA256";
    private final Digest bouncyDigest = new SHA256Digest();

    private final KeyPair ephemeralKeyPair;
    private final KeyPair deviceKeyPair;
    private final Mac hmac;
    private final byte[] timeStamp = CryptoUtilities.generateTimeStampAsBytes();

    // Shared AES state
    private final byte[] iv = new byte[CryptoUtilities.aes128BlockSizeInBytes];
    private final SecretKeySpec foreignKeyInAddressBook;
    private final byte[] hashOfForeignDevicePublicKey = new byte[hashSizeInBytes];
    private final byte[] ivPlusTimeStamp;
    private final byte[] unencryptedBeacon = new byte[hashSizeInBytes *2];

    public CompareSizeInvariantOptionsTest() throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException {
        super();

        // Initializing to our default values
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "SC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecName);
        keyPairGenerator.initialize(ecGenParameterSpec, secureRandom);
        hmac = Mac.getInstance(macAlgorithm);

        // We use these keys for all scenarios but ECIES which needs different key types
        ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        deviceKeyPair = keyPairGenerator.generateKeyPair();

        // This code creates the unencrypted version of the beacon used everywhere but
        // HMAC/HMAC
        secureRandom.nextBytes(iv);

        ivPlusTimeStamp = new byte[iv.length + timeStamp.length];
        System.arraycopy(iv, 0, ivPlusTimeStamp, 0, iv.length);
        System.arraycopy(timeStamp, 0, ivPlusTimeStamp, iv.length, timeStamp.length);

        foreignKeyInAddressBook =
                CryptoUtilities.generateHmacKeys(1, twoHundredFiftySixBitKeyInBytes)[0];
        secureRandom.nextBytes(hashOfForeignDevicePublicKey);
        byte[] hmacOfIvPlusTimeStamp =
                CryptoUtilities.generate128BitHash(ivPlusTimeStamp,
                        foreignKeyInAddressBook, hmac);

        System.arraycopy(hashOfForeignDevicePublicKey, 0, unencryptedBeacon, 0,
                hashOfForeignDevicePublicKey.length);

        System.arraycopy(hmacOfIvPlusTimeStamp, 0, unencryptedBeacon,
                hashOfForeignDevicePublicKey.length,
                hmacOfIvPlusTimeStamp.length);
    }

    public void testHmacHmac() throws Exception {
        PerfTest.runAndLogTest("Test hmac/hmac against " + entriesInAnnouncement +
                        " announcements with " + addressBookSize +
                        " entries in the address book", 10,
                new PerfTest() {
                    final SecretKeySpec[] addressBook =
                            CryptoUtilities.generateHmacKeys(addressBookSize,
                                    twoHundredFiftySixBitKeyInBytes);
                    final byte[][] flags = new byte[entriesInAnnouncement][hashSizeInBytes];
                    final byte[][] beacons = new byte[entriesInAnnouncement][hashSizeInBytes];

                    @Override
                    void setUpBeforeEachPerfRun() throws InvalidKeyException,
                            NoSuchProviderException,
                            NoSuchAlgorithmException {
                        createKeysAndSetFlags(flags, timeStamp, hmac);

                        for (int i = 0; i < entriesInAnnouncement - 1; ++i) {
                            secureRandom.nextBytes(beacons[i]);
                        }

                        beacons[entriesInAnnouncement - 1] =
                                CryptoUtilities.generate128BitHash(
                                        timeStamp,
                                        addressBook[addressBookSize - 1],
                                        hmac);
                    }

                    @Override
                    void runPerfTest() throws Exception {
                        byte[] sharedSecret =
                                generateEcdhSharedSecretWithKDF(deviceKeyPair.getPrivate(),
                                        ephemeralKeyPair.getPublic());

                        SecretKeySpec hmacForFlag = new SecretKeySpec(sharedSecret, "RAW");

                        for (int i = 0; i < entriesInAnnouncement; ++i) {
                            if (Arrays.equals(
                                    flags[i],
                                    CryptoUtilities.generate128BitHash(timeStamp, hmacForFlag,
                                            hmac))) {
                                byte[] matchingBeacon = beacons[i];
                                for (SecretKeySpec addressBookKey : addressBook) {
                                    if (Arrays.equals(
                                            matchingBeacon,
                                            CryptoUtilities.generate128BitHash(timeStamp,
                                                    addressBookKey, hmac))) {
                                        assertTrue(true);
                                        return;
                                    }
                                }
                            }
                        }
                        fail();
                    }
                });
    }

    public void testHmacAesCbc() throws Exception {
        PerfTest.runAndLogTest("Test hmac-aes-cbc against " + entriesInAnnouncement +
                        " announcements ", 100,
                new PerfTest() {
                    final byte[][] flags = new byte[entriesInAnnouncement][hashSizeInBytes];
                    byte[] encryptedBeacon = new byte[hashSizeInBytes];
                    Cipher decryptCipher;

                    @Override
                    void setUpBeforeEachPerfRun() throws InvalidKeyException,
                            NoSuchProviderException,
                            NoSuchAlgorithmException, NoSuchPaddingException,
                            InvalidAlgorithmParameterException,
                            BadPaddingException, IllegalBlockSizeException {
                        createKeysAndSetFlags(flags, ivPlusTimeStamp, hmac);

                        decryptCipher = CryptoUtilities.createAesCipher(CryptoUtilities.AesType.CBC);
                        encryptedBeacon = encryptBeacon(CryptoUtilities.AesType.CBC, iv);
                    }

                    @Override
                    void runPerfTest() throws Exception {
                        byte[] sharedSecret =
                                generateEcdhSharedSecretWithKDF(deviceKeyPair.getPrivate(),
                                        ephemeralKeyPair.getPublic());

                        SecretKeySpec hmacForFlag = new SecretKeySpec(sharedSecret, "RAW");

                        SecretKeySpec aes128Key = new SecretKeySpec(
                                Arrays.copyOfRange(sharedSecret, 0,
                                        CryptoUtilities.aes128BlockSizeInBytes),
                                "AES");

                        for (int i = 0; i < entriesInAnnouncement; ++i) {
                            if (Arrays.equals(flags[i],
                                    CryptoUtilities.generate128BitHash(ivPlusTimeStamp,
                                            hmacForFlag,
                                            hmac))) {
                                decryptCipher.init(Cipher.DECRYPT_MODE, aes128Key,
                                        new IvParameterSpec(iv));
                                byte[] decryptedContent = decryptCipher.doFinal(encryptedBeacon);
                                validateUnencryptedBeacon(decryptedContent);
                                return;
                            }
                        }
                        fail();
                    }
                });
    }

    public void testHmacAesGcm() throws Exception {
        PerfTest.runAndLogTest("Test aes-gcm against " + entriesInAnnouncement +
                        " announcements ", 100,
                new PerfTest() {
                    final byte[][] beacons = new byte[entriesInAnnouncement][];
                    byte[] encryptedBeacon = new byte[hashSizeInBytes];
                    Cipher decryptCipher;

                    @Override
                    void setUpBeforeEachPerfRun() throws InvalidKeyException,
                            NoSuchProviderException,
                            NoSuchAlgorithmException, NoSuchPaddingException,
                            InvalidAlgorithmParameterException,
                            BadPaddingException, IllegalBlockSizeException {
                        decryptCipher =
                                CryptoUtilities.createAesCipher(CryptoUtilities.AesType.GCM);
                        encryptedBeacon = encryptBeacon(CryptoUtilities.AesType.GCM, iv);

                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(128);

                        for (int i = 0; i < beacons.length - 1; ++i) {
                            beacons[i] = encryptBeacon(keyGenerator.generateKey(),
                                    CryptoUtilities.AesType.GCM, iv);
                        }

                        beacons[beacons.length - 1] = encryptedBeacon;
                    }

                    @Override
                    void runPerfTest() throws Exception {
                        SecretKeySpec sharedEphemeralKey =
                                getAes128SizedSecret(deviceKeyPair.getPrivate(),
                                        ephemeralKeyPair.getPublic());

                        for (int i = 0; i < entriesInAnnouncement; ++i) {
                            try {
                                decryptCipher.init(Cipher.DECRYPT_MODE, sharedEphemeralKey,
                                        new IvParameterSpec(iv));
                                byte[] decryptedContent = decryptCipher.doFinal(beacons[i]);
                                validateUnencryptedBeacon(decryptedContent);
                                return;
                            } catch (AEADBadTagException e) {
                                // Try next entry
                            }
                        }
                        fail();
                    }
                });
    }

    public void testEcies() throws Exception {
        // ECIES uses a different key so we need our own key generators
        final KeyPairGenerator eciesKeyPairGenerator =
                KeyPairGenerator.getInstance("EC", "SC");
        eciesKeyPairGenerator.initialize(256, secureRandom);
        final Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC");
        final KeyPair deviceKey = eciesKeyPairGenerator.generateKeyPair();

        PerfTest.runAndLogTest("Test ECIES against " + entriesInAnnouncement +
                " announcements ", 1, new PerfTest() {
            final byte[][] beacons = new byte[entriesInAnnouncement][];

            @Override
            void setUpBeforeEachPerfRun() throws InvalidAlgorithmParameterException,
                    InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

                for (int i = 0; i < entriesInAnnouncement - 1; ++i) {
                    KeyPair bogusDeviceKeyPair = eciesKeyPairGenerator.generateKeyPair();
                    cipher.init(Cipher.ENCRYPT_MODE,
                            bogusDeviceKeyPair.getPublic(), secureRandom);
                    beacons[i] = cipher.doFinal(unencryptedBeacon);
                }

                cipher.init(Cipher.ENCRYPT_MODE, deviceKey.getPublic(), secureRandom);
                beacons[beacons.length - 1] = cipher.doFinal(unencryptedBeacon);
            }

            @Override
            void runPerfTest() throws Exception {
                for (int i = 0; i < entriesInAnnouncement; ++i) {
                    try {
                        cipher.init(Cipher.DECRYPT_MODE, deviceKey.getPrivate(), secureRandom);
                        byte[] decryptedBeacon = cipher.doFinal(beacons[i]);
                        validateUnencryptedBeacon(decryptedBeacon);
                        return;
                    } catch (BadPaddingException e) {
                        // Ignore, failed match
                    }
                }
                fail();
            }
        });
    }

    private void validateUnencryptedBeacon(byte[] decryptedContent) throws
            InvalidKeyException {
        assertTrue(Arrays.equals(decryptedContent, unencryptedBeacon));

        byte[] hmacInDecryptedContent =
                Arrays.copyOfRange(decryptedContent,
                        hashOfForeignDevicePublicKey.length,
                        decryptedContent.length);
        byte[] generatedInternalHmac =
                CryptoUtilities.generate128BitHash(ivPlusTimeStamp,
                        foreignKeyInAddressBook, hmac);
        assertTrue(Arrays.equals(hmacInDecryptedContent, generatedInternalHmac));
    }

    private SecretKeySpec getAes128SizedSecret(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        return new SecretKeySpec(
                Arrays.copyOfRange(
                        generateEcdhSharedSecretWithKDF(privateKey, publicKey),
                        0, CryptoUtilities.aes128BlockSizeInBytes), "AES");
    }

    private byte[] encryptBeacon(CryptoUtilities.AesType aesType, byte[] iv)
            throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        SecretKey aes128Key = getAes128SizedSecret(ephemeralKeyPair.getPrivate(),
                deviceKeyPair.getPublic());

        return encryptBeacon(aes128Key, aesType, iv);
    }

    private byte[] encryptBeacon(SecretKey aes128Key, CryptoUtilities.AesType aesType, byte[] iv)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        AlgorithmParameterSpec algorithmParameterSpec =
                CryptoUtilities.getAlgorithmParameterSpec(aesType, iv);

        Cipher encryptCipher = CryptoUtilities.createAesCipher(aesType);
        encryptCipher.init(Cipher.ENCRYPT_MODE, aes128Key,
                algorithmParameterSpec);

        return encryptCipher.doFinal(unencryptedBeacon);
    }

    private byte[] generateEcdhSharedSecretWithKDF(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        KeyAgreement ephemeralKeyAgreement = KeyAgreement.getInstance("ECDH", "SC");
        ephemeralKeyAgreement.init(privateKey);
        ephemeralKeyAgreement.doPhase(publicKey, true);
        byte[] rawSecret = ephemeralKeyAgreement.generateSecret();

        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(bouncyDigest);
        HKDFParameters hkdfParameters = new HKDFParameters(rawSecret, iv, null);
        hkdfBytesGenerator.init(hkdfParameters);
        byte[] kdfValue = new byte[rawSecret.length];
        hkdfBytesGenerator.generateBytes(kdfValue, 0, kdfValue.length);
        return kdfValue;
    }

    private void createKeysAndSetFlags(byte[][] flags, byte[] valueToHash, Mac hmac5)
            throws NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidKeyException {
        for(int i = 0; i < entriesInAnnouncement - 1; ++i) {
            secureRandom.nextBytes(flags[i]);
        }

        byte[] sharedSecret = generateEcdhSharedSecretWithKDF(ephemeralKeyPair.getPrivate(),
                deviceKeyPair.getPublic());
        SecretKeySpec hmacEphemeralKey =
                new SecretKeySpec(sharedSecret, "RAW");

        flags[entriesInAnnouncement - 1] =
                CryptoUtilities.generate128BitHash(valueToHash, hmacEphemeralKey, hmac5);
    }

}
