package org.thaliproject.cryptopresencetest.app;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class CompareSizeInvariantOptionsTest extends BaseCryptoTest {
    final int addressBookSize = 10000;
    final int entriesInAnnouncement = 20;

    final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
    KeyPairGenerator keyPairGenerator;
    KeyPair ephemeralKeyPair, deviceKeyPair;
    byte[] timeStamp = Md5HashTests.generateTimeStampAsBytes();

    // Shared AES state
    SecretKeySpec foreignKeyInAddressBook;
    byte[] md5OfForeignDevicePublicKey = new byte[md5HashSizeInBytes];
    byte[] hmacMd5OfForeignDeviceKeyAndTimeStamp;
    byte[] unencryptedBeacon = new byte[md5HashSizeInBytes*2];
    byte[] encryptedBeacon;
    byte[] iv = new byte[AESTests.aes128BlockSizeInBytes];
    Mac hmac5;
    Cipher decryptCipher;


    public void setUp() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "SC");
        keyPairGenerator.initialize(ecGenParameterSpec, secureRandom);
        hmac5 = Mac.getInstance("HMacmd5");
    }

    public void testHmacHmac() throws Exception {
        TestCommand.runAndLogTest("Test hmac/hmac against " + entriesInAnnouncement +
                        " announcements with " + addressBookSize + " entries in the address book", 100,
                new TestCommand() {
                    SecretKeySpec[] addressBook =
                            Md5HashTests.generateHmacKeys(addressBookSize, twoHundredFiftySixBitKeyInBytes);
                    byte[][] flags = new byte[entriesInAnnouncement][md5HashSizeInBytes];
                    byte[][] beacons = new byte[entriesInAnnouncement][md5HashSizeInBytes];
                    Mac hmac5 = Mac.getInstance("HMACMD5");

                    @Override
                    void setUpBeforeEachTest() throws InvalidKeyException, NoSuchProviderException,
                            NoSuchAlgorithmException {
                        setFlags(flags, timeStamp, hmac5);

                        for (int i = 0; i < entriesInAnnouncement - 1; ++i) {
                            secureRandom.nextBytes(beacons[i]);
                        }

                        beacons[entriesInAnnouncement - 1] =
                                Md5HashTests.generateHmac(timeStamp, addressBook[addressBookSize - 1], hmac5);

                    }

                    @Override
                    void runTest() throws Exception {
                        byte[] sharedSecret =
                                generateEcdhSharedSecret(deviceKeyPair.getPrivate(),
                                        ephemeralKeyPair.getPublic());

                        SecretKeySpec hmacForFlag = new SecretKeySpec(sharedSecret, "RAW");

                        for (int i = 0; i < entriesInAnnouncement; ++i) {
                            if (Arrays.equals(flags[i], Md5HashTests.generateHmac(timeStamp, hmacForFlag,
                                    hmac5))) {
                                byte[] matchingBeacon = beacons[i];
                                for (SecretKeySpec addressBookKey : addressBook) {
                                    if (Arrays.equals(matchingBeacon,
                                            Md5HashTests.generateHmac(timeStamp, addressBookKey, hmac5))) {
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
        TestCommand.runAndLogTest("Test hmac-aes-cbc against " + entriesInAnnouncement +
                        " announcements ", 100,
                new TestCommand() {
                    byte[][] flags = new byte[entriesInAnnouncement][md5HashSizeInBytes];

                    @Override
                    void setUpBeforeEachTest() throws InvalidKeyException, NoSuchProviderException,
                            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
                            BadPaddingException, IllegalBlockSizeException {
                        SecretKey ephemeralDeviceECDHKey = setFlags(flags, timeStamp, hmac5);

                        createAesState(ephemeralDeviceECDHKey, AesType.CBC);
                    }

                    @Override
                    void runTest() throws Exception {
                        SecretKeySpec sharedEphemeralKey =
                                getAes128SizedSecret(deviceKeyPair.getPrivate(), ephemeralKeyPair.getPublic());

                        for (int i = 0; i < entriesInAnnouncement; ++i) {
                            if (Arrays.equals(flags[i],
                                    Md5HashTests.generateHmac(timeStamp, sharedEphemeralKey,
                                    hmac5))) {
                                decryptCipher.init(Cipher.DECRYPT_MODE, sharedEphemeralKey,
                                        new IvParameterSpec(iv));
                                byte[] decryptedContent = decryptCipher.doFinal(encryptedBeacon);
                                assertTrue(Arrays.equals(decryptedContent, unencryptedBeacon));

                                byte[] hmacInDecryptedContent =
                                        Arrays.copyOfRange(decryptedContent,
                                                md5OfForeignDevicePublicKey.length,
                                                decryptedContent.length);
                                byte[] generatedInternalHmac =
                                        Md5HashTests.generateHmac(timeStamp, foreignKeyInAddressBook, hmac5);
                                assertTrue(Arrays.equals(hmacInDecryptedContent, generatedInternalHmac));
                                return;
                            }
                        }
                        fail();
                    }
                });
    }

    public void testHmacAesGcm() throws Exception {
        TestCommand.runAndLogTest("Test aes-gcm against " + entriesInAnnouncement +
                        " announcements ", 100,
                new TestCommand() {
                    byte[][] beacons = new byte[entriesInAnnouncement][];

                    @Override
                    void setUpBeforeEachTest() throws InvalidKeyException, NoSuchProviderException,
                            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
                            BadPaddingException, IllegalBlockSizeException {
                        SecretKey aes128Key = createEphemeralSecretKey();

                        createAesState(aes128Key, AesType.GCM);

                        decryptCipher.init(Cipher.DECRYPT_MODE, aes128Key, new IvParameterSpec(iv));
                        byte[] foo = decryptCipher.doFinal(encryptedBeacon);
                        assertTrue(Arrays.equals(foo, unencryptedBeacon));


                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(128);

                        for(int i = 0; i < beacons.length - 1; ++i) {
                            Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");

                            encryptCipher.init(Cipher.ENCRYPT_MODE, keyGenerator.generateKey(),
                                    new GCMParameterSpec(16 * Byte.SIZE, iv));

                            System.arraycopy(md5OfForeignDevicePublicKey, 0, unencryptedBeacon, 0,
                                    md5OfForeignDevicePublicKey.length);

                            System.arraycopy(hmacMd5OfForeignDeviceKeyAndTimeStamp, 0, unencryptedBeacon,
                                    md5OfForeignDevicePublicKey.length,
                                    hmacMd5OfForeignDeviceKeyAndTimeStamp.length);

                            beacons[i] = encryptCipher.doFinal(unencryptedBeacon);
                        }

                        beacons[beacons.length - 1] = encryptedBeacon;
                    }

                    @Override
                    void runTest() throws Exception {
                        SecretKeySpec sharedEphemeralKey =
                                getAes128SizedSecret(deviceKeyPair.getPrivate(),
                                        ephemeralKeyPair.getPublic());
                        decryptCipher.init(Cipher.DECRYPT_MODE, sharedEphemeralKey,
                                new IvParameterSpec(iv));

                        for (int i = 0; i < entriesInAnnouncement; ++i) {
                            try {
                                byte[] decryptedContent = decryptCipher.doFinal(beacons[i]);
                                assertTrue(Arrays.equals(decryptedContent, unencryptedBeacon));

                                byte[] hmacInDecryptedContent =
                                        Arrays.copyOfRange(decryptedContent,
                                                md5OfForeignDevicePublicKey.length,
                                                decryptedContent.length);
                                byte[] generatedInternalHmac =
                                        Md5HashTests.generateHmac(timeStamp, foreignKeyInAddressBook, hmac5);
                                assertTrue(Arrays.equals(hmacInDecryptedContent, generatedInternalHmac));
                                return;
                            } catch(AEADBadTagException e) {
                                // Try next entry
                            }
                        }
                        fail();
                    }
                });
    }


    private SecretKeySpec getAes128SizedSecret(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        return new SecretKeySpec(
                Arrays.copyOfRange(
                        generateEcdhSharedSecret(privateKey, publicKey),
                        0, AESTests.aes128BlockSizeInBytes), "AES");
    }

    private enum AesType { CBC, GCM }

    private void createAesState(SecretKey ephemeralDeviceECDHKey,
                                AesType aesType) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        secureRandom.nextBytes(iv);

        String cipherInstance;
        AlgorithmParameterSpec algorithmParameterSpec;

        switch(aesType) {
            case CBC:
                cipherInstance = "AES/CBC/PKCS5Padding";
                algorithmParameterSpec = new IvParameterSpec(iv);
                break;
            case GCM:
                cipherInstance = "AES/GCM/NoPadding";
                algorithmParameterSpec = new GCMParameterSpec(16 * Byte.SIZE, iv);
                break;
            default:
                fail();
                return;
        }


        foreignKeyInAddressBook =
                Md5HashTests.generateHmacKeys(1, twoHundredFiftySixBitKeyInBytes)[0];

        secureRandom.nextBytes(md5OfForeignDevicePublicKey);

        hmacMd5OfForeignDeviceKeyAndTimeStamp =
                Md5HashTests.generateHmac(timeStamp, foreignKeyInAddressBook, hmac5);

        Cipher encryptCipher = Cipher.getInstance(cipherInstance);
        decryptCipher = Cipher.getInstance(cipherInstance);

        encryptCipher.init(Cipher.ENCRYPT_MODE, ephemeralDeviceECDHKey,
                algorithmParameterSpec);

        System.arraycopy(md5OfForeignDevicePublicKey, 0, unencryptedBeacon, 0,
                md5OfForeignDevicePublicKey.length);

        System.arraycopy(hmacMd5OfForeignDeviceKeyAndTimeStamp, 0, unencryptedBeacon,
                md5OfForeignDevicePublicKey.length,
                hmacMd5OfForeignDeviceKeyAndTimeStamp.length);

        encryptedBeacon = encryptCipher.doFinal(unencryptedBeacon);
    }

    private SecretKeySpec createEphemeralSecretKey() throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException {
        ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        deviceKeyPair = keyPairGenerator.generateKeyPair();

        return getAes128SizedSecret(ephemeralKeyPair.getPrivate(), deviceKeyPair.getPublic());
    }

    private byte[] generateEcdhSharedSecret(PrivateKey privateKey, PublicKey publicKey)
            throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        KeyAgreement ephemeralKeyAgreement = KeyAgreement.getInstance("ECDH", "SC");
        ephemeralKeyAgreement.init(privateKey);
        ephemeralKeyAgreement.doPhase(publicKey, true);
        return ephemeralKeyAgreement.generateSecret();
    }

    private SecretKeySpec setFlags(byte[][] flags, byte[] timeStamp, Mac hmac5) throws NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidKeyException {
        for(int i = 0; i < entriesInAnnouncement - 1; ++i) {
            secureRandom.nextBytes(flags[i]);
        }

        SecretKeySpec hmacEphemeralKey = createEphemeralSecretKey();

        flags[entriesInAnnouncement - 1] =
                Md5HashTests.generateHmac(timeStamp, hmacEphemeralKey, hmac5);

        return hmacEphemeralKey;
    }

}
