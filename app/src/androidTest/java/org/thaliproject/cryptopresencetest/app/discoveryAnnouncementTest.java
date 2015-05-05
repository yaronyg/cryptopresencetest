package org.thaliproject.cryptopresencetest.app;

import android.test.AndroidTestCase;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

public class DiscoveryAnnouncementTest extends AndroidTestCase {
    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public void testCreateExpiration() {
        testIAE(new TestIAEInterface() {
            @Override
            public void call() throws IllegalArgumentException {
                DiscoveryAnnouncement.createExpiration(-1);
            }
        });

        testIAE(new TestIAEInterface() {
            @Override
            public void call() throws IllegalArgumentException {
                DiscoveryAnnouncement
                        .createExpiration(DiscoveryAnnouncement.minimumMillisIntoTheFuture - 1);
            }
        });

        testIAE(new TestIAEInterface() {
            @Override
            public void call() throws IllegalArgumentException {
                DiscoveryAnnouncement
                        .createExpiration(DiscoveryAnnouncement.maximumMillisIntoTheFuture + 1);
            }
        });

        long nearZero = DiscoveryAnnouncement
                .createExpiration(DiscoveryAnnouncement.minimumMillisIntoTheFuture)
                - System.currentTimeMillis()
                - DiscoveryAnnouncement.minimumMillisIntoTheFuture;

        // I am arbitrarily picking 10 ms as the window within which I expect
        // createExpiration to return and for System.currentTimeMillis() to be called.
        assertTrue(nearZero >= 0 && nearZero <= 10);
    }

    public void testValidateKeyPair() throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Not an EC Key
        final KeyPairGenerator rsaKeyPairGenerator =
                KeyPairGenerator.getInstance("RSA", DiscoveryAnnouncement.cryptoEngine);
        rsaKeyPairGenerator.initialize(1024);
        testIAE(new TestIAEInterface() {
            @Override
            public void call() throws IllegalArgumentException {
                DiscoveryAnnouncement.validateKeyPair(rsaKeyPairGenerator.generateKeyPair(),
                        "test");
            }
        });

        // Wrong curve
        final KeyPairGenerator ecKeyPairGenerator =
            KeyPairGenerator.getInstance(DiscoveryAnnouncement.keyGeneratorType,
                    DiscoveryAnnouncement.cryptoEngine);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("prime192v1");
        ecKeyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        testIAE(new TestIAEInterface() {
            @Override
            public void call() throws IllegalArgumentException {
                DiscoveryAnnouncement.validateKeyPair(ecKeyPairGenerator.generateKeyPair(),
                        "test");
            }
        });

        // Wrong key type
        final KeyPairGenerator ecKeyPairGenerator2 = KeyPairGenerator.getInstance("ECDSA",
                DiscoveryAnnouncement.cryptoEngine);
        ecGenParameterSpec = new ECGenParameterSpec(DiscoveryAnnouncement.ecName);
        ecKeyPairGenerator2.initialize(ecGenParameterSpec, new SecureRandom());
        testIAE(new TestIAEInterface() {
            @Override
            public void call() throws IllegalArgumentException {
                DiscoveryAnnouncement.validateKeyPair(ecKeyPairGenerator2.generateKeyPair(),
                        "test");
            }
        });
    }

    public void testCreateIv() {
        byte[] iv = DiscoveryAnnouncement.createIV();
        assertTrue(iv.length == DiscoveryAnnouncement.ivSizeInBytes);
    }

    public void testGenerateDiscoveryAnnouncement() throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, InvalidKeyException {
        Dictionary<ByteBuffer, ECPublicKey> kyAddressBook = new Hashtable<>();
        Set<ECPublicKey> kxListOfReceivingDevicesPublicKeys = new HashSet<>();

        KeyPair ky = null;

        for(int i = 0; i < 1; ++i) {
            KeyPair keyPair = DiscoveryAnnouncement.createKeyPair();
            if (ky == null) {
                ky = keyPair;
            }
            kxListOfReceivingDevicesPublicKeys.add((ECPublicKey) keyPair.getPublic());
        }

        KeyPair kx = DiscoveryAnnouncement.createKeyPair();
        byte[] kxIndex = DiscoveryAnnouncement
                .generateInsideBeaconKeyId((ECPublicKey) kx.getPublic());

        kyAddressBook.put(ByteBuffer.wrap(kxIndex), (ECPublicKey) kx.getPublic());

        final long millisecondsUntilExpiry = 1000 * 60 * 2;

        byte[] discoveryAnnouncement = DiscoveryAnnouncement
                .generateDiscoveryAnnouncement(kxListOfReceivingDevicesPublicKeys,
                        kx, millisecondsUntilExpiry);

        byte[] shouldBeKxIndex =
                DiscoveryAnnouncement
                        .parseDiscoveryAnnouncement(discoveryAnnouncement, kyAddressBook, ky);

        assertTrue(Arrays.equals(shouldBeKxIndex, kxIndex));

        KeyPair noMatchingKy = DiscoveryAnnouncement.createKeyPair();

        byte[] shouldBeNull =
                DiscoveryAnnouncement
                .parseDiscoveryAnnouncement(discoveryAnnouncement, kyAddressBook, noMatchingKy);

        assertTrue(shouldBeNull == null);
    }

    interface TestIAEInterface {
        void call() throws IllegalArgumentException;
    }

    private void testIAE(TestIAEInterface test) {
        try {
            test.call();
            fail();
        } catch(IllegalArgumentException e) {
            assertTrue(true);
        }
    }
}
