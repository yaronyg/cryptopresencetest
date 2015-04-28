package org.thaliproject.cryptopresencetest.app;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.Callable;

public class AESTests extends BaseCryptoTest {
    Cipher encryptCipher, decryptCipher;
    int sizeOfEncryptedContent = md5HashSizeInBytes * 2;
    byte[][] contentToEncrypt;
    byte[][] encryptedContent;
    public static final int aes128BlockSizeInBytes = 16;
    byte[] iv = new byte[aes128BlockSizeInBytes];

    KeyGenerator keyGenerator;
    SecretKey aesKey;

    public void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException {
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
    }

    public void testAesCbcDecryptionTime() throws Exception {
        final int numberOfRuns = 1000;
        runTest("AES+CBC", "AES/CBC/PKCS5Padding", new Callable<AlgorithmParameterSpec>() {
            @Override
            public AlgorithmParameterSpec call() throws Exception {
                return new IvParameterSpec(iv);
            }
        }, numberOfRuns);
    }

    public void testAesGcmDecryptionTime() throws Exception {
        final int numberOfRuns = 1000;
        runTest("AES+GCM", "AES/GCM/NoPadding", new Callable<AlgorithmParameterSpec>() {
            @Override
            public AlgorithmParameterSpec call() throws Exception {
                return new GCMParameterSpec(16 * Byte.SIZE, iv);
            }
        }, numberOfRuns);
    }

    private byte[][] generateContentToEncrypt(int numberOfRuns, int sizeOfRawContent) {
        byte[][] contentToEncrypt = new byte[numberOfRuns][sizeOfRawContent];
        for(int i = 0; i < numberOfRuns; ++i) {
            secureRandom.nextBytes(contentToEncrypt[i]);
        }
        return contentToEncrypt;
    }

    /**
     * Encrypts content
     * @param initedEncryptCipher The Cipher must already be init'd
     * @param contentToEncrypt Content To be encrypted
     * @return encrypted content
     */
    private byte[][] generateEncryptedContent(Cipher initedEncryptCipher, byte[][] contentToEncrypt)
            throws BadPaddingException, IllegalBlockSizeException {
        byte[][] encryptedContent = new byte[contentToEncrypt.length][];
        for(int i = 0; i < contentToEncrypt.length; ++i) {
            encryptedContent[i] = initedEncryptCipher.doFinal(contentToEncrypt[i]);
        }
        return encryptedContent;
    }

    private void runTest(String testName, final String getInstanceType,
                         final Callable<AlgorithmParameterSpec> callable,
                               final int numberOfRuns) throws Exception {
        TestCommand.runAndLogTest(testName + ": Test how long it takes to decrypt " +
                numberOfRuns + " values", 100, new TestCommand() {
            @Override
            public void setUpBeforeEachTest() throws Exception {
                aesKey = keyGenerator.generateKey();

                secureRandom.nextBytes(iv);

                encryptCipher = Cipher.getInstance(getInstanceType);
                decryptCipher = Cipher.getInstance(getInstanceType);

                encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, callable.call());

                contentToEncrypt = generateContentToEncrypt(numberOfRuns, sizeOfEncryptedContent);

                encryptedContent =
                        generateEncryptedContent(encryptCipher, contentToEncrypt);
            }

            @Override
            void runTest() throws Exception {
                decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                for (int i = 0; i < contentToEncrypt.length; ++i) {
                    assertTrue(Arrays.equals(decryptCipher.doFinal(encryptedContent[i]), contentToEncrypt[i]));
                }
            }
        });

    }
}
