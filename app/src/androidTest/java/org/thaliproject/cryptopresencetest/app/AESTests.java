package org.thaliproject.cryptopresencetest.app;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

/**
 * This was just some quick and dirty tests to give me a sense of how to
 * use the AES APIs and what their rough perf looks like.
 */
public class AESTests extends BaseCryptoTest {
    final int sizeOfEncryptedContent = hashSizeInBytes * 2;

    public void testAesCbcDecryptionTime() throws Exception {
        final int numberOfRuns = 1000;
        runTest("AES+CBC", CryptoUtilities.AesType.CBC, numberOfRuns);
    }

    public void testAesGcmDecryptionTime() throws Exception {
        final int numberOfRuns = 1000;
        runTest("AES+GCM", CryptoUtilities.AesType.GCM, numberOfRuns);
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
    private byte[][] generateEncryptedContent(Cipher initedEncryptCipher,
                                              byte[][] contentToEncrypt)
            throws BadPaddingException, IllegalBlockSizeException {
        byte[][] encryptedContent = new byte[contentToEncrypt.length][];
        for(int i = 0; i < contentToEncrypt.length; ++i) {
            encryptedContent[i] = initedEncryptCipher.doFinal(contentToEncrypt[i]);
        }
        return encryptedContent;
    }

    private void runTest(String testName, final CryptoUtilities.AesType aesType,
                               final int numberOfRuns) throws Exception {
        PerfTest.runAndLogTest(testName + ": Test how long it takes to decrypt " +
                numberOfRuns + " values", 100, new PerfTest() {
            byte[] iv = new byte[CryptoUtilities.aes128BlockSizeInBytes];
            byte[][] contentToEncrypt, encryptedContent;
            KeyGenerator keyGenerator;
            SecretKey aesKey;

            @Override
            public void setUpBeforeEachPerfRun() throws Exception {
                keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(128);

                final Cipher encryptCipher = CryptoUtilities.createAesCipher(aesType);

                aesKey = keyGenerator.generateKey();

                secureRandom.nextBytes(iv);

                encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey,
                        CryptoUtilities.getAlgorithmParameterSpec(aesType, iv));

                contentToEncrypt =
                        generateContentToEncrypt(numberOfRuns, sizeOfEncryptedContent);

                encryptedContent =
                        generateEncryptedContent(encryptCipher, contentToEncrypt);
            }

            @Override
            void runPerfTest() throws Exception {
                final Cipher decryptCipher = CryptoUtilities.createAesCipher(aesType);
                decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                for (int i = 0; i < contentToEncrypt.length; ++i) {
                    assertTrue(Arrays.equals(decryptCipher.doFinal(encryptedContent[i]), contentToEncrypt[i]));
                }
            }
        });

    }
}
