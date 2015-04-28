package org.thaliproject.cryptopresencetest.app;

import android.test.AndroidTestCase;

import java.security.SecureRandom;
import java.security.Security;

public class BaseCryptoTest extends AndroidTestCase {
    static final int sizeOfTimeStampInBytes = 8;
    static final int twoHundredFiftySixBitKeyInBytes = 32;
    static final int md5HashSizeInBytes = 16;
    static final SecureRandom secureRandom = new SecureRandom();

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }
}
