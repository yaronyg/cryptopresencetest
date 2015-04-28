package org.thaliproject.cryptopresencetest.app;

import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import org.spongycastle.crypto.engines.IESEngine;
import org.spongycastle.jcajce.provider.digest.Tiger;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;


public class MainActivity extends ActionBarActivity {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public abstract class Command {
        void runOnceBeforeAllTests() {

        }

        void setUpBeforeEachTest() {

        }

        abstract void runTest();
    }

    private long[] runTests(int numberOfRepeats, Command command) {
        if (numberOfRepeats <= 0) {
            throw new IllegalArgumentException("numberOfRepeats must be > 0");
        }

        command.runOnceBeforeAllTests();

        final long[] results = new long[numberOfRepeats];
        for(int i = 0; i < numberOfRepeats; ++i) {
            command.setUpBeforeEachTest();
            final long startTime = System.currentTimeMillis();
            command.runTest();
            final long endTime = System.currentTimeMillis();
            results[i] = endTime - startTime;
        }

        return results;
    }

    public String minMedianMax(long[] results) {
        long min, max;
        double median;

        if (results == null || results.length == 0) {
            throw new IllegalArgumentException("results must be a non-null value with a length greater than 0");
        }

        Arrays.sort(results);
        min = results[0];
        max = results[results.length - 1];
        median = results.length % 2 == 0 ?
                ((double)results[results.length/2] + (double)results[results.length/2 - 1])/2 :
                (double)results[results.length/2];

        BigInteger sumOfRunTimes = BigInteger.ZERO;
        for (long result : results) {
            sumOfRunTimes = sumOfRunTimes.add(BigInteger.valueOf(result));
        }

        return "min: " + min + ", median: " + median + ", max: " + max + ", total: " + sumOfRunTimes.toString();
    }

    public void runAndLogTest(String testDescription, int numberOfRepeats, Command command) {
        long[] results = runTests(100, command);
        Log.e("CryptoTest", testDescription + " - " + " repeated " + numberOfRepeats + " times: " + minMedianMax(results));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new Thread() {
            public void run() {
                final int beaconSize = 24; // Timestamp (long - 64 bits) + MD5(Key) (128 bits) = 24 bytes
                final SecureRandom secureRandom = new SecureRandom();

                try {
                    ECGenParameterSpec ecGenSpecForStaticDH = new ECGenParameterSpec("secp256k1");
                    KeyPairGenerator keyPairGeneratorStaticDH = KeyPairGenerator.getInstance("ECDH", "SC");
                    keyPairGeneratorStaticDH.initialize(ecGenSpecForStaticDH, secureRandom);

                    KeyPair xKeyPair = keyPairGeneratorStaticDH.generateKeyPair();
                    KeyAgreement xKeyAgree = KeyAgreement.getInstance("ECDH", "SC");
                    xKeyAgree.init(xKeyPair.getPrivate());

                    KeyPair yKeyPair = keyPairGeneratorStaticDH.generateKeyPair();
                    KeyAgreement yKeyAgree = KeyAgreement.getInstance("ECDH", "SC");
                    yKeyAgree.init(yKeyPair.getPrivate());

                    xKeyAgree.doPhase(yKeyPair.getPublic(), true);
                    byte[] xKeySecret = xKeyAgree.generateSecret();

                    yKeyAgree.doPhase(xKeyPair.getPublic(), true);
                    byte[] yKeySecret = yKeyAgree.generateSecret();

                    Log.e("CryptoTest", "The keys matched? " + Arrays.equals(xKeySecret, yKeySecret) + ", and their size is " + xKeySecret.length);

                    Mac hmac5Init = null;
                    try {
                        hmac5Init = Mac.getInstance("HMACMD5");
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        Log.e("CryptoTest", "Failure! - " + e.toString());
                    }

                    final Mac hmac5 = hmac5Init;

                    final int keysToGenerate = 100;
                    runAndLogTest("Generate " + keysToGenerate +
                            " HMAC-MD5 Values using different keys", 100, new Command() {
                        SecretKeySpec[] keys = new SecretKeySpec[keysToGenerate];
                        ByteBuffer buffer = ByteBuffer.allocate(8);

                        @Override
                        void setUpBeforeEachTest() {
                            byte[] keyBytes = new byte[32];
                            for(int keyIndex = 0; keyIndex < keysToGenerate; ++keyIndex) {
                                secureRandom.nextBytes(keyBytes);
                                keys[keyIndex] = new SecretKeySpec(keyBytes, "RAW");
                            }
                        }

                        @Override
                        void runTest() {
                            long timeStamp = System.currentTimeMillis();
                            for(int keyIndex = 0; keyIndex < keysToGenerate; ++keyIndex) {
                                try {
                                    hmac5.init(keys[keyIndex]);
                                    byte[] timeStampAsBytes = buffer.putLong(0, timeStamp).array();
                                    hmac5.update(timeStampAsBytes);
                                    hmac5.doFinal(timeStampAsBytes);
                                } catch (InvalidKeyException e) {
                                    e.printStackTrace();
                                    Log.e("CryptoTest", "Failure! - " + e.toString());
                                }
                            }
                        }
                    });

                    final int keysInAddressBook = 1000;
                    final int hashesToCheck = 100;
                    runAndLogTest("Check " + hashesToCheck + " hashes against " +
                            keysInAddressBook + " keys", 100, new Command() {
                        SecretKeySpec[] addressBook = new SecretKeySpec[keysInAddressBook];
                        byte[][] valuesToHash = new byte[hashesToCheck][8]; // Size of a time stamp
                        ByteBuffer buffer = ByteBuffer.allocate(8);
                        Mac hmacmd5;

                        @Override
                        void runOnceBeforeAllTests() {
                            byte[] keyBytes = new byte[32];
                            for(int keyIndex = 0; keyIndex < keysToGenerate; ++keyIndex) {
                                secureRandom.nextBytes(keyBytes);
                                addressBook[keyIndex] = new SecretKeySpec(keyBytes, "RAW");
                            }
                        }

                        @Override
                        void setUpBeforeEachTest() {
                            for(int i = 0; i < hashesToCheck; ++i) {
                                secureRandom.nextBytes(valuesToHash[i]);
                            }
                        }

                        @Override
                        void runTest() {

                        }
                    });

                    ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
                    final KeyPairGenerator keyPairGeneratorEcdsa = KeyPairGenerator.getInstance("ECDSA", "SC");
                    keyPairGeneratorEcdsa.initialize(ecGenSpec, secureRandom);

                    runAndLogTest("Create 256 bit ECDSA Key", 100, new Command() {
                        @Override
                        public void runTest() {
                            keyPairGeneratorEcdsa.generateKeyPair();
                        }
                    });

                    final KeyPair keyPair = keyPairGeneratorEcdsa.generateKeyPair();
                    final byte[] beaconValue = new byte[beaconSize];
                    final Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "SC");
                    ecdsaSign.initVerify(keyPair.getPublic());

                    runAndLogTest("Sign 24 byte value with 256 bit ECDSA Key", 100, new Command() {
                        @Override
                        public void runOnceBeforeAllTests() {
                            try {
                                ecdsaSign.initSign(keyPair.getPrivate());
                            } catch (InvalidKeyException e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }
                        }

                        @Override
                        public void setUpBeforeEachTest() {
                            secureRandom.nextBytes(beaconValue);
                        }

                        @Override
                        public void runTest() {
                            try {
                                ecdsaSign.update(beaconValue);
                                byte[] signedValue = ecdsaSign.sign();
                            } catch (SignatureException e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }

                        }
                    });

                    runAndLogTest("Verify 24 byte signature value with 256 bit ECDSA Key", 100, new Command() {
                        private byte[] signedValue;
                        @Override
                        public void setUpBeforeEachTest() {
                            try {
                                secureRandom.nextBytes(beaconValue);
                                ecdsaSign.initSign(keyPair.getPrivate());
                                ecdsaSign.update(beaconValue);
                                signedValue = ecdsaSign.sign();
                            } catch (SignatureException | InvalidKeyException e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }
                        }

                        @Override
                        public void runTest() {
                            try {
                                ecdsaSign.initVerify(keyPair.getPublic());
                                ecdsaSign.update(beaconValue);
                                if (!ecdsaSign.verify(signedValue)) {
                                    throw new Exception("EEEEK!");
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }
                        }
                    });

                    runAndLogTest("Verify 24 byte signature value DOESN'T MATCH with 256 bit ECDSA Key", 100, new Command() {
                        private byte[] signedValue;
                        KeyPair verifyKeyPair = keyPairGeneratorEcdsa.generateKeyPair();
                        Signature ecdsaFailVerify = Signature.getInstance("SHA1withECDSA", "SC");

                        @Override
                        public void runOnceBeforeAllTests() {
                            try {
                                ecdsaSign.initSign(keyPair.getPrivate());
                                ecdsaFailVerify.initVerify(verifyKeyPair.getPublic());
                            } catch (InvalidKeyException e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }
                        }

                        @Override
                        public void setUpBeforeEachTest() {
                            secureRandom.nextBytes(beaconValue);
                            try {
                                ecdsaSign.update(beaconValue);
                                signedValue = ecdsaSign.sign();
                            } catch (SignatureException e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }
                        }

                        @Override
                        public void runTest() {
                            try {
                                ecdsaFailVerify.update(beaconValue);
                                if (ecdsaFailVerify.verify(signedValue)) {
                                    throw new Exception("Somehow the verify passed when it wasn't supposed to!!!!!!");
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                Log.e("CryptoTest", "Failure! - " + e.toString());
                            }
                        }
                    });

//                    // ECIES combines both validation and encryption. See http://bouncy-castle.1462172.n4.nabble.com/ECC-with-ECIES-Encrypt-Decrypt-Questions-td4656750.html
//                    // especially the last post for where I got the sample code for this.
//                    ECGenParameterSpec ecGenSpecForEcies = new ECGenParameterSpec("Curve25519");
//                    KeyPairGenerator keyPairGeneratorEcies = KeyPairGenerator.getInstance("ECIES", "SC");
//                    keyPairGeneratorEcies.initialize(ecGenSpecForEcies, secureRandom);
//
//                    KeyPair eciesKeyPair = keyPairGeneratorEcies.generateKeyPair();
//                    ECPublicKey publicKey = (ECPublicKey) eciesKeyPair.getPublic();
//                    ECPrivateKey privateKey = (ECPrivateKey) eciesKeyPair.getPrivate();



                } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
                    e.printStackTrace();
                    Log.e("CryptoTest", "Failure! - " + e.toString());
                }
            }
        }.start();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
