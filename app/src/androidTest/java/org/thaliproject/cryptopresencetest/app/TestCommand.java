package org.thaliproject.cryptopresencetest.app;

import android.util.Log;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public abstract class TestCommand {
    void runOnceBeforeAllTests() throws InvalidKeyException {

    }

    void setUpBeforeEachTest() throws Exception {

    }

    abstract void runTest() throws Exception;

    public static long[] runTests(int numberOfRepeats, TestCommand command) throws Exception {
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

    public static String minMedianMax(long[] results) {
        long min, max;
        double median;

        if (results == null || results.length == 0) {
            throw new
                    IllegalArgumentException("results must be a non-null value with a length greater than 0");
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

        return "min: " + min + ", median: " + median + ", max: " + max + ", total: "
                + sumOfRunTimes.toString();
    }

    public static void runAndLogTest(String testDescription, int numberOfRepeats, TestCommand command)
            throws Exception {
        long[] results = runTests(numberOfRepeats, command);
        Log.e("CryptoTest", testDescription + " - " + " repeated " + numberOfRepeats + " times: "
                + minMedianMax(results));
    }
}
