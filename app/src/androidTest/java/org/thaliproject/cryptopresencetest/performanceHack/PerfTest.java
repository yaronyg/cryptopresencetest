package org.thaliproject.cryptopresencetest.performanceHack;

import android.util.Log;

import java.math.BigInteger;
import java.util.Arrays;

abstract class PerfTest {
    void setUpBeforeEachPerfRun() throws Exception {

    }

    abstract void runPerfTest() throws Exception;

    private static long[] runPerfTests(int numberOfRuns, PerfTest perfTest) throws Exception {
        if (numberOfRuns <= 0) {
            throw new IllegalArgumentException("numberOfRuns must be > 0");
        }

        final long[] results = new long[numberOfRuns];
        for(int i = 0; i < numberOfRuns; ++i) {
            perfTest.setUpBeforeEachPerfRun();
            final long startTime = System.currentTimeMillis();
            perfTest.runPerfTest();
            final long endTime = System.currentTimeMillis();
            results[i] = endTime - startTime;
        }

        return results;
    }

    private static String minMedianMax(long[] results) {
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

    public static void runAndLogTest(String testDescription, int numberOfRepeats, PerfTest command)
            throws Exception {
        long[] results = runPerfTests(numberOfRepeats, command);
        Log.e("CryptoTest", testDescription + " - " + " repeated " + numberOfRepeats + " times: "
                + minMedianMax(results));
    }
}
