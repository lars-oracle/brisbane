/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software (each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at
 * a minimum a reference to the UPL must be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.oracle.jipher.internal.openssl;

import java.util.function.Supplier;

public class RandUtil {

    static final int DEFAULT_EXPECTED_ENTROPY_BITS = 6; // Bits per byte
    static final int LOG_2_ACCEPTABLE_FALSE_POSITIVE_PROBABILITY = -20;

    private static final int ADAPTIVE_PROPORTION_TEST_WINDOW = 512; // Samples

    /*
     * Cutoff values for the adaptive proportion test drawn from a binomial distribution with
     * n = 512, p = 2^-H at a critical threshold of 2^-20.
     * H being the expected entropy per sample.  Refer SP 800-90B section 4.4.2, table 2.
     */
    private static final int[] ADAPTIVE_PROPORTION_TEST_CUT_OFF_VALUE = new int[]{
            410,                                /* H = 0.5 */
            311, 177, 103, 62, 39, 25, 18, 13   /* H = 1, ..., 8 */
    };

    /*
     * Repetition Count Test - See SP 800-90B section 4.4.1
     * Given a min-entropy H, the probability n identical values consecutively is at most 2^[-H(n-1)]
     */
    static boolean runRepetitionCountTest(Supplier<Byte> supplier, int limit, int expectedEntropyBits) {
        int c = getRepetitionCountTestCutOffValue(expectedEntropyBits);
        byte a = supplier.get();
        int b = 1;
        int count = 1;
        while (count++ < limit) {
            byte x = supplier.get();
            if (x == a) {
                b++;
                if (b > c) {
                    return false;
                }
            } else {
                a = x;
                b = 1;
            }
        }
        return true;
    }

    /*
     * Repetition Count Test - See SP 800-90B section 4.4.2
     * Measures the local frequency of occurrence of a sample value in a sequence of samples to determine if
     * the sample occurs too frequently.
     */
    static boolean runAdaptiveProportionTest(Supplier<Byte> supplier, int expectedEntropyBits) {
        int c = getAdaptiveProportionTestCutOffValue(expectedEntropyBits);

        byte a = supplier.get();
        int b = 1;
        for (int i = 1; i < ADAPTIVE_PROPORTION_TEST_WINDOW; i++) {
            if (a == supplier.get()) {
                b++;
            }
            if (b >= c) {
                return false;
            }
        }
        return true;
    }

    private static int getRepetitionCountTestCutOffValue(int expectedEntropyBits)  {
        return 1 + (int) Math.ceil(-LOG_2_ACCEPTABLE_FALSE_POSITIVE_PROBABILITY / (double) expectedEntropyBits);
    }

    private static int getAdaptiveProportionTestCutOffValue(int expectedEntropyBits)  {
        if (LOG_2_ACCEPTABLE_FALSE_POSITIVE_PROBABILITY != -20) {
            throw new AssertionError();
        }
        return ADAPTIVE_PROPORTION_TEST_CUT_OFF_VALUE[expectedEntropyBits];
    }


    static boolean runRepetitionCountTest(byte[] sample)  {
        return runRepetitionCountTest(sample, DEFAULT_EXPECTED_ENTROPY_BITS);
    }

    static boolean runRepetitionCountTest(byte[] sample, int expectedEntropyBits) {
        final int[] index = {0};
        int limit = sample.length;

        return runRepetitionCountTest(() -> sample[index[0]++], limit, expectedEntropyBits);
    }

    static boolean runRepetitionCountTest(Supplier<Byte> supplier, int count) {
        return runRepetitionCountTest(supplier, count, DEFAULT_EXPECTED_ENTROPY_BITS);
    }


    static boolean runAdaptiveProportionTest(byte[] sample)  {
        return runAdaptiveProportionTest(sample, DEFAULT_EXPECTED_ENTROPY_BITS);
    }

    static boolean runAdaptiveProportionTest(byte[] sample, int expectedEntropyBits) {
        if (sample.length < ADAPTIVE_PROPORTION_TEST_WINDOW) {
            throw new AssertionError("Insufficient sample size");
        }

        for (int startIndex = 0; startIndex < sample.length - ADAPTIVE_PROPORTION_TEST_WINDOW; startIndex++) {
            final int[] index = {startIndex};
            if (!runAdaptiveProportionTest(() -> sample[index[0]++], expectedEntropyBits)) {
                return false;
            }
        }
        return true;
    }

    static boolean runAdaptiveProportionTest(Supplier<Byte> supplier) {
        return runAdaptiveProportionTest(supplier, DEFAULT_EXPECTED_ENTROPY_BITS);
    }
}
