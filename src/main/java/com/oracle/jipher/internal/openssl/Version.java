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

import java.util.Arrays;

public class Version implements Comparable<Version> {

    public static final String REGEX = "[0-9]+(\\.[0-9]+)*";

    public static Version of(String s) {
        return new Version(s);
    }

    private final String version;

    public Version(String version) {
        if (version == null) {
            throw new IllegalArgumentException("Version string must not be null");
        }
        version = version.split("-")[0];
        if (!version.matches(REGEX)) {
            throw new IllegalArgumentException("Invalid version string");
        }
        this.version = version;
    }

    public int[] getParts() {
        return Arrays.stream(version.split("\\.")).map(Integer::parseInt).mapToInt(Integer::intValue).toArray();
    }

    @Override
    public int compareTo(Version that) {
        if (that == null) {
            return 1;
        }
        int[] thisParts = this.getParts();
        int[] thatParts = that.getParts();

        int maxPartLength = Math.max(thisParts.length, thatParts.length);
        if (thisParts.length < maxPartLength) {
            thisParts = Arrays.copyOf(thisParts, maxPartLength);
        } else if (thatParts.length < maxPartLength) {
            thatParts = Arrays.copyOf(thatParts, maxPartLength);
        }

        for (int i = 0; i < maxPartLength; i++) {
            if (thisParts[i] < thatParts[i]) {
                return -1;
            }
            if (thisParts[i] > thatParts[i]) {
                return 1;
            }
        }
        return 0;
    }
}
