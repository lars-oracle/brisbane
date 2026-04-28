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

import java.text.ParseException;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class VersionRangeTest {

    @Test
    public void singleEntryVersionRange() {
        VersionLimit min = new VersionLimit(Version.of("1.2.3"), false);
        VersionLimit max = new VersionLimit(Version.of("1.2.3"), false);
        VersionRange versionRange = new VersionRange(min, max);

        Assert.assertFalse(versionRange.contains(null));

        Assert.assertTrue(versionRange.contains(Version.of("1.2.3")));

        Assert.assertFalse(versionRange.contains(Version.of("1.2.2")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.4")));

        Assert.assertFalse(versionRange.contains(Version.of("1.1.3")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.3")));

        Assert.assertTrue(versionRange.contains(Version.of("1.2.3.0")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.3.1")));
    }

    @Test
    public void inclusiveVersionRange() {
        VersionLimit min = new VersionLimit(Version.of("1.2.3"), false);
        VersionLimit max = new VersionLimit(Version.of("1.3.1"), false);
        VersionRange versionRange = new VersionRange(min, max);

        Assert.assertFalse(versionRange.contains(null));

        Assert.assertFalse(versionRange.contains(Version.of("1.1.999")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.2")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.2.999")));

        Assert.assertTrue(versionRange.contains(Version.of("1.2.3")));
        Assert.assertTrue(versionRange.contains(Version.of("1.2.3.0")));
        Assert.assertTrue(versionRange.contains(Version.of("1.2.3.999")));
        Assert.assertTrue(versionRange.contains(Version.of("1.2.999")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.0")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.0.1")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.1")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.1.0")));

        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.0.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.2")));
    }

    @Test
    public void exclusiveVersionRange() {
        VersionLimit min = new VersionLimit(Version.of("1.2.3"), true);
        VersionLimit max = new VersionLimit(Version.of("1.3.1"), true);
        VersionRange versionRange = new VersionRange(min, max);

        Assert.assertFalse(versionRange.contains(null));

        Assert.assertFalse(versionRange.contains(Version.of("1.1.999")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.2")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.2.999")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.3")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.3.0")));

        Assert.assertTrue(versionRange.contains(Version.of("1.2.3.0.1")));
        Assert.assertTrue(versionRange.contains(Version.of("1.2.3.1")));
        Assert.assertTrue(versionRange.contains(Version.of("1.2.999")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.0")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.0.1")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.0.999")));

        Assert.assertFalse(versionRange.contains(Version.of("1.3.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.0")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.0.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.2")));
    }

    @Test
    public void allVersionRange() {
        VersionRange versionRange = new VersionRange(null, null);

        Assert.assertTrue(versionRange.contains(null));
        Assert.assertTrue(versionRange.contains(Version.of("0")));
        Assert.assertTrue(versionRange.contains(Version.of("999")));
    }

    @Test
    public void nullMinVersionRange() {
        VersionLimit max = new VersionLimit(Version.of("1.3.1"), false);
        VersionRange versionRange = new VersionRange(null, max);

        Assert.assertFalse(versionRange.contains(null));

        Assert.assertTrue(versionRange.contains(Version.of("0")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.1")));
        Assert.assertTrue(versionRange.contains(Version.of("1.3.1.0")));

        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.0.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.1.1")));
        Assert.assertFalse(versionRange.contains(Version.of("1.3.2")));
    }

    @Test
    public void nullMaxVersionRange() {
        VersionLimit min = new VersionLimit(Version.of("1.2.3"), false);
        VersionRange versionRange = new VersionRange(min, null);

        Assert.assertFalse(versionRange.contains(null));

        Assert.assertFalse(versionRange.contains(Version.of("1.2.2")));
        Assert.assertFalse(versionRange.contains(Version.of("1.2.2.999")));

        Assert.assertTrue(versionRange.contains(Version.of("1.2.3")));
        Assert.assertTrue(versionRange.contains(Version.of("999.999.999")));
    }

    @Test
    public void parseNullString() throws Exception {
        List<VersionRange> list = VersionRange.parse(null);

        Assert.assertEquals(0, list.size());
    }

    @Test
    public void parseEmptyString() throws Exception {
        List<VersionRange> list = VersionRange.parse("");

        Assert.assertEquals(0, list.size());
    }

    @Test
    public void parseVersion() throws Exception {
        List<VersionRange> list = VersionRange.parse("1.2.3");

        Assert.assertEquals(1, list.size());
        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, false);
        checkVersionLimit(list.get(0).getTo(), 1, 2, 3, false);
    }

    @Test
    public void parseInclusiveVersionRange() throws Exception {
        List<VersionRange> list = VersionRange.parse("[1.2.3, 4.5.6]");

        Assert.assertEquals(1, list.size());
        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, false);
        checkVersionLimit(list.get(0).getTo(), 4, 5, 6, false);
    }

    @Test
    public void parseExclusiveVersionRange() throws Exception {
        List<VersionRange> list = VersionRange.parse("(1.2.3, 4.5.6)");

        Assert.assertEquals(1, list.size());
        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, true);
        checkVersionLimit(list.get(0).getTo(), 4, 5, 6, true);
    }

    @Test
    public void parseMinInclusiveMaxExclusiveVersionRange() throws Exception {
        List<VersionRange> list = VersionRange.parse("[1.2.3, 4.5.6)");

        Assert.assertEquals(1, list.size());
        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, false);
        checkVersionLimit(list.get(0).getTo(), 4, 5, 6, true);
    }

    @Test
    public void parseMinIExclusiveMaxInclusiveVersionRange() throws Exception {
        List<VersionRange> list = VersionRange.parse("(1.2.3, 4.5.6]");

        Assert.assertEquals(1, list.size());
        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, true);
        checkVersionLimit(list.get(0).getTo(), 4, 5, 6, false);
    }

    @Test
    public void parseNoMinVersionRange() throws Exception {
        List<VersionRange> list = VersionRange.parse("(, 1.2.3]");

        Assert.assertEquals(1, list.size());
        Assert.assertNull(list.get(0).getFrom());
        checkVersionLimit(list.get(0).getTo(), 1, 2, 3, false);
    }

    @Test
    public void parseNoMaxVersionRange() throws Exception {
        List<VersionRange> list = VersionRange.parse("(1.2.3, ]");

        Assert.assertEquals(1, list.size());
        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, true);
        Assert.assertNull(list.get(0).getTo());
    }

    @Test
    public void parseMultipleVersionRanges() throws Exception {
        List<VersionRange> list = VersionRange.parse("[1.2.3, 4.5.6), 7.8.9, (, 10.11.12], 13.14.15");

        Assert.assertEquals(4, list.size());

        checkVersionLimit(list.get(0).getFrom(), 1, 2, 3, false);
        checkVersionLimit(list.get(0).getTo(), 4, 5, 6, true);

        checkVersionLimit(list.get(1).getFrom(), 7, 8, 9, false);
        checkVersionLimit(list.get(1).getTo(), 7, 8, 9, false);

        Assert.assertNull(list.get(2).getFrom());
        checkVersionLimit(list.get(2).getTo(), 10, 11, 12, false);

        checkVersionLimit(list.get(3).getFrom(), 13, 14, 15, false);
        checkVersionLimit(list.get(3).getTo(), 13, 14, 15, false);
    }

    private void checkVersionLimit(VersionLimit versionLimit, int major, int minor, int patch, boolean exclusive) {
        Assert.assertEquals(major, versionLimit.version().getParts()[0]);
        Assert.assertEquals(minor, versionLimit.version().getParts()[1]);
        Assert.assertEquals(patch, versionLimit.version().getParts()[2]);

        Assert.assertEquals(exclusive, versionLimit.exclusive());
    }

    @Test (expected = ParseException.class)
    public void parseInvalidVersionNeg() throws Exception {
        try {
            VersionRange.parse("1.2. ");
        } catch (ParseException e) {
            Assert.assertEquals(3, e.getErrorOffset());
            Assert.assertEquals("Expected end of input or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseStartsWithDotNeg() throws Exception {
        try {
            VersionRange.parse(" .2.3");
        } catch (ParseException e) {
            Assert.assertEquals(1, e.getErrorOffset());
            Assert.assertEquals("Unexpected character", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseEndsWithDotNeg() throws Exception {
        try {
            VersionRange.parse("1.2.");
        } catch (ParseException e) {
            Assert.assertEquals(3, e.getErrorOffset());
            Assert.assertEquals("Expected end of input or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingElementSeparatorNeg() throws Exception {
        try {
            VersionRange.parse("1.2.3 4.5.6");
        } catch (ParseException e) {
            Assert.assertEquals(6, e.getErrorOffset());
            Assert.assertEquals("Expected end of input or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingElementSeparatorAfterRangeNeg() throws Exception {
        try {
            VersionRange.parse("[1.2.3,) 1.2.3");
        } catch (ParseException e) {
            Assert.assertEquals(9, e.getErrorOffset());
            Assert.assertEquals("Expected end of input or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseInvalidFromVersionLimitPrefixNeg() throws Exception {
        try {
            VersionRange.parse("[A.2.3,)");
        } catch (ParseException e) {
            Assert.assertEquals(1, e.getErrorOffset());
            Assert.assertEquals("Unexpected character", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseInvalidFromVersionLimitSuffixNeg() throws Exception {
        try {
            VersionRange.parse("[1.2.)");
        } catch (ParseException e) {
            Assert.assertEquals(4, e.getErrorOffset());
            Assert.assertEquals("Expected ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseInvalidToVersionLimitPrefixNeg() throws Exception {
        try {
            VersionRange.parse("[,A.2.3)");
        } catch (ParseException e) {
            Assert.assertEquals(2, e.getErrorOffset());
            Assert.assertEquals("Unexpected character", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseInvalidToVersionLimitNeg() throws Exception {
        try {
            VersionRange.parse("[,1.2.A)");
        } catch (ParseException e) {
            Assert.assertEquals(5, e.getErrorOffset());
            Assert.assertEquals("Expected ') or ']'", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingElementSeparatorBetweenVersionRangesNeg() throws Exception {
        try {
            VersionRange.parse("[,1.2.3) [4.5.6,)");
        } catch (ParseException e) {
            Assert.assertEquals(9, e.getErrorOffset());
            Assert.assertEquals("Expected end of input or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingVersionRangeStartMarkNeg() throws Exception {
        try {
            VersionRange.parse("1.2.3, 4.5.6]");
        } catch (ParseException e) {
            Assert.assertEquals(12, e.getErrorOffset());
            Assert.assertEquals("Expected end of input or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingVersionRangeEndMarkNeg() throws Exception {
        try {
            VersionRange.parse("[1.2.3, 4.5.6");
        } catch (ParseException e) {
            Assert.assertEquals(13, e.getErrorOffset());
            Assert.assertEquals("Expected ') or ']'", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingVersionRangeEndMark2() throws Exception {
        try {
            VersionRange.parse("[1.2.3, 4.5.6 , 7.8.9");
        } catch (ParseException e) {
            Assert.assertEquals(14, e.getErrorOffset());
            Assert.assertEquals("Expected ') or ']'", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingVersionRangeSeparatorNeg() throws Exception {
        try {
            VersionRange.parse("[1.2.3 4.5.6]");
        } catch (ParseException e) {
            Assert.assertEquals(7, e.getErrorOffset());
            Assert.assertEquals("Expected ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingFromVersionLimitEndOfInputNeg() throws Exception {
        try {
            VersionRange.parse("[");
        } catch (ParseException e) {
            Assert.assertEquals(1, e.getErrorOffset());
            Assert.assertEquals("Expected version string or ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class) // Separator
    public void parseMissingVersionLimitSeparatorEndOfInputNeg() throws Exception {
        try {
            VersionRange.parse("[ 1.2.3");
        } catch (ParseException e) {
            Assert.assertEquals(7, e.getErrorOffset());
            Assert.assertEquals("Expected ','", e.getMessage());
            throw e;
        }
    }

    @Test (expected = ParseException.class)
    public void parseMissingToVersionLimitEndOfInputNeg() throws Exception {
        try {
            VersionRange.parse("[ 1.2.3,");
        } catch (ParseException e) {
            Assert.assertEquals(8, e.getErrorOffset());
            Assert.assertEquals("Expected version string or ') or ']'", e.getMessage());
            throw e;
        }
    }
}
