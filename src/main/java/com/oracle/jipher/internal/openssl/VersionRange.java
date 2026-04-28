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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VersionRange {

    final VersionLimit from;
    final VersionLimit to;

    VersionRange(VersionLimit from, VersionLimit to) {
        this.from = from;
        this.to = to;
    }

    VersionLimit getFrom() {
        return from;
    }

    VersionLimit getTo() {
        return to;
    }

    public boolean contains(Version version) {
        if (version == null) {
            return (from == null) && (to == null);
        }

        if (from != null) {
            int comparison = from.version().compareTo(version);
            if ((comparison > 0) || ((comparison == 0) && from.exclusive())) {
                return false;
            }
        }
        if (to != null) {
            int comparison = to.version().compareTo(version);
            return (comparison >= 0) && ((comparison != 0) || !to.exclusive());
        }
        return true;
    }

    enum State {
        EXPECTING_ELEMENT,
        EXPECTING_ELEMENT_SEPARATOR,
        EXPECTING_FROM_VERSION_LIMIT,
        EXPECTING_VERSION_LIMIT_SEPARATOR,
        EXPECTING_TO_VERSION_LIMIT,
        EXPECTING_VERSION_LIMIT_TERMINATOR
    }

    public static List<VersionRange> parse(String s) throws ParseException {
        List<VersionRange> ranges = new ArrayList<>();

        if (s == null) {
            return ranges;
        }

        Pattern pattern = Pattern.compile(Version.REGEX);
        Matcher matcher;
        Version version = null;
        VersionLimit versionLimit = null;
        boolean exclusive = false;

        State state = State.EXPECTING_ELEMENT;
        int index = 0;

        while (index < s.length()) {
            char c = s.charAt(index);
            // Ignore all white space
            if (!Character.isWhitespace(c)) {
                switch (state) {
                    case EXPECTING_ELEMENT:
                        if (Character.isDigit(c)) {
                            matcher = pattern.matcher(s.substring(index));
                            boolean match = matcher.lookingAt();
                            assert match; // Matcher should always match as a singe digit is a valid version.
                            version = new Version(s.substring(index, index + matcher.end()));
                            versionLimit = new VersionLimit(version, false);
                            ranges.add(new VersionRange(versionLimit, versionLimit));
                            index += matcher.end() - 1;
                            state = State.EXPECTING_ELEMENT_SEPARATOR;
                        } else if (c == '[' || c == '(') {
                            exclusive = c == '(';
                            state = State.EXPECTING_FROM_VERSION_LIMIT;
                        } else {
                            throw new ParseException("Unexpected character",  index);
                        }
                        break;
                    case EXPECTING_ELEMENT_SEPARATOR:
                        if (c == ',') {
                            state = State.EXPECTING_ELEMENT;
                        } else {
                            throw new ParseException("Expected end of input or ','", index);
                        }
                        break;
                    case EXPECTING_FROM_VERSION_LIMIT:
                        if (Character.isDigit(c)) {
                            matcher = pattern.matcher(s.substring(index));
                            boolean match = matcher.lookingAt();
                            assert match; // Matcher should always match as a singe digit is a valid version.
                            version = new Version(s.substring(index, index + matcher.end()));
                            versionLimit = new VersionLimit(version, exclusive);
                            index += matcher.end() - 1;
                            state = State.EXPECTING_VERSION_LIMIT_SEPARATOR;
                        } else if (c == ',') {
                            versionLimit = null;
                            state = State.EXPECTING_TO_VERSION_LIMIT;
                        } else {
                            throw new ParseException("Unexpected character", index);
                        }
                        break;
                    case EXPECTING_VERSION_LIMIT_SEPARATOR:
                        if (c == ',') {
                            state = State.EXPECTING_TO_VERSION_LIMIT;
                        } else {
                            throw new ParseException("Expected ','", index);
                        }
                        break;
                    case EXPECTING_TO_VERSION_LIMIT:
                        if (Character.isDigit(c)) {
                            matcher = pattern.matcher(s.substring(index));
                            boolean match = matcher.lookingAt();
                            assert match; // Matcher should always match as a singe digit is a valid version.
                            version = new Version(s.substring(index, index + matcher.end()));
                            index += matcher.end() - 1;
                            state = State.EXPECTING_VERSION_LIMIT_TERMINATOR;
                        } else if (c == ']' || c == ')') {
                            ranges.add(new VersionRange(versionLimit, null));
                            state = State.EXPECTING_ELEMENT_SEPARATOR;
                        } else {
                            throw new ParseException("Unexpected character", index);
                        }
                        break;
                    case EXPECTING_VERSION_LIMIT_TERMINATOR:
                        if (c == ')' || c == ']') {
                            ranges.add(new VersionRange(versionLimit, new VersionLimit(version, c == ')')));
                            state = State.EXPECTING_ELEMENT_SEPARATOR;
                        } else {
                            throw new ParseException("Expected ') or ']'", index);
                        }
                        break;
                }
            }
            index++;
        }
        switch (state) {
            case EXPECTING_ELEMENT, EXPECTING_ELEMENT_SEPARATOR:
                // Expected
                break;
            case EXPECTING_FROM_VERSION_LIMIT:
                throw new ParseException("Expected version string or ','", index);
            case EXPECTING_VERSION_LIMIT_SEPARATOR:
                throw new ParseException("Expected ','", index);
            case EXPECTING_TO_VERSION_LIMIT:
                throw new ParseException("Expected version string or ') or ']'", index);
            case EXPECTING_VERSION_LIMIT_TERMINATOR:
                throw new ParseException("Expected ') or ']'", index);
        }

        return ranges;
    }
}
