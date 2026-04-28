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

package com.oracle.jipher.internal.asn1;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.oracle.jipher.internal.asn1.TagClass.CONTEXT_SPECIFIC;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;
import static com.oracle.jipher.internal.asn1.UniversalTag.BIT_STRING;
import static com.oracle.jipher.internal.asn1.UniversalTag.BOOLEAN;
import static com.oracle.jipher.internal.asn1.UniversalTag.ENUMERATED;
import static com.oracle.jipher.internal.asn1.UniversalTag.GeneralizedTime;
import static com.oracle.jipher.internal.asn1.UniversalTag.INTEGER;
import static com.oracle.jipher.internal.asn1.UniversalTag.NULL;
import static com.oracle.jipher.internal.asn1.UniversalTag.OBJECT_IDENTIFIER;
import static com.oracle.jipher.internal.asn1.UniversalTag.OCTET_STRING;
import static com.oracle.jipher.internal.asn1.UniversalTag.RELATIVE_OID;
import static com.oracle.jipher.internal.asn1.UniversalTag.SEQUENCE;
import static com.oracle.jipher.internal.asn1.UniversalTag.SET;
import static com.oracle.jipher.internal.asn1.UniversalTag.UTCTime;

/**
 * Used to decode or encode an ASN.1 BER value.
 */
public final class Asn1BerValue {

    static final Pattern UTC_TIME_PATTERN = Pattern.compile(
            "\\d".repeat(10) + // "yyMMddHHmm"
                    "(?<second>\\d\\d)?" +
                    "(?<offset>Z|[-+]\\d\\d\\d\\d)");

    static final Pattern GENERALIZED_TIME_PATTERN = Pattern.compile(
            "\\d".repeat(10) + // "yyyyMMddHH"
                    "(?:(?<minute>\\d\\d)" +
                    "(?:(?<second>\\d\\d)" +
                    "(?<nano>[.,]\\d{1,9})?)?)?" +
                    "(?<offset>Z|[-+]\\d\\d\\d\\d)?");

    static final DateTimeFormatter UTC_TIME_PARSER = new DateTimeFormatterBuilder()
            .appendValueReduced(ChronoField.YEAR, 2, 2, 1950)
            .appendPattern("MMddHHmm")
            .optionalStart().appendValue(ChronoField.SECOND_OF_MINUTE, 2).optionalEnd()
            .appendOffset("+HHMM","Z")
            .toFormatter();

    static final DateTimeFormatter GENERALIZED_TIME_PARSER = new DateTimeFormatterBuilder()
            .appendPattern("yyyyMMddHHmmss")
            .optionalStart()
            .appendLiteral('.') // Always use '.' regardless of Locale.
            .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, false)
            .optionalEnd()
            .optionalStart().appendOffset("+HHMM","Z").optionalEnd()
            .toFormatter();

    static final TagClass[] TAG_CLASS_VALUES = TagClass.values();

    static final String INVALID_BER_CONTENT_ENCODING = "Invalid BER content encoding: ";
    static final String CONTENT_NOT_DER_COMPLIANT = "Content not DER compliant: ";
    static final String BUFFER_UNDERFLOW_AT_OFFSET = "Buffer underflow while decoding value; at offset ";
    static final String CONTENT_LENGTH_EXCEEDS_IMPLEMENTATION_LIMIT = "Content length exceeds implementation limit";
    static final String AT_OFFSET = "; at offset ";
    static final String NESTING_DEPTH_EXCEEDS_IMPLEMENTATION_LIMIT = "Nesting depth exceeds implementation limit" + AT_OFFSET;

    enum SortOrder { SEQUENCE, SET, SET_OF }

    static final int ID_TAG_CLASS_MASK = 0xc0;
    static final int ID_TAG_CLASS_SHIFT = 6;
    static final int ID_CONSTRUCTED_MASK = 0x20;
    static final int ID_TAG_MASK = 0x1f;

    static final int INDEFINITE_LENGTH = -1;

    /**
     * Maximum permitted nesting depth of constructed values when decoding.
     * Limiting input to this depth guards against excessive stack usage
     * that could result in stack overflow and possible denial of service.
     */
    static final int MAX_DECODE_DEPTH = 64;

    /**
     * The TagClass of this Asn1BerValue. This may be an implicit tag if
     * not UNIVERSAL.
     */
    public final TagClass tagClass;

    /**
     * The TagValue. This may be the value of an implicit tag if
     * <code>tagClass</code> is not UNIVERSAL.
     */
    public final int tagValue;

    /**
     * For Asn1BerValues resulting from a decode operation, the offset of the
     * start of this value within the original ByteBuffer that was the source
     * of the BER data.
     */
    public final int offset;

    /**
     * <code>true</code> if this value is constructed.
     */
    public final boolean constructed;

    /**
     * <code>true</code> if this is an end-of-contents marker.
     */
    public final boolean endOfContents;

    /** The sort order when encoding a constructed value. */
    final SortOrder sortOrder;

    /**
     * Whether to perform strict DER checking at both decode and conversion time,
     * where appropriate. Only the structure (Length status and encoding) is
     * checked at decode time since, due to the use of implicit tags, the types
     * of primitive values may not be known until conversion time.
     * <p>
     * Only primitive values that are converted will be checked. The ordering
     * of SET and SET OF is not checked.
     */
    final boolean checkDer;

    /**
     * if <code>true</code> then the tag class is asserted to be
     * {@link TagClass#UNIVERSAL} at conversion time.
     * <p>
     * Defaults to <code>true</code> for decoded values, <code>false</code>
     * otherwise.
     */
    final boolean checkTagClass;

    /**
     * The remaining bytes of this buffer make up the content of the value.
     * This is <code>null</code> for newly created constructed values but is
     * present for decoded constructed values and all primitive values.
     */
    final ByteBuffer contentBuffer;

    /**
     * The values contained within a constructed value or <code>null</code>
     * if this is a primitive value.
     */
    final List<Asn1BerValue> contentValues;

    /**
     * True if the BER value and all values contained within are structurally
     * DER. Only the Length (status, i.e. whether indefinite length or not, and
     * encoding) contributes to this.
     */
    boolean der = true;

    /**
     * Decodes an ASN.1 BER value and its sub-values, if it is constructed,
     * from the specified ByteBuffer and moves the position past the decoded
     * value. The content of the value, and sub-values, is captured as slices
     * of the <b>src</b> buffer; the data in the <b>src</b> buffer should not
     * be changed while any decoded Asn1BerValues are still in use.
     *
     * @param src the ByteBuffer from which to decode the BER value
     * @param checkDer enable DER checking for the length octets at decode time
     *                 as well as the primitive content at primitive
     *                 extraction/conversion time
     * @param depth the current depth of nested constructed values within the
     *              BER data being decoded; used to avoid excessive stack usage
     *              that could result in stack overflow and possible denial of
     *              service
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of the value being invalid
     */
    Asn1BerValue(ByteBuffer src, boolean checkDer, int depth) {
        this.sortOrder = SortOrder.SEQUENCE;
        this.checkDer = checkDer;
        this.checkTagClass = true;
        ByteBuffer rbb = src.asReadOnlyBuffer();
        this.offset = rbb.position();

        if (depth > MAX_DECODE_DEPTH) {
            throw new Asn1DecodeException(NESTING_DEPTH_EXCEEDS_IMPLEMENTATION_LIMIT + this.offset);
        }

        int len;
        try {
            int id = rbb.get();
            this.tagClass = TAG_CLASS_VALUES[(id & ID_TAG_CLASS_MASK) >> ID_TAG_CLASS_SHIFT];
            this.constructed = (id & ID_CONSTRUCTED_MASK) != 0;
            int tag = id & ID_TAG_MASK;
            if (tag == ID_TAG_MASK) {
                tag = decodeTagValue(rbb);
            }
            this.tagValue = tag;
            len = decodeLength(rbb);
        } catch (Asn1DecodeException ex) {
            throw new Asn1DecodeException(ex.getMessage() + AT_OFFSET + this.offset, ex);
        } catch (BufferUnderflowException ex) {
            throw new Asn1DecodeException(BUFFER_UNDERFLOW_AT_OFFSET + rbb.position(), ex);
        }
        if (checkDer) {
            der();
        }

        if (this.tagClass == UNIVERSAL && this.tagValue == 0) {
            // End-of-contents marker
            if (len != 0 || this.constructed || !this.der) {
                throw new Asn1DecodeException("Invalid End-of-contents marker; at offset " + this.offset);
            }
            this.endOfContents = true;
            src.position(rbb.position());
            this.contentValues = null;
            this.contentBuffer = null;
            return;
        }
        this.endOfContents = false;

        rbb.mark();
        if (len != INDEFINITE_LENGTH) {
            if (len > rbb.remaining()) {
                throw new Asn1DecodeException(BUFFER_UNDERFLOW_AT_OFFSET + this.offset);
            }
            rbb.limit(rbb.position() + len);
        }
        if (this.constructed) {
            if (len == INDEFINITE_LENGTH) {
                this.contentValues = Asn1.decodeUntilMark(rbb, depth + 1);
                rbb.limit(rbb.position());
            } else {
                this.contentValues = Asn1.decodeAll(rbb, checkDer, depth + 1);
                for (Asn1BerValue value : this.contentValues) {
                    if (!value.isDer()) {
                        this.der = false;
                        break;
                    }
                }
            }
        } else {
            if (len == INDEFINITE_LENGTH) {
                throw new Asn1DecodeException("Non-constructed BER value has indefinite length; at offset " + this.offset);
            }
            this.contentValues = null;
        }
        rbb.reset();
        this.contentBuffer = rbb;
        src.position(rbb.limit());
    }

    /**
     * Constructs a copy of an existing value with checkTagClass set to a specified state.
     *
     * @param original the value to copy
     * @param checkTagClass the checkTagClass setting of the copy
     */
    Asn1BerValue(Asn1BerValue original, boolean checkTagClass) {
        this.tagClass = original.tagClass;
        this.tagValue = original.tagValue;
        this.offset = original.offset;
        this.constructed = original.constructed;
        this.endOfContents = original.endOfContents;
        this.sortOrder = original.sortOrder;
        this.checkDer = original.checkDer;
        this.checkTagClass = checkTagClass;
        this.contentBuffer = original.contentBuffer;
        this.contentValues = original.contentValues;
        this.der = original.der;
    }

    /**
     * Constructs a new Asn1BerValue to be encoded later.
     *
     * @param tagClass      the TagClass
     * @param tagValue      the TagValue
     * @param constructed   <code>true</code> if the value is constructed
     * @param sortOrder     the sort order of a constructed value or
     *                      <code>null</code> if this is a primitive value
     * @param contentBuffer the ByteBuffer that holds the content of a
     *                      primitive value as the remaining bytes or <code>null</code> if this is a
     *                      constructed value
     * @param contentValues the values that make up the content of a
     *                      constructed value or <code>null</code> if this ia a primitive value
     */
    Asn1BerValue(TagClass tagClass, int tagValue, boolean constructed, SortOrder sortOrder, ByteBuffer contentBuffer, List<Asn1BerValue> contentValues) {
        this.tagClass = tagClass;
        this.tagValue = tagValue;
        this.offset = -1; // The offset is not known
        this.constructed = constructed;
        this.endOfContents = false;
        this.sortOrder = sortOrder;
        this.checkDer = false;
        this.checkTagClass = false;
        this.contentBuffer = contentBuffer;
        this.contentValues = contentValues;
    }

    /**
     * Returns a value equivalent to this value with the tag class check
     * disabled.
     *
     * @return a value equivalent to this value but where conversion-time
     * check that the tag class is {@link TagClass#UNIVERSAL} has been
     * disabled, or <code>this</code> if the tag class check has already
     * been disabled
     */
    public Asn1BerValue noTagCheck() {
        return this.checkTagClass ? new Asn1BerValue(this, false) : this;
    }

    /**
     * Asserts that this decoded value is structurally encoded according to
     * DER. Only the Length of the value and all values contained within, if
     * any, contribute.
     *
     * @return this value
     * @throws Asn1DerDecodeException if the value is not structurally encoded
     * according to DER
     */
    public Asn1BerValue der() {
        if (!this.der) {
            throw new Asn1DerDecodeException("Not DER; at offset " + this.offset);
        }
        return this;
    }

    /**
     * Asserts that this value is constructed.
     *
     * @return this value
     * @throws Asn1DecodeException if this value is not constructed
     */
    public Asn1BerValue constructed() {
        if (!this.constructed) {
            throw new Asn1DecodeException("Non-constructed value; at offset " + this.offset);
        }
        return this;
    }

    /**
     * Asserts that this value is primitive.
     *
     * @return this value
     * @throws Asn1DecodeException if this value is constructed
     */
    public Asn1BerValue primitive() {
        if (this.constructed) {
            throw new Asn1DecodeException("Constructed value; at offset " + this.offset);
        }
        return this;
    }

    /**
     * Asserts that the tag on this value is the specified CONTEXT SPECIFIC
     * tag.
     *
     * @param expectedCsTag the expected CONTEXT SPECIFIC tag
     * @return a value equivalent to this value with the tag class check
     * disabled
     * @throws Asn1DecodeException if this value does not have the specified
     * CONTEXT SPECIFIC tag
     */
    public Asn1BerValue tag(int expectedCsTag) {
        return tag(CONTEXT_SPECIFIC, expectedCsTag);
    }

    /**
     * Asserts that the tag class is {@link TagClass#UNIVERSAL} and tag value
     * matches the specified {@link UniversalTag}.
     *
     * @param expectedUniversalTag the expected UNIVERSAL tag
     * @return this value
     * @throws Asn1DecodeException if this value does not have the specified
     * {@link UniversalTag}
     */
    public Asn1BerValue tag(UniversalTag expectedUniversalTag) {
        return tag(UNIVERSAL, expectedUniversalTag.tagValue);
    }

    /**
     * Asserts that the tag class matches the specified tag class
     *
     * @param expectedTagClass the expected tag class
     * @return this value
     */
    public Asn1BerValue tagClass(TagClass expectedTagClass) {
        if (!hasTagClass(expectedTagClass)) {
            throw new Asn1DecodeException("Unexpected tag class at offset " + this.offset + "; expected: " +
                    expectedTagClass.name() + ", was: " + this.tagClass.name());
        }
        return this;
    }

    void assertTagClassDeepInternal(TagClass expectedTagClass) {
        if (this.tagClass != expectedTagClass) {
            throw new Asn1DecodeException("Unexpected tag class at offset " + this.offset + "; expected: " +
                    expectedTagClass.name() + ", was: " + this.tagClass.name());
        }
        if (this.constructed) {
            for (Asn1BerValue subValue : this.contentValues) {
                subValue.assertTagClassDeepInternal(expectedTagClass);
            }
        }
    }

    /**
     * Deeply asserts that the tag class of this value and, recursively,
     * that of all nested values, if any, matches the specified tag class.
     *
     * @param expectedTagClass the expected tag class
     * @return this value
     */
    public Asn1BerValue tagClassDeep(TagClass expectedTagClass) {
        Objects.requireNonNull(expectedTagClass, "expectedTagClass must not be null");
        assertTagClassDeepInternal(expectedTagClass);
        return this;
    }

    /**
     * Asserts that the tag class and tag value match the specified expected
     * tag class and tag value.
     *
     * @param expectedTagClass the expected tag class
     * @param expectedTagValue the expected tag value
     * @return this value, if <em>expectedTagClass</em> is {@link TagClass#UNIVERSAL},
     * or a value equivalent to this value with the tag class check disabled, otherwise
     * @throws Asn1DecodeException if the tag does not match
     */
    public Asn1BerValue tag(TagClass expectedTagClass, int expectedTagValue) {
        if (!hasTag(expectedTagClass, expectedTagValue)) {
            throw new Asn1DecodeException("Unexpected tag at offset " +
                this.offset + "; expected: " +
                Asn1.tagToString(expectedTagClass, expectedTagValue) +
                ", was: " + Asn1.tagToString(this.tagClass, this.tagValue));
        }
        return expectedTagClass != UNIVERSAL ? noTagCheck() : this;
    }

    /**
     * Returns <code>true</code> if this value has the specified CONTEXT
     * SPECIFIC tag.
     *
     * @param expectedCsTag the expected CONTEXT SPECIFIC tag
     * @return <code>true</code> if this value has the specified CONTEXT
     * SPECIFIC tag, <code>false</code> otherwise
     */
    public boolean hasTag(int expectedCsTag) {
        return hasTag(CONTEXT_SPECIFIC, expectedCsTag);
    }

    /**
     * Returns <code>true</code> if this value has the specified UNIVERSAL tag.
     *
     * @param expectedUniversalTag the expected UNIVERSAL tag
     * @return <code>true</code> if this value has the specified UNIVERSAL tag,
     * <code>false</code> otherwise
     */
    public boolean hasTag(UniversalTag expectedUniversalTag) {
        return hasTag(UNIVERSAL, expectedUniversalTag.tagValue);
    }

    /**
     * Returns <code>true</code> if this value has the specified tag class.
     *
     * @param expectedTagClass the expected tag class
     * @return <code>true</code> if this value has the specified tag class,
     * <code>false</code> otherwise
     */
    public boolean hasTagClass(TagClass expectedTagClass) {
        Objects.requireNonNull(expectedTagClass, "expectedTagClass must not be null");
        return this.tagClass == expectedTagClass;
    }

    boolean hasTagClassDeepInternal(TagClass expectedTagClass) {
        if (this.tagClass != expectedTagClass) {
            return false;
        }
        if (this.constructed) {
            for (Asn1BerValue subValue : this.contentValues) {
                if (!subValue.hasTagClassDeepInternal(expectedTagClass)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Returns <code>true</code> if the tag class of this value and, recursively,
     * that of all nested values, if any, matches the specified tag class.
     *
     * @param expectedTagClass the expected tag class
     * @return <code>true</code> if the tag class of this value and, recursively,
     * that of all nested values, if any, matches the specified tag class,
     * <code>false</code> otherwise
     */
    public boolean hasTagClassDeep(TagClass expectedTagClass) {
        Objects.requireNonNull(expectedTagClass, "expectedTagClass must not be null");
        return this.hasTagClassDeepInternal(expectedTagClass);
    }

    /**
     * Returns <code>true</code> if this value has the specified tag class and
     * tag value.
     *
     * @param expectedTagClass the expected tag class
     * @param expectedTagValue the expected tag value
     * @return <code>true</code> if this value has the specified tag, <code>false</code>
     * otherwise
     */
    public boolean hasTag(TagClass expectedTagClass, int expectedTagValue) {
        Objects.requireNonNull(expectedTagClass, "expectedTagClass must not be null");
        if (expectedTagValue < 0) {
            throw new IllegalArgumentException("Invalid expected tag value (negative)");
        }
        return this.tagClass == expectedTagClass && this.tagValue == expectedTagValue;
    }

    void checkTag(UniversalTag expectedUniversalTag) {
        if (this.checkTagClass || this.tagClass == UNIVERSAL) {
            tag(expectedUniversalTag);
        }
    }

    static int decodeIdentifier(ByteBuffer src) {
        int octet = src.get();
        if (octet == -128) {
            // Identifier could be encoded in less octets
            throw new Asn1DecodeException("Invalid identifier encoding");
        }
        int value = octet & 0x7f;
        while (octet < 0) {
            if (value > (Integer.MAX_VALUE >> 7)) {
                throw new Asn1DecodeException("Identifier value exceeds implementation limit");
            }
            octet = src.get();
            value = (value << 7) | (octet & 0x7f);
        }
        return value;
    }

    static int decodeTagValue(ByteBuffer src) {
        int tagValue;
        try {
            tagValue = decodeIdentifier(src);
            if (tagValue < ID_TAG_MASK) {
                throw new Asn1DecodeException("Tag value would fit in first identifier octet");
            }
        } catch (Asn1DecodeException ex) {
            throw new Asn1DecodeException("Invalid BER tag encoding", ex);
        }
        return tagValue;
    }

    int decodeLength(ByteBuffer src) {
        int b = src.get();
        if (b >= 0) {
            return b;
        }
        int c = b & 0x7f;
        if (c == 0) {
            // Not DER: indefinite length
            this.der = false;
            return INDEFINITE_LENGTH;
        }
        if (c > Integer.BYTES) {
            throw new Asn1DecodeException(CONTENT_LENGTH_EXCEEDS_IMPLEMENTATION_LIMIT);
        }

        int len = src.get() & 0xff;
        if (len == 0) {
            // Not DER: leading zero; could have been encoded in less octets
            this.der = false;
        }
        while (--c > 0) {
            b = src.get() & 0xff;
            len = (len << 8) | b;
        }
        if (len < 0) {
            // High bit is set
            throw new Asn1DecodeException(CONTENT_LENGTH_EXCEEDS_IMPLEMENTATION_LIMIT);
        }
        if (len < 0x80) {
            // Not DER: length could have been encoded in a single octet
            this.der = false;
        }
        return len;
    }

    /**
     * Returns <code>true</code> if this BER value and all values contained
     * within, if any, are structurally encoded according to DER. Only the
     * Length (status, i.e. whether indefinite length or not, and encoding)
     * contributes since the types of primitive values may not be known until
     * conversion time.
     */
    public boolean isDer() {
        return this.der;
    }

    /**
     * Returns a ByteBuffer containing the content of this value.
     * For decoded values the content will be present for both constructed and
     * primitive values. For newly created values, only primitive values have
     * a valid content buffer.
     * <p>
     * NOTE: For decoded values, the returned buffer is a slice of the original
     * source buffer that this value was decoded from; changes to the data in
     * the original source buffer at any time could result in changes to the
     * data in the buffer returned by this method.
     *
     * @return a ByteBuffer containing the content of this value
     * @throws NullPointerException if this is a newly created constructed
     * value
     */
    public ByteBuffer content() {
        return this.contentBuffer.slice();
    }

    /**
     * Recursively gathers all primitive content under this value and
     * concatenates it into a newly allocated ByteBuffer. All sub-values must
     * have a Universal tag of {@link UniversalTag#OCTET_STRING} or an
     * exception will be thrown.
     * <p>
     * if this is a primitive value then this method behaves like
     * {@link #content()} except that the returned buffer contains a copy of
     * the data made at the time of the call to this method rather than a slice
     * of the original source buffer from which this value was decoded.
     *
     * @return a newly allocated ByteBuffer containing a copy of the gathered
     * content
     * @throws Asn1DecodeException if any sub-values have a tag other than
     * Universal {@link UniversalTag#OCTET_STRING}
     */
    public ByteBuffer gatherContent() {
        List<ByteBuffer> bufferList = new ArrayList<>();
        int size = gatherContent(bufferList);
        ByteBuffer gatherBuf = ByteBuffer.allocate(size);
        for (ByteBuffer buf : bufferList) {
            gatherBuf.put(buf);
        }
        gatherBuf.rewind();
        return gatherBuf;
    }

    int gatherContent(List<ByteBuffer> bufferList) {
        if (this.constructed) {
            int size = 0;
            for (Asn1BerValue value : values()) {
                value.tag(OCTET_STRING);
                size += value.gatherContent(bufferList);
            }
            return size;
        }
        if (this.contentBuffer.hasRemaining()) {
            bufferList.add(content());
        }
        return this.contentBuffer.remaining();
    }

    /**
     * Recursively gathers all primitive content under this value and
     * concatenates it into a newly allocated ByteBuffer. All sub-values must
     * have a Universal tag of {@link UniversalTag#OCTET_STRING} or an
     * exception will be thrown.
     * <p>
     * if this is a primitive value then this method behaves like
     * {@link #octets()}.
     *
     * @return a byte array containing a copy of the gathered content
     * @throws Asn1DecodeException if any sub-values have a tag other than
     * Universal {@link UniversalTag#OCTET_STRING}
     */
    public byte[] gatherOctets() {
        return gatherContent().array();
    }

    /**
     * Returns a byte array containing the content of this value.
     * For decoded values the content will be present for both constructed and
     * primitive values. For newly created values, only primitive values have
     * a valid content buffer.
     * <p>
     * NOTE: For decoded values, the returned buffer is a copy made at the time
     * of the call to this method of data from the original source buffer that
     * this value was decoded from; changes to the data in the original source
     * buffer after decoding but prior to the call to this method could result
     * in changes to the data in the byte array returned by this method.
     *
     * @return a byte array containing the content of this value
     * @throws NullPointerException if this is a newly created constructed
     * value
     */
    public byte[] octets() {
        ByteBuffer c = content();
        byte[] contentOctets = new byte[c.remaining()];
        c.get(contentOctets);
        return contentOctets;
    }

    /**
     * Returns a list of the sub-values contained within this constructed
     * value.
     *
     * @return the list of sub-values
     * @throws Asn1DecodeException if this is not a constructed value
     */
    public List<Asn1BerValue> values() {
        constructed();
        return this.contentValues;
    }

    /**
     * Returns a list of the sub-values contained within this sequence.
     *
     * @return the list of sub-values
     * @throws Asn1DecodeException if this is not a constructed value or has a
     * Universal tag which is not {@link UniversalTag#SEQUENCE}
     */
    public List<Asn1BerValue> sequence() {
        constructed().checkTag(SEQUENCE);
        return this.contentValues;
    }

    /**
     * Returns a list of the sub-values contained within this sequence.
     * This is used for extracting the content of both <code>SET</code>s and
     * <code>SET OF</code>s.
     *
     * @return the list of sub-values
     * @throws Asn1DecodeException if this is not a constructed value or has a
     * Universal tag which is not {@link UniversalTag#SET}
     */
    public List<Asn1BerValue> set() {
        constructed().checkTag(SET);
        return this.contentValues;
    }

    /**
     * Asserts that this constructed value has no more than the specified
     * number of sub-values.
     *
     * @param max the maximum number of sub-values
     * @return this value
     * @throws Asn1DecodeException if this is not a constructed value or has
     * more than the specified number maximum of sub-values
     */
    public Asn1BerValue maxCount(int max) {
        List<Asn1BerValue> vl = values();
        if (vl.size() > max) {
            throw new Asn1DecodeException("Constructed BER value contains more than " + max + " sub-values: " + vl.size() + AT_OFFSET + this.offset);
        }
        return this;
    }

    /**
     * Asserts that this constructed value has no fewer than the specified
     * number of sub-values.
     *
     * @param min the minimum number of sub-values
     * @return this value
     * @throws Asn1DecodeException if this is not a constructed value or has
     * less than the specified minimum number of sub-values
     */
    public Asn1BerValue minCount(int min) {
        List<Asn1BerValue> vl = values();
        if (vl.size() < min) {
            throw new Asn1DecodeException("Constructed BER value contains less than " + min + " sub-values: " + vl.size() + AT_OFFSET + this.offset);
        }
        return this;
    }

    /**
     * Asserts that this constructed value has no fewer than the specified
     * minimum and no more than the specified maximum number of sub-values.
     *
     * @param min the minimum number of sub-values
     * @param max the maximum number of sub-values
     * @return this value
     * @throws Asn1DecodeException if this is not a constructed value or has
     * less than the specified minimum or more than the specified maximum
     * number of sub-values
     */
    public Asn1BerValue count(int min, int max) {
        return minCount(min).maxCount(max);
    }

    /**
     * Asserts that this constructed value has exactly the specified number of
     * sub-values.
     *
     * @param n the number of sub-values
     * @return this value
     * @throws Asn1DecodeException if this is not a constructed value or has a
     * number of sub-values other than the number specified
     */
    public Asn1BerValue count(int n) {
        return count(n, n);
    }

    /**
     * Extracts the single value contained within this explicit tag.
     *
     * @return the single value contained within this explicit tag
     * @throws Asn1DecodeException if this is not a constructed value, has
     * other than one sub-value or has a Universal tag
     */
    public Asn1BerValue explicit() {
        count(1);
        if (this.checkTagClass) {
            throw new Asn1DecodeException("Explicit tag value not asserted; at offset " + this.offset);
        }
        if (this.tagClass == UNIVERSAL) {
            throw new Asn1DecodeException("Unexpected universal explicit tag; at offset " + this.offset);
        }
        return this.contentValues.get(0);
    }

    /**
     * Extracts the content of this BOOLEAN as a <code>boolean</code>.
     *
     * @return the <code>boolean</code> value of this BOOLEAN
     * @throws Asn1ContentDecodeException if the content is not exactly one
     * octet in size
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#BOOLEAN}
     */
    public boolean getBoolean() {
        primitive().checkTag(BOOLEAN);
        if (this.contentBuffer.remaining() != 1) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + BOOLEAN.asn1Name() + AT_OFFSET + this.offset);
        }
        int v = this.contentBuffer.get(this.contentBuffer.position());

        // Check for DER compliance, if enabled.
        // DER encoding is either 0x00 (FALSE) or 0xff (TRUE).
        if (this.checkDer && ((v + 1) & 0xfe) != 0) {
            throw new Asn1DerDecodeException(CONTENT_NOT_DER_COMPLIANT + BOOLEAN.asn1Name() + AT_OFFSET + this.offset);
        }

        return v != 0x00;
    }

    /**
     * Extracts the content of this ENUMERATED as a <code>BigInteger</code>.
     *
     * @return the <code>BigInteger</code> value of this ENUMERATED
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#ENUMERATED}
     */
    public BigInteger getEnumerated() {
        return getInteger(ENUMERATED);
    }

    /**
     * Extracts the content of this INTEGER as a <code>BigInteger</code>.
     *
     * @return the <code>BigInteger</code> value of this INTEGER
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#INTEGER}
     */
    public BigInteger getInteger() {
        return getInteger(INTEGER);
    }

    private BigInteger getInteger(UniversalTag type) {
        byte[] val = getIntegerOctets(type);
        return new BigInteger(val);
    }

    /**
     * Extracts the content octets of this INTEGER as a byte array.
     *
     * @return the byte array value of this INTEGER
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#INTEGER}
     */
    public byte[] getIntegerOctets() {
        return getIntegerOctets(INTEGER);
    }

    private byte[] getIntegerOctets(UniversalTag type) {
        primitive().checkTag(type);
        if (!this.contentBuffer.hasRemaining()) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + type.asn1Name() + AT_OFFSET + this.offset);
        }
        byte[] val = octets();

        // Check that the content is valid for BER.
        if (Asn1.countRedundantLeadingOctets(val) > 0) {
            Arrays.fill(val, (byte)0);
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + type.asn1Name() + AT_OFFSET + this.offset);
        }

        return val;
    }

    /**
     * Parses the content of this UTCTime or GeneralizedTime and returns a date-time object with concrete
     * class of either <code>java.time.OffsetDateTime</code> or <code>java.time.LocalDateTime</code>,
     * depending on whether timezone offset information is present. This value must have a Universal tag
     * that identifies the type of ASN.1 value (UTCTime or GeneralizedTime) to be parsed.
     *
     * @return either an <code>OffsetDateTime</code> or a <code>LocalDateTime</code> object, depending on
     * whether timezone offset information is present
     * @throws Asn1ContentDecodeException if the content encoding is not valid for the UTCTime or GeneralizedTime value
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if the type of this ASN.1 value (UTCTime or GeneralizedTime) can not be
     * determined from the tag
     */
    public TemporalAccessor getDateTime() {
        UniversalTag ut = Asn1.toUniversalTag(this.tagClass, this.tagValue);
        if (ut != UTCTime && ut != GeneralizedTime) {
            throw new Asn1DecodeException(
                    "UTCTime or GeneralizedTime Tag required: " +
                            Asn1.tagToString(this.tagClass, this.tagValue));
        }
        return ut == UTCTime ? getUtcTime() : getGeneralizedTime();
    }

    /**
     * Parses the content of this UTCTime and returns a
     * <code>java.time.OffsetDateTime</code> object.
     *
     * @return an <code>OffsetDateTime</code> object
     * @throws Asn1ContentDecodeException if the content encoding is not valid for a UTCTime value
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if this value has a Universal tag which is not
     * {@link UniversalTag#UTCTime}
     */
    public OffsetDateTime getUtcTime() {
        String contentString = getRcs(UTCTime);
        Matcher matcher = UTC_TIME_PATTERN.matcher(contentString);
        if (!matcher.matches()) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + UTCTime.asn1Name() + AT_OFFSET + this.offset);
        }

        String second = matcher.group("second");
        String tzOffset = matcher.group("offset");
        boolean contentIsDer = second != null && tzOffset.equals("Z");

        if (this.checkDer && !contentIsDer) {
            throw new Asn1DerDecodeException(CONTENT_NOT_DER_COMPLIANT + UTCTime.asn1Name() + AT_OFFSET + this.offset);
        }

        try {
            return OffsetDateTime.parse(contentString, UTC_TIME_PARSER);
        } catch (DateTimeParseException e) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + UTCTime.asn1Name() + AT_OFFSET + this.offset);
        }
    }

    /**
     * Parses the content of this GeneralizedTime and returns either a
     * <code>java.time.OffsetDateTime</code> object, with offset <code>ZoneOffset.UTC</code>, or a
     * <code>java.time.LocalDateTime</code> object depending on whether timezone offset information
     * is present.
     *
     * @return either an <code>OffsetDateTime</code> or a <code>LocalDateTime</code> object
     * @throws Asn1ContentDecodeException if the content encoding is not valid for a GeneralizedTime value
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if this value has a Universal tag which is not
     * {@link UniversalTag#GeneralizedTime}
     */
    public TemporalAccessor getGeneralizedTime() {
        String contentString = getRcs(GeneralizedTime);
        Matcher matcher = GENERALIZED_TIME_PATTERN.matcher(contentString);
        if (!matcher.matches()) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + GeneralizedTime.asn1Name() + AT_OFFSET + this.offset);
        }

        String minute = matcher.group("minute");
        String second = matcher.group("second");
        String nano = matcher.group("nano");
        String tzOffset = matcher.group("offset");
        boolean contentIsDer = minute != null &&
                second != null &&
                (nano == null || (nano.startsWith(".") && !nano.endsWith("0"))) &&
                "Z".equals(tzOffset);

        if (this.checkDer && !contentIsDer) {
            throw new Asn1DerDecodeException(CONTENT_NOT_DER_COMPLIANT + GeneralizedTime.asn1Name() + AT_OFFSET + this.offset);
        }

        // Ensure decimal point is '.' for parsing.
        if (nano != null && nano.startsWith(",")) {
            contentString = contentString.replace(',', '.');
        }

        // Insert defaults for minutes and seconds before parsing.
        // It appears that these cannot be made optional in the DateTimeFormatter,
        // possibly due to later variable-length optional components and no separators.
        if (minute == null) {
            // Minute defaults to 00. Second defaults to 00.
            contentString = contentString.substring(0, 10) + "0000" + contentString.substring(10);
        } else if (second == null) {
            // Second defaults to 00.
            contentString = contentString.substring(0, 12) + "00" + contentString.substring(12);
        }

        try {
            // Parse the content and return an OffsetDateTime if timezone offset information is present,
            // otherwise return a LocalDateTime.
            return GENERALIZED_TIME_PARSER.parseBest(contentString, OffsetDateTime::from, LocalDateTime::from);
        } catch (DateTimeParseException e) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + GeneralizedTime.asn1Name() + AT_OFFSET + this.offset);
        }
    }

    /**
     * Extracts the encoded content of this BIT STRING as a new ByteBuffer.
     * The first octet (at index zero) is the number of unused bits in the
     * final octet (at index <code>capacity() - 1</code>).  Bit zero of this
     * BIT STRING is the Most Significant Bit (bit 7, counting from 0) of the
     * second octet, and so on.
     * <p>
     * Unused bits are zeroed in the buffer before it is returned.
     *
     * @return the content of this BIT STRING as a ByteBuffer
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if this value has a Universal tag which is
     * not {@link UniversalTag#BIT_STRING} or this value is constructed
     * and a sub-value (recursively) has a tag other than
     * {@link UniversalTag#OCTET_STRING}
     */
    public ByteBuffer getBitStringContent() {
        checkTag(BIT_STRING);
        ByteBuffer content = gatherContent();
        int unusedBits;
        if (!content.hasRemaining() || (unusedBits = content.get(0) & 0xff) > 7) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + BIT_STRING.asn1Name() + AT_OFFSET + this.offset);
        }
        if (unusedBits > 0) {
            // Set the unused bits to zero
            int mask = (1 << unusedBits) - 1;
            int lastIndex = content.capacity() - 1;
            boolean contentIsDer = mask == 0 || lastIndex > 0;
            if (lastIndex > 0) {
                int lastOctet = content.get(lastIndex);
                if ((lastOctet & mask) != 0) {
                    content.put(lastIndex, (byte)(lastOctet & ~mask));
                    contentIsDer = false;
                }
            }
            if (this.checkDer && !contentIsDer) {
                throw new Asn1DerDecodeException(CONTENT_NOT_DER_COMPLIANT + BIT_STRING.asn1Name() + AT_OFFSET + this.offset);
            }
        }
        return content;
    }

    /**
     * Extracts the content of this BIT STRING as a byte array.  Bit zero of
     * this BIT STRING is the Most Significant Bit (bit 7, counting from 0) of
     * the second octet, and so on.
     * <p>
     * Unused bits are zeroed in the buffer before it is returned.
     *
     * @return the byte array content of this BIT STRING
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if this value has a Universal tag which is
     * not {@link UniversalTag#BIT_STRING} or this value is constructed
     * and a sub-value (recursively) has a tag other than
     * {@link UniversalTag#OCTET_STRING}
     */
    public byte[] getBitStringOctets() {
        byte[] bytes = getBitStringContent().array();
        return Arrays.copyOfRange(bytes, 1, bytes.length);
    }

    /**
     * Extracts the content of this BIT STRING as a <code>BitSet</code>.
     *
     * @return the <code>BitSet</code> value of this BIT STRING
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DerDecodeException if the content does not comply with DER,
     * and DER compliance checking is enabled
     * @throws Asn1DecodeException if this value has a Universal tag which is
     * not {@link UniversalTag#BIT_STRING} or this value is constructed
     * and a sub-value (recursively) has a tag other than
     * {@link UniversalTag#OCTET_STRING}
     */
    public BitSet getBitString() {
        ByteBuffer content = getBitStringContent();

        // Skip the initial octet (unused bits)
        content.position(1);

        // Reverse the bits in each octet
        while (content.hasRemaining()) {
            int b = Integer.reverse(content.get(content.position())) >>> 24;
            content.put((byte)b);
        }
        content.position(1);
        return BitSet.valueOf(content);
    }

    /**
     * Extracts the content of this OCTET STRING as a byte array.
     *
     * @return the byte array content of this OCTET STRING
     * @throws Asn1DecodeException if this value has a Universal tag which is
     * not {@link UniversalTag#OCTET_STRING} or this value is constructed
     * and a sub-value (recursively) has a tag other than
     * {@link UniversalTag#OCTET_STRING}
     */
    public byte[] getOctetString() {
        checkTag(OCTET_STRING);
        return gatherOctets();
    }

    /**
     * Asserts that this value is an ASN.1 NULL.
     *
     * @throws Asn1ContentDecodeException if the content is not empty
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#NULL}
     */
    public void getNull() {
        primitive().checkTag(NULL);
        if (this.contentBuffer.hasRemaining()) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + NULL.asn1Name() + AT_OFFSET + this.offset);
        }
    }

    static int countOidSubIdentifiers(ByteBuffer content) {
        int subIds = 0;
        content.mark();
        while (content.hasRemaining()) {
            if (content.get() >= 0) {
                ++subIds;
            }
        }
        content.reset();
        return subIds;
    }

    /**
     * A utility method that formats an array of <code>int</code>s as a
     * "dotted" String, i.e. as a single String with the components separated
     * by '.' characters.
     *
     * @param components the int array
     * @return the dotted String
     */
    public static String dottedString(int[] components) {
        if (components.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(components[0]);
        for (int i = 1; i < components.length; ++i) {
            sb.append('.').append(components[i]);
        }
        return sb.toString();
    }

    void decodeOidSubIdentifiers(ByteBuffer content, int[] subIds, int offset, UniversalTag ut) {
        try {
            while (content.hasRemaining()) {
                subIds[offset++] = decodeIdentifier(content);
            }
        } catch (BufferUnderflowException | Asn1DecodeException ex) {
            throw new Asn1ContentDecodeException(INVALID_BER_CONTENT_ENCODING + ut.asn1Name() + AT_OFFSET + this.offset, ex);
        }
    }

    /**
     * Extracts the content of this OBJECT IDENTIFIER as an array of ints.
     *
     * @return the int array value of this OBJECT IDENTIFIER
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#OBJECT_IDENTIFIER}
     */
    public int[] getOidComponents() {
        primitive().checkTag(OBJECT_IDENTIFIER);
        ByteBuffer content = content();
        int[] subIds = new int[countOidSubIdentifiers(content) + 1];
        int c1 = decodeIdentifier(content);
        int c0 = c1 / 40;
        switch (c0) {
        case 0:
            break;
        case 1:
            c1 -= 40;
            break;
        default:
            c0 = 2;
            c1 -= 80;
            break;
        }
        subIds[0] = c0;
        subIds[1] = c1;
        decodeOidSubIdentifiers(content, subIds, 2, OBJECT_IDENTIFIER);
        return subIds;
    }

    /**
     * Extracts the content of this OBJECT IDENTIFIER as a "dotted" String,
     * such as <code>"1.2.840.113549.1.1.1"</code>.
     *
     * @return the String value of this OBJECT IDENTIFIER
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#OBJECT_IDENTIFIER}
     */
    public String getOid() {
        return dottedString(getOidComponents());
    }

    /**
     * Extracts the content of this RELATIVE OID as an array of ints.
     *
     * @return the int array value of this RELATIVE OID
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#RELATIVE_OID}
     */
    public int[] getRelativeOidComponents() {
        primitive().checkTag(RELATIVE_OID);
        ByteBuffer content = content();
        int[] subIds = new int[countOidSubIdentifiers(content)];
        decodeOidSubIdentifiers(content, subIds, 0, RELATIVE_OID);
        return subIds;
    }

    /**
     * Extracts the content of this RELATIVE OID as a "dotted" String, such as
     * <code>"113549.1.1.1"</code>.
     *
     * @return the String value of this OBJECT IDENTIFIER
     * @throws Asn1ContentDecodeException if the content encoding is invalid
     * @throws Asn1DecodeException if this value is not primitive or has a
     * Universal tag which is not {@link UniversalTag#RELATIVE_OID}
     */
    public String getRelativeOid() {
        return dottedString(getRelativeOidComponents());
    }

    /**
     * Extracts the content of this Restricted Character String as a
     * <code>String</code>. This value must have a Universal tag that
     * identifies the encoding of the RCS.
     *
     * @return the String value of this RCS
     * @throws Asn1DecodeException if the encoding of this RCS can not be
     * determined from the tag
     */
    public String getRcs() {
        UniversalTag ut = Asn1.toUniversalTag(this.tagClass, this.tagValue);
        if (ut == null) {
            throw new Asn1DecodeException(
                "Valid Restricted Character String Universal Tag required: " +
                Asn1.tagToString(this.tagClass, this.tagValue));
        }
        return getRcs(ut);
    }

    /**
     * Extracts the content of this Restricted Character String as a
     * <code>String</code> using the encoding identified by the specified
     * Universal tag.
     *
     * @return the String value of this RCS
     * @throws Asn1DecodeException if this value has a Universal tag which does
     * not agree with the specified encoding
     */
    public String getRcs(UniversalTag encoding) {
        checkTag(encoding);
        try {
            return new String(gatherOctets(), Asn1.getRcsCharset(encoding));
        } catch (Asn1Exception ex) {
            throw new Asn1DecodeException(ex.getMessage() + AT_OFFSET + this.offset, ex);
        }
    }

    int calcIdAndLenLength(int contentLen) {
        int idLen = 1;
        if (this.tagValue >= ID_TAG_MASK) {
            int tagBitCount = Integer.SIZE - Integer.numberOfLeadingZeros(this.tagValue);
            idLen += (tagBitCount + 6) / 7;
        }
        int lenLen = 1;
        if (contentLen >= 0x80) {
            int lenBitCount = Integer.SIZE - Integer.numberOfLeadingZeros(contentLen);
            lenLen += (lenBitCount + 7) / 8;
        }
        return idLen + lenLen;
    }

    /**
     * Returns the length of the content of this value, in octets. For
     * primitive values this is the length of the existing content. For
     * constructed values the length is always recalculated even if this is a
     * decoded value with an existing content buffer; if the BER data does not
     * conform to DER then the length may not agree with length of the content
     * buffer.
     * <p>
     * Note: The length of the existing content buffer for a decoded value can
     * be determined by calling <code>content().remaining()</code>.
     *
     * @return the length of the content of this value, in octets
     */
    public int contentLength() {
        if (this.constructed) {
            int len = 0;
            for (Asn1BerValue value : this.contentValues) {
                len += value.encodedLength();
            }
            return len;
        }
        return this.contentBuffer.remaining();
    }

    /**
     * Calculates the length of the DER encoding of this value.
     *
     * @return the length of the DER encoding of this value in octets
     */
    public int encodedLength() {
        int contentLen = contentLength();
        return calcIdAndLenLength(contentLen) + contentLen;
    }

    void encodeIdAndLen(ByteBuffer dst) {
        // Encode identifier octets
        int id = this.tagClass.ordinal() << ID_TAG_CLASS_SHIFT;
        if (this.constructed) {
            id |= ID_CONSTRUCTED_MASK;
        }
        if (this.tagValue < ID_TAG_MASK) {
            id |= this.tagValue;
            dst.put((byte)id);
        } else {
            id |= ID_TAG_MASK;
            dst.put((byte)id);
            Asn1.encodeIdentifier(dst, this.tagValue);
        }

        // Encode content length octets
        int contentLen = contentLength();
        if (contentLen < 0x80) {
            dst.put((byte)contentLen);
        } else {
            int lenBitCount = Integer.SIZE - Integer.numberOfLeadingZeros(contentLen);
            int lenLen = (lenBitCount + 7) / 8;
            dst.put((byte)(0x80 | lenLen));
            int shift = lenLen * 8;
            do {
                shift -= 8;
                dst.put((byte)(contentLen >>> shift));
            } while (shift > 0);
        }
    }

    /**
     * DER encodes and outputs a list of values to the specified
     * <code>ByteBuffer</code>.
     *
     * @param dst the destination buffer for the DER data
     * @param content the list of values to encode
     */
    public static void encodeSequenceContent(ByteBuffer dst, List<Asn1BerValue> content) {
        for (Asn1BerValue value : content) {
            value.encodeDer(dst);
        }
    }

    static class SetComparator implements Comparator<Asn1BerValue> {
        public int compare(Asn1BerValue v1, Asn1BerValue v2) {
            if (v1.tagClass != v2.tagClass) {
                return v1.tagClass.ordinal() - v2.tagClass.ordinal();
            }
            return Integer.compare(v1.tagValue, v2.tagValue);
        }
    }
    static final SetComparator SET_COMPARATOR = new SetComparator();

    /**
     * DER encodes and outputs a list of values to the specified
     * <code>ByteBuffer</code>. The values are encoded and output in the order
     * required by DER for a <code>SET</code>.
     *
     * @param dst the destination buffer for the DER data
     * @param content the list of values to encode
     */
    public static void encodeSetContent(ByteBuffer dst, List<Asn1BerValue> content) {
        // Sort by tags
        List<Asn1BerValue> sortedContent = new ArrayList<>(content);
        sortedContent.sort(SET_COMPARATOR);
        encodeSequenceContent(dst, sortedContent);
    }

    static class SetOfComparator implements Comparator<byte[]> {
        public int compare(byte[] v1, byte[] v2) {
            int commLen = Math.min(v1.length, v2.length);
            for (int i = 0; i < commLen; ++i) {
                int c = (v1[i] & 0xff) - (v2[i] & 0xff);
                if (c != 0) {
                    return c;
                }
            }
            return Integer.compare(v1.length, v2.length);
        }
    }
    static final SetOfComparator SET_OF_COMPARATOR = new SetOfComparator();

    /**
     * DER encodes and outputs a list of values to the specified
     * <code>ByteBuffer</code>. The values are encoded and output in the order
     * required by DER for a <code>SET OF</code>.
     *
     * @param dst the destination buffer for the DER data
     * @param content the list of values to encode
     */
    public static void encodeSetOfContent(ByteBuffer dst, List<Asn1BerValue> content) {
        // Sort by encoded values
        byte[][] sortedContent = new byte[content.size()][];
        int i = 0;
        for (Asn1BerValue value : content) {
            sortedContent[i++] = value.encodeDerOctets();
        }
        Arrays.sort(sortedContent, SET_OF_COMPARATOR);
        for (byte[] encodedValue : sortedContent) {
            dst.put(encodedValue);
        }
    }

    /**
     * Encodes this value as DER and outputs it to the specified destination
     * <code>ByteBuffer</code>. The amount of space required can be calculated
     * by calling {@link #encodedLength()}.
     *
     * @param dst the destination buffer
     * @throws java.nio.BufferOverflowException if the buffer does not have
     * sufficient space available for the DER-encoded output
     */
    public void encodeDer(ByteBuffer dst) {
        encodeIdAndLen(dst);
        if (this.constructed) {
            switch (this.sortOrder) {
            case SEQUENCE:
                encodeSequenceContent(dst, this.contentValues);
                break;
            case SET:
                encodeSetContent(dst, this.contentValues);
                break;
            case SET_OF:
                encodeSetOfContent(dst, this.contentValues);
                break;
            }
        } else {
            dst.put(content());
        }
    }

    /**
     * Encodes this value as DER and returns it in a new ByteBuffer.
     *
     * @return the DER encoding of this value in a ByteBuffer
     */
    public ByteBuffer encodeDer() {
        ByteBuffer buf = ByteBuffer.allocate(encodedLength());
        encodeDer(buf);
        assert !buf.hasRemaining();
        buf.rewind();
        return buf;
    }

    /**
     * Encodes this value as DER and returns it as a byte array.
     *
     * @return the DER encoding of this value as a byte array
     */
    public byte[] encodeDerOctets() {
        return encodeDer().array();
    }

    /**
     * Formats the bytes remaining in the specified ByteBuffer as a hexadecimal
     * String with each byte separated from the other bytes by a single space
     * and formatted as two uppercase hex digits. The position of the buffer
     * is updated to equal the limit.
     *
     * @param buf the ByteBuffer containing the bytes to be formatted
     * @return the hexadecimal String
     */
    static String hex(ByteBuffer buf) {
        StringBuilder sb = new StringBuilder();
        try {
            hex(sb, buf);
        } catch (IOException ex) {
            // Unexpected
            throw new Error(ex);
        }
        return sb.toString();
    }

    /**
     * Formats each byte remaining in the specified ByteBuffer as a pair of
     * uppercase hexadecimal digits with each byte separated from the others by
     * a single space. The resulting output is appended to the specified
     * Appendable. The position of the buffer is updated to equal the limit.
     *
     * @param out the Appendable to output the formatted hexadecimal bytes to
     * @param buf the ByteBuffer containing the bytes to be formatted
     */
    static void hex(Appendable out, ByteBuffer buf) throws IOException {
        boolean first = true;
        while (buf.hasRemaining()) {
            if (first) {
                first = false;
            } else {
                out.append(' ');
            }
            out.append(String.format("%02X", buf.get() & 0xff));
        }
    }

    /**
     * Quotes the specified String in single quotes while escaping any
     * single-quotes contained in the String.
     *
     * @param str the String to be quoted
     * @return the quoted String
     */
    static String quoteString(String str) {
        return str.replace("'", "\\'");
    }

    /**
     * Returns a short String representation of this Asn1BerValue. For
     * constructed values the tag and an indication that it is a constructed
     * value is output. For primitive values only a String representation of
     * the content is output (no tag). Primitive values without a universal tag
     * are represented as a hex String.
     *
     * @return the String representation of this value
     */
    @Override
    public String toString() {
        if (this.constructed) {
            return Asn1.tagToString(this.tagClass, this.tagValue) + " <constructed>";
        } else {
            UniversalTag ut = Asn1.toUniversalTag(this.tagClass, this.tagValue);
            if (ut != null) {
                switch (ut) {
                case BOOLEAN:
                    return Boolean.toString(getBoolean()).toUpperCase();
                case INTEGER:
                case ENUMERATED:
                    return getInteger(ut).toString();
                case NULL:
                    getNull();
                    return "NULL";
                case OBJECT_IDENTIFIER:
                    return "(" + getOid().replace('.', ' ') + ')';
                case RELATIVE_OID:
                    return "(" + getRelativeOid().replace('.', ' ') + ')';
                case UTF8String:
                case NumericString:
                case PrintableString:
                case TeletexString:
                case VideotexString:
                case IA5String:
                case GraphicString:
                case VisibleString:
                case GeneralString:
                case UniversalString:
                case BMPString:
                    return "'" + quoteString(getRcs(ut)) + '\'';
                case UTCTime:
                    return getUtcTime().toString();
                case GeneralizedTime:
                    return getGeneralizedTime().toString();
                }
            }
            return Asn1BerValue.hex(content());
        }
    }

    /**
     * Calculates the deep hash code of this value. Values that compare equal
     * according to {@link #equals(Object)} will also have the same hash code.
     *
     * @return the hash code of this value
     */
    @Override
    public int hashCode() {
        int tagHash = this.tagValue * 3 + tagClass.ordinal();
        if (this.constructed) {
            return this.contentValues.hashCode() * 17 + tagHash;
        }
        return this.contentBuffer.hashCode() * 17 + tagHash;
    }

    /**
     * Deeply compares this value with another specified value; the tag, length
     * and content all contribute to the comparison. Newly created and decoded
     * constructed values can be successfully compared regardless of the
     * original encoding of the decoded value with respect to use of indefinite
     * length encoding or whether or not the length was encoded according to
     * DER. Decoded primitive values as well as SET and SET OF constructed
     * values, however, may not compare equal to other values if one or both
     * were not encoded according to DER.
     *
     * @return <code>true</code> if this value is equal to the other value
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Asn1BerValue other)) {
            return false;
        }
        if (this.tagClass != other.tagClass ||
                this.tagValue != other.tagValue ||
                this.constructed != other.constructed) {
            return false;
        }
        if (this.constructed) {
            return this.contentValues.equals(other.contentValues);
        }
        return this.contentBuffer.equals(other.contentBuffer);
    }

}
