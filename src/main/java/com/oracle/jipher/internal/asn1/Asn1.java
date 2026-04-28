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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.oracle.jipher.internal.asn1.Asn1BerValue.SortOrder;

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
import static com.oracle.jipher.internal.asn1.UniversalTag.UTF8String;

/**
 * Factory class for encoding and decoding Asn1BerValue objects.
 */
public final class Asn1 {

    private Asn1() { }

    static final byte[] FALSE = {0x00};
    static final byte[] TRUE = {(byte)0xff};

    static final DateTimeFormatter UTC_TIME_FORMATTER = new DateTimeFormatterBuilder()
            .appendValueReduced(ChronoField.YEAR, 2, 2, 1950)
            .appendPattern("MMddHHmmss'Z'").toFormatter();

    static final DateTimeFormatter GENERALIZED_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");
    static final DateTimeFormatter GENERALIZED_TIME_FRACTIONAL_FORMATTER = new DateTimeFormatterBuilder()
            .appendPattern("yyyyMMddHHmmss'.'")
            .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, false)
            .appendLiteral('Z').toFormatter();

    static final Map<Integer,UniversalTag> MAP_TO_UNIVERSAL = genMapToUniversal();
    static Map<Integer,UniversalTag> genMapToUniversal() {
        Map<Integer,UniversalTag> map = new HashMap<>();
        for (UniversalTag ut : UniversalTag.values()) {
            if (!map.containsKey(ut.tagValue)) {
                map.put(ut.tagValue, ut);
            }
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Decodes an ASN.1 BER value and its sub-values, if it is constructed,
     * from the specified ByteBuffer and moves the position past the decoded
     * value. The content of the value, and sub-values, is captured as slices
     * of the <b>src</b> buffer; the data in the <b>src</b> buffer should not
     * be changed while any decoded Asn1BerValues are still in use.
     *
     * @param src the ByteBuffer from which to decode the BER value
     * as well as the primitive content at primitive conversion time
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of the value being invalid
     */
    public static Asn1BerValue decode(ByteBuffer src) {
        return decode(src, false);
    }

    /**
     * Decodes an ASN.1 BER value and its sub-values, if it is constructed,
     * from the specified ByteBuffer and moves the position past the decoded
     * value. The content of the value, and sub-values, is captured as slices
     * of the <b>src</b> buffer; the data in the <b>src</b> buffer should not
     * be changed while any decoded Asn1BerValues are still in use.
     *
     * @param src the ByteBuffer from which to decode the BER value
     * @param checkDer enable DER checking for the length octets at decode time
     * as well as the primitive content at primitive extraction/conversion time
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of the value being invalid
     */
    public static Asn1BerValue decode(ByteBuffer src, boolean checkDer) {
        return new Asn1BerValue(src, checkDer, 0);
    }

    /**
     * Decodes a single ASN.1 BER value and its sub-values, if it is
     * constructed, from the specified ByteBuffer, moves the position past the
     * decoded value and asserts that there is no more data remaining in the
     * buffer. The content of the value, and sub-values, is captured as slices
     * of the <b>src</b> buffer; the data in the <b>src</b> buffer should not
     * be changed while any decoded Asn1BerValues are still in use.
     *
     * @param src the ByteBuffer from which to decode the BER value
     * as well as the primitive content at primitive conversion time
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of the value being invalid or due to unconsumed data remaining
     * in the buffer
     */
    public static Asn1BerValue decodeOne(ByteBuffer src) {
        return decodeOne(src, false);
    }

    /**
     * Decodes a single ASN.1 BER value and its sub-values, if it is
     * constructed, from the specified ByteBuffer and moves the position past
     * the decoded value and asserts that there is no more data remaining in
     * the buffer. The content of the value, and sub-values, is captured as
     * slices of the <b>src</b> buffer; the data in the <b>src</b> buffer
     * should not be changed while any decoded Asn1BerValues are still in use.
     *
     * @param src the ByteBuffer from which to decode the BER value
     * @param checkDer enable DER checking for the length octets at decode time
     * as well as the primitive content at primitive extraction/conversion time
     * @throws Asn1DecodeException If the decode operation fails due to the
     * encoding of the value being invalid or due to unconsumed data remaining
     * in the buffer
     */
    public static Asn1BerValue decodeOne(ByteBuffer src, boolean checkDer) {
        Asn1BerValue value = decode(src, checkDer);
        if (src.hasRemaining()) {
            throw new Asn1DecodeException("Unconsumed data remains in buffer after decoding value; at offset " + value.offset);
        }
        return value;
    }

    /**
     * Decodes a single ASN.1 BER value and its sub-values, if constructed, from the
     * specified byte[] and asserts that the full data array was consumed.
     *
     * @param src the byte array from which to decode the BER value
     * @param checkDer enable DER checking for the length octets at decode time
     * as well as the primitive content at primitive extraction/conversion time
     * @return the decoded value
     */
    public static Asn1BerValue decodeOne(byte[] src, boolean checkDer) {
        return decodeOne(ByteBuffer.wrap(src), checkDer);
    }

    /**
     * Decodes a single ASN.1 BER value and its sub-values, if constructed, from the
     * specified byte[] and asserts that the full data array was consumed.
     *
     * @param src the byte array from which to decode the BER value
     * @return the decoded value
     */
    public static Asn1BerValue decodeOne(byte[] src) {
        return decodeOne(src, false);
    }

    /**
     * Decodes all remaining bytes in the specified <code>ByteBuffer</code>
     * as zero or more complete values and returns the list of values.
     *
     * @param src the source buffer containing the BER data
     * @return the list of decoded values
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of any value being invalid or incomplete
     */
    public static List<Asn1BerValue> decodeAll(ByteBuffer src) {
        return decodeAll(src, false);
    }

    /**
     * Decodes all remaining bytes in the specified <code>ByteBuffer</code>
     * as zero or more complete values and returns the list of values.
     *
     * @param src the source buffer containing the BER data
     * @param checkDer enable DER checking for the length octets at decode time
     * as well as the primitive content at primitive extraction/conversion time
     * @return the list of decoded values
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of any value being invalid or incomplete
     */
    public static List<Asn1BerValue> decodeAll(ByteBuffer src, boolean checkDer) {
        return decodeAll(src, checkDer, 0);
    }

    static List<Asn1BerValue> decodeAll(ByteBuffer src, boolean checkDer, int depth) {
        List<Asn1BerValue> values = new ArrayList<>();
        while (src.hasRemaining()) {
            Asn1BerValue value = new Asn1BerValue(src, checkDer, depth);
            if (value.endOfContents) {
                throw new Asn1DecodeException("Unexpected End-of-contents marker at offset " + value.offset);
            }
            values.add(value);
        }
        return Collections.unmodifiableList(values);
    }

    /**
     * Decodes zero or more values from the specified <code>ByteBuffer</code>
     * up to an end-of-contents marker at top level. End-of-contents markers
     * nested within constructed values do not cause premature termination.
     *
     * @param src the source buffer containing the BER data
     * @return the list of decoded values
     * @throws Asn1DecodeException if the decode operation fails due to the
     * encoding of any value being invalid or if the end-of-contents marker is
     * not encountered within the bytes remaining in the buffer
     */
    public static List<Asn1BerValue> decodeUntilMark(ByteBuffer src) {
        return decodeUntilMark(src, 0);
    }

    static List<Asn1BerValue> decodeUntilMark(ByteBuffer src, int depth) {
        List<Asn1BerValue> values = new ArrayList<>();
        for (;;) {
            Asn1BerValue value = new Asn1BerValue(src, false, depth);
            if (value.endOfContents) {
                return Collections.unmodifiableList(values);
            }
            values.add(value);
        }
    }

    /**
     * A utility method for converting an array of <code>Asn1BerValue</code>s
     * to a list of <code>Asn1BerValue</code>s while omitting <code>null</code>
     * values.
     *
     * @param values the array of values, possibly containing one or more nulls
     * @return the List of values with nulls omitted
     */
    public static List<Asn1BerValue> toListWithoutNulls(Asn1BerValue[] values) {
        List<Asn1BerValue> vl = new ArrayList<>(values.length);
        for (Asn1BerValue v : values) {
            if (v != null) {
                vl.add(v);
            }
        }
        return vl;
    }

    /**
     * Returns the UniversalTag that corresponds to the specified TagClass and
     * TagValue or <code>null</code> if there is no matching UniversalTag.
     *
     * @param tagClass the TagClass
     * @param tagValue the TagValue
     * @return the UniversalTag that corresponds to the specified TagClass and
     * TagValue or <code>null</code> if there is no matching UniversalTag
     */
    public static UniversalTag toUniversalTag(TagClass tagClass, int tagValue) {
        return tagClass != UNIVERSAL ? null : MAP_TO_UNIVERSAL.get(tagValue);
    }

    /**
     * Returns a String representation of the specified tag.
     *
     * @param tagClass the TagClass
     * @param tagValue the TagValue
     * @return the String representation
     */
    public static String tagToString(TagClass tagClass, int tagValue) {
        if (tagClass == null) {
            return "[null tag class]";
        }
        if (tagValue < 0) {
            return "[invalid tag value: " + tagValue + "]";
        }
        UniversalTag ut = toUniversalTag(tagClass, tagValue);
        if (ut != null) {
            return ut.asn1Name();
        }
        if (tagClass != CONTEXT_SPECIFIC) {
            return "[" + tagClass.name() + ' ' + tagValue + ']';
        }
        return "[" + tagValue + ']';
    }

    /**
     * Returns the Charset used to encode the specified Restricted Character
     * Set value.
     *
     * @param encoding the UniversalTag that identifies the RCS encoding
     * @return the Charset
     * @throws NullPointerException if the encoding parameter is
     * <code>null</code>
     * @throws Asn1Exception if the UniversalTag does not correspond to a
     * Restricted Character String encoding
     */
    static Charset getRcsCharset(UniversalTag encoding) {
        return switch (encoding) {
            case UTF8String -> StandardCharsets.UTF_8;
            case NumericString, PrintableString, TeletexString, T61String, VideotexString, IA5String, GraphicString,
                 VisibleString, ISO646String, GeneralString, GeneralizedTime, UTCTime -> StandardCharsets.US_ASCII;
            case UniversalString -> Charset.forName("UTF-32BE");
            case BMPString -> StandardCharsets.UTF_16BE;
            default -> throw new Asn1Exception("Not a Restricted Character String encoding: " + encoding.asn1Name());
        };
    }

    // Primitive values

    public static Asn1BerValue newBoolean(boolean b) {
        return newBoolean(UNIVERSAL, BOOLEAN.tagValue, b);
    }

    public static Asn1BerValue newInteger(long l) {
        return newInteger(UNIVERSAL, INTEGER.tagValue, l);
    }

    public static Asn1BerValue newInteger(BigInteger i) {
        return newInteger(UNIVERSAL, INTEGER.tagValue, i);
    }

    /**
     * Creates an Asn1BerValue INTEGER for an integer value specified as a byte array.
     *
     * @param octets a byte array containing a two's-complement representation of an integer value
     *               in big-endian byte-order: the most significant byte is in the zeroth element
     * @return an Asn1BerValue INTEGER repressing the integer
     */
    public static Asn1BerValue newInteger(byte[] octets) {
        return newInteger(UNIVERSAL, INTEGER.tagValue, octets);
    }

    public static Asn1BerValue newEnumerated(long e) {
        return newEnumerated(BigInteger.valueOf(e));
    }

    public static Asn1BerValue newEnumerated(BigInteger e) {
        return newEnumerated(UNIVERSAL, ENUMERATED.tagValue, e);
    }

    public static Asn1BerValue newBitString(byte[] octets) {
        return newBitString(UNIVERSAL, BIT_STRING.tagValue, octets);
    }

    public static Asn1BerValue newBitString(BitSet bitSet) {
        return newBitString(UNIVERSAL, BIT_STRING.tagValue, bitSet);
    }

    public static Asn1BerValue newOctetString(ByteBuffer buf) {
        return newOctetString(UNIVERSAL, OCTET_STRING.tagValue, buf);
    }

    public static Asn1BerValue newOctetString(byte[] octets) {
        return newOctetString(UNIVERSAL, OCTET_STRING.tagValue, octets);
    }

    public static Asn1BerValue newNull() {
        return newNull(UNIVERSAL, NULL.tagValue);
    }

    public static Asn1BerValue newOid(int... components) {
        return newOid(UNIVERSAL, OBJECT_IDENTIFIER.tagValue, components);
    }

    public static Asn1BerValue newOid(String oidStr) {
        return newOid(UNIVERSAL, OBJECT_IDENTIFIER.tagValue, oidStr);
    }

    public static Asn1BerValue newRelativeOid(int... components) {
        return newRelativeOid(UNIVERSAL, RELATIVE_OID.tagValue, components);
    }

    public static Asn1BerValue newRelativeOid(String oidStr) {
        return newRelativeOid(UNIVERSAL, RELATIVE_OID.tagValue, oidStr);
    }

    public static Asn1BerValue newRcsUTF8String(String str) {
        return newRcs(str, UTF8String);
    }

    public static Asn1BerValue newRcs(String str, UniversalTag encoding) {
        return newRcs(UNIVERSAL, encoding.tagValue, str, encoding);
    }

    public static Asn1BerValue newGeneralizedTime(OffsetDateTime dateTime) {
        return newGeneralizedTime(UNIVERSAL, GeneralizedTime.tagValue, dateTime);
    }

    public static Asn1BerValue newUtcTime(OffsetDateTime dateTime) {
        return newUtcTime(UNIVERSAL, UTCTime.tagValue, dateTime);
    }

    static void checkUniversalTag(TagClass tagClass, int tagValue, UniversalTag ut) {
        if (tagClass == UNIVERSAL && tagValue != ut.tagValue) {
            throw new Asn1Exception(
                "Invalid universal tag applied to " + ut.asn1Name() + ": " +
                tagToString(tagClass, tagValue));
        }
    }

    static Asn1BerValue newBoolean(TagClass tagClass, int tagValue, boolean b) {
        checkUniversalTag(tagClass, tagValue, BOOLEAN);
        return newPrimitive(tagClass, tagValue, b ? TRUE : FALSE);
    }

    static Asn1BerValue newInteger(TagClass tagClass, int tagValue, long l) {
        return newInteger(tagClass, tagValue, ByteBuffer.allocate(Long.BYTES).putLong(l).array());
    }

    static Asn1BerValue newInteger(TagClass tagClass, int tagValue, BigInteger i) {
        checkUniversalTag(tagClass, tagValue, INTEGER);
        return newPrimitive(tagClass, tagValue, i.toByteArray());
    }

    static Asn1BerValue newInteger(TagClass tagClass, int tagValue, byte[] octets) {
        checkUniversalTag(tagClass, tagValue, INTEGER);
        if (octets.length == 0) {
            throw new IllegalArgumentException("Integer content must contain at least one octet");
        }

        // Remove redundant leading (most-significant) octets with value 0x00 or 0xff, if any.
        int skip = countRedundantLeadingOctets(octets);
        return newPrimitive(tagClass, tagValue, ByteBuffer.wrap(octets, skip, octets.length - skip));
    }

    /**
     * Return the count of the number of redundant leading octets in the specified INTEGER content octets.
     *
     * <p>
     * Redundant leading octets are the leading (most-significant) octets that can be removed without
     * changing the numeric value of the INTEGER.  The content octet array encodes the value of an
     * INTEGER in two's complement, big endian form.  Both BER and DER encoding rules require that
     * INTEGERs are always encoded in the minimum number of octets.
     * </p>
     *
     * @param content the INTEGER content octets
     * @return the count of the number of redundant leading octets
     */
    static int countRedundantLeadingOctets(byte[] content) {
        if (content.length >= 2 && ((content[0] + 1) & 0xfe) == 0) {
            // The content has at least two octets and the first octet is either 0x00 or 0xff.
            int first = content[0];

            // Locate the next octet that doesn't match the first or, if all match, the final octet
            // (located at octets.length - 1).
            int index = 1;
            while (index < content.length - 1 && content[index] == first) {
                ++index;
            }

            // If the high bit still matches then all the preceding octets are redundant,
            // otherwise all but one are redundant.
            return (((first ^ content[index]) & 0x80) == 0) ? index : index - 1;
        }
        return 0;
    }

    static Asn1BerValue newEnumerated(TagClass tagClass, int tagValue, BigInteger e) {
        checkUniversalTag(tagClass, tagValue, ENUMERATED);
        return newPrimitive(tagClass, tagValue, e.toByteArray());
    }

    static Asn1BerValue newBitString(TagClass tagClass, int tagValue, byte[] octets) {
        checkUniversalTag(tagClass, tagValue, BIT_STRING);
        ByteBuffer content = ByteBuffer.allocate(octets.length + 1);
        content.put((byte)0).put(octets).rewind();
        return newPrimitive(tagClass, tagValue, content);
    }

    static Asn1BerValue newBitString(TagClass tagClass, int tagValue, BitSet bitSet) {
        checkUniversalTag(tagClass, tagValue, BIT_STRING);
        byte[] bytes = bitSet.toByteArray();
        ByteBuffer content = ByteBuffer.allocate(bytes.length + 1);
        int unusedBits = bytes.length * 8 - bitSet.length();
        content.put((byte)unusedBits);
        for (byte aByte : bytes) {
            content.put((byte) (Integer.reverse(aByte) >>> 24));
        }
        content.rewind();
        return newPrimitive(tagClass, tagValue, content);
    }

    static Asn1BerValue newOctetString(TagClass tagClass, int tagValue, ByteBuffer buf) {
        checkUniversalTag(tagClass, tagValue, OCTET_STRING);
        return newPrimitive(tagClass, tagValue, buf);
    }

    static Asn1BerValue newOctetString(TagClass tagClass, int tagValue, byte[] octets) {
        checkUniversalTag(tagClass, tagValue, OCTET_STRING);
        return newPrimitive(tagClass, tagValue, octets);
    }

    public static Asn1BerValue newNull(TagClass tagClass, int tagValue) {
        checkUniversalTag(tagClass, tagValue, NULL);
        return newPrimitive(tagClass, tagValue, new byte[0]);
    }

    static int countIdentifierOctets(int id) {
        int bitCount = 32 - Integer.numberOfLeadingZeros(id);
        return Math.max(1, (bitCount + 6) / 7);
    }

    static int countOidSubIdentifierOctets(int[] subIds, int offset) {
        int octetCount = 0;
        for (int i = offset; i < subIds.length; ++i) {
            if (subIds[i] < 0) {
                throw new IllegalArgumentException("Invalid OID component: " + subIds[i]);
            }
            octetCount += countIdentifierOctets(subIds[i]);
        }
        return octetCount;
    }

    static void encodeIdentifier(ByteBuffer dst, int id) {
        int octetCount = countIdentifierOctets(id);
        for (int shift = (octetCount - 1) * 7; shift > 0; shift -= 7) {
            dst.put((byte)((id >>> shift) | 0x80));
        }
        dst.put((byte)(id & 0x7f));
    }

    static void encodeOidSubIdentifiers(ByteBuffer dst, int[] subIds, int offset) {
        for (int i = offset; i < subIds.length; ++i) {
            encodeIdentifier(dst, subIds[i]);
        }
    }

    static Asn1BerValue newOid(TagClass tagClass, int tagValue, int[] components) {
        checkUniversalTag(tagClass, tagValue, OBJECT_IDENTIFIER);
        if (components.length < 2) {
            throw new IllegalArgumentException("Insufficient OID components");
        }
        int c0 = components[0];
        int c1 = components[1];
        int subId0 = c0 * 40 + c1;
        if (c0 < 0 || c1 < 0 || c0 > 2 || (c0 < 2 && c1 >= 40) || subId0 < 0) {
            throw new IllegalArgumentException("Invalid OID component: " + Arrays.toString(components));
        }
        int len = countIdentifierOctets(subId0) + countOidSubIdentifierOctets(components, 2);
        ByteBuffer content = ByteBuffer.allocate(len);
        encodeIdentifier(content, subId0);
        encodeOidSubIdentifiers(content, components, 2);
        content.rewind();
        return newPrimitiveValue(tagClass, tagValue, content);
    }

    static int[] splitToInts(String oidStr) {
        String[] sComponents = oidStr.split("\\.");
        int[] components = new int[sComponents.length];
        for (int i = 0; i < components.length; ++i) {
            components[i] = Integer.parseInt(sComponents[i]);
        }
        return components;
    }

    static Asn1BerValue newOid(TagClass tagClass, int tagValue, String oidStr) {
        return newOid(tagClass, tagValue, splitToInts(oidStr));
    }

    static Asn1BerValue newRelativeOid(TagClass tagClass, int tagValue, int[] components) {
        checkUniversalTag(tagClass, tagValue, RELATIVE_OID);
        int len = countOidSubIdentifierOctets(components, 0);
        ByteBuffer content = ByteBuffer.allocate(len);
        encodeOidSubIdentifiers(content, components, 0);
        content.rewind();
        return newPrimitiveValue(tagClass, tagValue, content);
    }

    static Asn1BerValue newRelativeOid(TagClass tagClass, int tagValue, String oidStr) {
        return newRelativeOid(tagClass, tagValue, splitToInts(oidStr));
    }

    static Asn1BerValue newRcs(TagClass tagClass, int tagValue, String str, UniversalTag encoding) {
        Charset charset = getRcsCharset(encoding);
        checkUniversalTag(tagClass, tagValue, encoding);
        return newPrimitive(tagClass, tagValue, str.getBytes(charset));
    }

    static Asn1BerValue newGeneralizedTime(TagClass tagClass, int tagValue, OffsetDateTime dateTime) {
        checkUniversalTag(tagClass, tagValue, GeneralizedTime);
        OffsetDateTime utcDateTime = dateTime.withOffsetSameInstant(ZoneOffset.UTC);
        DateTimeFormatter dtf = utcDateTime.getNano() != 0 ?
                GENERALIZED_TIME_FRACTIONAL_FORMATTER : GENERALIZED_TIME_FORMATTER;
        String formattedDateTime = dtf.format(utcDateTime);
        return newPrimitive(tagClass, tagValue, formattedDateTime.getBytes(StandardCharsets.US_ASCII));
    }

    static Asn1BerValue newUtcTime(TagClass tagClass, int tagValue, OffsetDateTime dateTime) {
        checkUniversalTag(tagClass, tagValue, UTCTime);
        OffsetDateTime utcDateTime = dateTime.withOffsetSameInstant(ZoneOffset.UTC);
        String formattedDateTime = UTC_TIME_FORMATTER.format(utcDateTime);
        return newPrimitive(tagClass, tagValue, formattedDateTime.getBytes(StandardCharsets.US_ASCII));
    }

    static Asn1BerValue newPrimitive(TagClass tagClass, int tagValue, ByteBuffer content) {
        return newPrimitiveValue(tagClass, tagValue, content.slice());
    }

    static Asn1BerValue newPrimitive(TagClass tagClass, int tagValue, byte[] content) {
        return newPrimitiveValue(tagClass, tagValue, ByteBuffer.wrap(content));
    }

    static Asn1BerValue newPrimitiveValue(TagClass tagClass, int tagValue, ByteBuffer content) {
        if (tagClass == UNIVERSAL && (tagValue == SET.tagValue || tagValue == SEQUENCE.tagValue)) {
            throw new Asn1Exception("Invalid universal tag applied to primitive: " + tagToString(tagClass, tagValue));
        }
        return new Asn1BerValue(tagClass, tagValue, false, null, content.asReadOnlyBuffer(), null);
    }

    // Constructed values

    public static Asn1BerValue newSequence(Asn1BerValue... values) {
        return newSequence(toListWithoutNulls(values));
    }

    public static Asn1BerValue newSet(Asn1BerValue... values) {
        return newSet(toListWithoutNulls(values));
    }

    public static Asn1BerValue newSetOf(Asn1BerValue... values) {
        return newSetOf(toListWithoutNulls(values));
    }

    public static Asn1BerValue newSequence(List<Asn1BerValue> values) {
        return newSequence(UNIVERSAL, SEQUENCE.tagValue, values);
    }

    public static Asn1BerValue newSet(List<Asn1BerValue> values) {
        return newSet(UNIVERSAL, SET.tagValue, values, SortOrder.SET);
    }

    public static Asn1BerValue newSetOf(List<Asn1BerValue> values) {
        return newSet(UNIVERSAL, SET.tagValue, values, SortOrder.SET_OF);
    }

    public static Asn1BerValue newExplicitTag(int csTag, Asn1BerValue value) {
        return newExplicitTag(CONTEXT_SPECIFIC, csTag, value);
    }

    static Asn1BerValue newSequence(TagClass tagClass, int tagValue, List<Asn1BerValue> values) {
        checkUniversalTag(tagClass, tagValue, SEQUENCE);
        return newConstructedValue(tagClass, tagValue, Collections.unmodifiableList(values), SortOrder.SEQUENCE);
    }

    static Asn1BerValue newSet(TagClass tagClass, int tagValue, List<Asn1BerValue> values, SortOrder sortOrder) {
        checkUniversalTag(tagClass, tagValue, SET);
        return newConstructedValue(tagClass, tagValue, Collections.unmodifiableList(values), sortOrder);
    }

    public static Asn1BerValue newExplicitTag(TagClass tagClass, int tagValue, Asn1BerValue value) {
        if (tagClass == UNIVERSAL) {
            throw new Asn1Exception(
                "Invalid universal explicit tag: " +
                tagToString(tagClass, tagValue));
        }
        return newConstructedValue(tagClass, tagValue, Collections.singletonList(value), SortOrder.SEQUENCE);
    }

    static Asn1BerValue newConstructedValue(TagClass tagClass, int tagValue, List<Asn1BerValue> values, SortOrder sortOrder) {
        return new Asn1BerValue(tagClass, tagValue, true, sortOrder, null, values);
    }

    // ImplicitTagValueFactory for applying an implicit tag

    public static ImplicitTagValueFactory implicit(int csTag) {
        return implicit(csTag, null);
    }

    public static ImplicitTagValueFactory implicit(UniversalTag universalTag) {
        return implicit(universalTag, null);
    }

    public static ImplicitTagValueFactory implicit(TagClass tagClass, int tagValue) {
        return implicit(tagClass, tagValue, null);
    }

    static ImplicitTagValueFactory implicit(int csTag, ExplicitTagValueFactory tagWrapper) {
        return implicit(CONTEXT_SPECIFIC, csTag, tagWrapper);
    }

    static ImplicitTagValueFactory implicit(UniversalTag universalTag, ExplicitTagValueFactory tagWrapper) {
        return implicit(UNIVERSAL, universalTag.tagValue, tagWrapper);
    }

    static ImplicitTagValueFactory implicit(TagClass tagClass, int tagValue, ExplicitTagValueFactory tagWrapper) {
        Objects.requireNonNull(tagClass, "tagClass must not be null");
        if (tagValue < 0) {
            throw new IllegalArgumentException("Invalid tag value (negative)");
        }
        return new ImplicitTagValueFactory(tagClass, tagValue, tagWrapper);
    }

    public static final class ImplicitTagValueFactory implements ValueFactory {
        private final TagClass tagClass;
        private final int tagValue;
        private final ExplicitTagValueFactory tagWrapper;

        ImplicitTagValueFactory(TagClass tagClass, int tagValue, ExplicitTagValueFactory tagWrapper) {
            this.tagClass = tagClass;
            this.tagValue = tagValue;
            this.tagWrapper = tagWrapper;
        }

        Asn1BerValue applyExplicit(Asn1BerValue value) {
            return this.tagWrapper != null ? this.tagWrapper.applyExplicit(value) : value;
        }

        @Override
        public Asn1BerValue newBoolean(boolean b) {
            return applyExplicit(Asn1.newBoolean(this.tagClass, this.tagValue, b));
        }

        @Override
        public Asn1BerValue newInteger(long l) {
            return applyExplicit(Asn1.newInteger(this.tagClass, this.tagValue, l));
        }

        @Override
        public Asn1BerValue newInteger(BigInteger i) {
            return applyExplicit(Asn1.newInteger(this.tagClass, this.tagValue, i));
        }

        @Override
        public Asn1BerValue newInteger(byte[] octets) {
            return applyExplicit(Asn1.newInteger(this.tagClass, this.tagValue, octets));
        }

        @Override
        public Asn1BerValue newEnumerated(long e) {
            return applyExplicit(Asn1.newEnumerated(this.tagClass, this.tagValue, BigInteger.valueOf(e)));
        }

        @Override
        public Asn1BerValue newEnumerated(BigInteger e) {
            return applyExplicit(Asn1.newEnumerated(this.tagClass, this.tagValue, e));
        }

        @Override
        public Asn1BerValue newBitString(byte[] octets) {
            return applyExplicit(Asn1.newBitString(this.tagClass, this.tagValue, octets));
        }

        @Override
        public Asn1BerValue newBitString(BitSet bitSet) {
            return applyExplicit(Asn1.newBitString(this.tagClass, this.tagValue, bitSet));
        }

        @Override
        public Asn1BerValue newOctetString(ByteBuffer buf) {
            return applyExplicit(Asn1.newOctetString(this.tagClass, this.tagValue, buf));
        }

        @Override
        public Asn1BerValue newOctetString(byte[] octets) {
            return applyExplicit(Asn1.newOctetString(this.tagClass, this.tagValue, octets));
        }

        @Override
        public Asn1BerValue newNull() {
            return applyExplicit(Asn1.newNull(this.tagClass, this.tagValue));
        }

        @Override
        public Asn1BerValue newOid(int... components) {
            return applyExplicit(Asn1.newOid(this.tagClass, this.tagValue, components));
        }

        @Override
        public Asn1BerValue newOid(String oidStr) {
            return applyExplicit(Asn1.newOid(this.tagClass, this.tagValue, oidStr));
        }

        @Override
        public Asn1BerValue newRelativeOid(int... components) {
            return applyExplicit(Asn1.newRelativeOid(this.tagClass, this.tagValue, components));
        }

        @Override
        public Asn1BerValue newRelativeOid(String oidStr) {
            return applyExplicit(Asn1.newRelativeOid(this.tagClass, this.tagValue, oidStr));
        }

        public Asn1BerValue newRcs(String str) {
            UniversalTag encoding = toUniversalTag(this.tagClass, this.tagValue);
            if (encoding == null) {
                throw new Asn1Exception("Unknown RCS encoding for tag: " + tagToString(this.tagClass, this.tagValue));
            }
            return applyExplicit(Asn1.newRcs(this.tagClass, this.tagValue, str, encoding));
        }

        @Override
        public Asn1BerValue newRcsUTF8String(String str) {
            return applyExplicit(Asn1.newRcs(this.tagClass, this.tagValue, str, UTF8String));
        }

        @Override
        public Asn1BerValue newRcs(String str, UniversalTag encoding) {
            return applyExplicit(Asn1.newRcs(this.tagClass, this.tagValue, str, encoding));
        }

        @Override
        public Asn1BerValue newGeneralizedTime(OffsetDateTime dateTime) {
            return applyExplicit(Asn1.newGeneralizedTime(this.tagClass, this.tagValue, dateTime));
        }

        @Override
        public Asn1BerValue newUtcTime(OffsetDateTime dateTime) {
            return applyExplicit(Asn1.newUtcTime(this.tagClass, this.tagValue, dateTime));
        }

        public Asn1BerValue newPrimitive(ByteBuffer content) {
            return applyExplicit(Asn1.newPrimitive(this.tagClass, this.tagValue, content));
        }

        public Asn1BerValue newPrimitive(byte[] content) {
            return applyExplicit(Asn1.newPrimitive(this.tagClass, this.tagValue, content));
        }

        @Override
        public Asn1BerValue newSequence(Asn1BerValue... values) {
            return newSequence(toListWithoutNulls(values));
        }

        @Override
        public Asn1BerValue newSet(Asn1BerValue... values) {
            return newSet(toListWithoutNulls(values));
        }

        @Override
        public Asn1BerValue newSetOf(Asn1BerValue... values) {
            return newSetOf(toListWithoutNulls(values));
        }

        @Override
        public Asn1BerValue newSequence(List<Asn1BerValue> values) {
            return applyExplicit(Asn1.newSequence(this.tagClass, this.tagValue, values));
        }

        @Override
        public Asn1BerValue newSet(List<Asn1BerValue> values) {
            return applyExplicit(Asn1.newSet(this.tagClass, this.tagValue, values, SortOrder.SET));
        }

        @Override
        public Asn1BerValue newSetOf(List<Asn1BerValue> values) {
            return applyExplicit(Asn1.newSet(this.tagClass, this.tagValue, values, SortOrder.SET_OF));
        }
    }

    // ExplicitTagValueFactory for applying an explicit tag

    public static ExplicitTagValueFactory explicit(int csTag) {
        return explicit(csTag, null);
    }

    public static ExplicitTagValueFactory explicit(TagClass tagClass, int tagValue) {
        return explicit(tagClass, tagValue, null);
    }

    static ExplicitTagValueFactory explicit(int csTag, ExplicitTagValueFactory tagWrapper) {
        return explicit(CONTEXT_SPECIFIC, csTag, tagWrapper);
    }

    static ExplicitTagValueFactory explicit(TagClass tagClass, int tagValue, ExplicitTagValueFactory tagWrapper) {
        Objects.requireNonNull(tagClass, "tagClass must not be null");
        if (tagValue < 0) {
            throw new IllegalArgumentException("Invalid tag value (negative)");
        }
        return new ExplicitTagValueFactory(tagClass, tagValue, tagWrapper);
    }

    public static final class ExplicitTagValueFactory implements ValueFactory {
        private final TagClass tagClass;
        private final int tagValue;
        private final ExplicitTagValueFactory tagWrapper;

        ExplicitTagValueFactory(TagClass tagClass, int tagValue, ExplicitTagValueFactory tagWrapper) {
            this.tagClass = tagClass;
            this.tagValue = tagValue;
            this.tagWrapper = tagWrapper;
        }

        Asn1BerValue applyExplicit(Asn1BerValue value) {
            Asn1BerValue et = Asn1.newExplicitTag(this.tagClass, this.tagValue, value);
            return this.tagWrapper != null ? this.tagWrapper.applyExplicit(et) : et;
        }

        @Override
        public Asn1BerValue newBoolean(boolean b) {
            return applyExplicit(Asn1.newBoolean(b));
        }

        @Override
        public Asn1BerValue newInteger(long l) {
            return applyExplicit(Asn1.newInteger(l));
        }

        @Override
        public Asn1BerValue newInteger(BigInteger i) {
            return applyExplicit(Asn1.newInteger(i));
        }

        @Override
        public Asn1BerValue newInteger(byte[] octets) {
            return applyExplicit(Asn1.newInteger(octets));
        }

        @Override
        public Asn1BerValue newEnumerated(long e) {
            return applyExplicit(Asn1.newEnumerated(e));
        }

        @Override
        public Asn1BerValue newEnumerated(BigInteger e) {
            return applyExplicit(Asn1.newEnumerated(e));
        }

        @Override
        public Asn1BerValue newBitString(byte[] octets) {
            return applyExplicit(Asn1.newBitString(octets));
        }

        @Override
        public Asn1BerValue newBitString(BitSet bitSet) {
            return applyExplicit(Asn1.newBitString(bitSet));
        }

        @Override
        public Asn1BerValue newOctetString(ByteBuffer buf) {
            return applyExplicit(Asn1.newOctetString(buf));
        }

        @Override
        public Asn1BerValue newOctetString(byte[] octets) {
            return applyExplicit(Asn1.newOctetString(octets));
        }

        @Override
        public Asn1BerValue newNull() {
            return applyExplicit(Asn1.newNull());
        }

        @Override
        public Asn1BerValue newOid(int... components) {
            return applyExplicit(Asn1.newOid(components));
        }

        @Override
        public Asn1BerValue newOid(String oidStr) {
            return applyExplicit(Asn1.newOid(oidStr));
        }

        @Override
        public Asn1BerValue newRelativeOid(int... components) {
            return applyExplicit(Asn1.newRelativeOid(components));
        }

        @Override
        public Asn1BerValue newRelativeOid(String oidStr) {
            return applyExplicit(Asn1.newRelativeOid(oidStr));
        }

        @Override
        public Asn1BerValue newRcsUTF8String(String str) {
            return applyExplicit(Asn1.newRcs(str, UTF8String));
        }

        @Override
        public Asn1BerValue newRcs(String str, UniversalTag encoding) {
            return applyExplicit(Asn1.newRcs(str, encoding));
        }

        @Override
        public Asn1BerValue newSequence(Asn1BerValue... values) {
            return applyExplicit(Asn1.newSequence(values));
        }

        @Override
        public Asn1BerValue newSet(Asn1BerValue... values) {
            return applyExplicit(Asn1.newSet(values));
        }

        @Override
        public Asn1BerValue newSetOf(Asn1BerValue... values) {
            return applyExplicit(Asn1.newSetOf(values));
        }

        @Override
        public Asn1BerValue newSequence(List<Asn1BerValue> values) {
            return applyExplicit(Asn1.newSequence(values));
        }

        @Override
        public Asn1BerValue newSet(List<Asn1BerValue> values) {
            return applyExplicit(Asn1.newSet(values));
        }

        @Override
        public Asn1BerValue newSetOf(List<Asn1BerValue> values) {
            return applyExplicit(Asn1.newSetOf(values));
        }

        @Override
        public Asn1BerValue newUtcTime(OffsetDateTime dateTime) {
            return applyExplicit(Asn1.newUtcTime(dateTime));
        }

        @Override
        public Asn1BerValue newGeneralizedTime(OffsetDateTime dateTime) {
            return applyExplicit(Asn1.newGeneralizedTime(dateTime));
        }

        public ImplicitTagValueFactory implicit(int csTag) {
            return Asn1.implicit(csTag, this);
        }

        public ImplicitTagValueFactory implicit(UniversalTag universalTag) {
            return Asn1.implicit(universalTag, this);
        }

        public ImplicitTagValueFactory implicit(TagClass tagClass, int tagValue) {
            return Asn1.implicit(tagClass, tagValue, this);
        }

        public ExplicitTagValueFactory explicit(int csTag) {
            return Asn1.explicit(csTag, this);
        }

        public ExplicitTagValueFactory explicit(TagClass tagClass, int tagValue) {
            return Asn1.explicit(tagClass, tagValue, this);
        }
    }

    interface ValueFactory {
        Asn1BerValue newBoolean(boolean b);
        Asn1BerValue newInteger(long l);
        Asn1BerValue newInteger(BigInteger i);
        Asn1BerValue newInteger(byte[] octets);
        Asn1BerValue newEnumerated(long e);
        Asn1BerValue newEnumerated(BigInteger e);
        Asn1BerValue newBitString(byte[] octets);
        Asn1BerValue newBitString(BitSet bitSet);
        Asn1BerValue newOctetString(ByteBuffer buf);
        Asn1BerValue newOctetString(byte[] octets);
        Asn1BerValue newNull();
        Asn1BerValue newOid(int... components);
        Asn1BerValue newOid(String oidStr);
        Asn1BerValue newRelativeOid(int... components);
        Asn1BerValue newRelativeOid(String oidStr);
        Asn1BerValue newRcsUTF8String(String str);
        Asn1BerValue newRcs(String str, UniversalTag encoding);
        Asn1BerValue newGeneralizedTime(OffsetDateTime dateTime);
        Asn1BerValue newUtcTime(OffsetDateTime dateTime);
        Asn1BerValue newSequence(Asn1BerValue... values);
        Asn1BerValue newSet(Asn1BerValue... values);
        Asn1BerValue newSetOf(Asn1BerValue... values);
        Asn1BerValue newSequence(List<Asn1BerValue> values);
        Asn1BerValue newSet(List<Asn1BerValue> values);
        Asn1BerValue newSetOf(List<Asn1BerValue> values);
    }

}
