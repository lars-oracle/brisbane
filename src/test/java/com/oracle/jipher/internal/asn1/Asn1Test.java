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
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.Month;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.BitSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;

import com.oracle.jiphertest.util.TestUtil;

import static com.oracle.jipher.internal.asn1.Asn1.explicit;
import static com.oracle.jipher.internal.asn1.Asn1.implicit;
import static com.oracle.jipher.internal.asn1.Asn1.newBitString;
import static com.oracle.jipher.internal.asn1.Asn1.newBoolean;
import static com.oracle.jipher.internal.asn1.Asn1.newEnumerated;
import static com.oracle.jipher.internal.asn1.Asn1.newExplicitTag;
import static com.oracle.jipher.internal.asn1.Asn1.newGeneralizedTime;
import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newNull;
import static com.oracle.jipher.internal.asn1.Asn1.newOctetString;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newRcs;
import static com.oracle.jipher.internal.asn1.Asn1.newRcsUTF8String;
import static com.oracle.jipher.internal.asn1.Asn1.newRelativeOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.asn1.Asn1.newSet;
import static com.oracle.jipher.internal.asn1.Asn1.newSetOf;
import static com.oracle.jipher.internal.asn1.Asn1.newUtcTime;
import static com.oracle.jipher.internal.asn1.TagClass.APPLICATION;
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
import static com.oracle.jipher.internal.asn1.UniversalTag.PrintableString;
import static com.oracle.jipher.internal.asn1.UniversalTag.RELATIVE_OID;
import static com.oracle.jipher.internal.asn1.UniversalTag.SEQUENCE;
import static com.oracle.jipher.internal.asn1.UniversalTag.SET;
import static com.oracle.jipher.internal.asn1.UniversalTag.UTCTime;
import static com.oracle.jipher.internal.asn1.UniversalTag.UTF8String;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class Asn1Test {

    static final byte[] B1 = TestUtil.hexStringToByteArray("12345678deadbeef");
    static final byte[] NON_BER_M42 = TestUtil.hexStringToByteArray("ffffffd6");
    static final byte[] M42 = TestUtil.hexStringToByteArray("d6");
    static final byte[] NON_BER_M155 = TestUtil.hexStringToByteArray("ffffff65");
    static final byte[] M155 = TestUtil.hexStringToByteArray("ff65");
    static final byte[] NON_BER_N = TestUtil.hexStringToByteArray("00499602D2"); // 1234567890
    static final byte[] N = TestUtil.hexStringToByteArray("499602D2"); // 1234567890
    static final OffsetDateTime DATE_TIME = OffsetDateTime.of(LocalDateTime.of(
            1985, Month.NOVEMBER, 6,
            21, 6, 27), ZoneOffset.UTC);

    // Bits {2, 3, 5, 7, 11, 13}
    static final byte[] BITSTR = TestUtil.hexStringToByteArray("3514");
    static final byte[] BITSTRCONT = TestUtil.hexStringToByteArray("023514");
    static final BitSet BITSET = new BitSet(14);

    static {
        BITSET.set(2);
        BITSET.set(3);
        BITSET.set(5);
        BITSET.set(7);
        BITSET.set(11);
        BITSET.set(13);
    }

    static final Asn1BerValue TEST_SEQUENCE = newSequenceValue();
    static final int TEST_SEQUENCE_SIZE = TEST_SEQUENCE.values().size(); //contentValues
    static final int TEST_SEQUENCE_LEN = TEST_SEQUENCE.encodedLength();

    // Utility functions for tests

    static Asn1BerValue newSequenceValue() {
        Asn1BerValue seq = newSequence(
                newBoolean(true),
                newInteger(-42),
                newInteger(new BigInteger("1234567890")),
                newInteger(M155),
                newBitString(BITSET),
                null, // Ignored
                newOctetString(B1.clone()),
                newNull(),
                newRcsUTF8String("A String"),
                newRcs("Another String", PrintableString),
                newOid("1.2.840.113549.1.1.1"),
                newRelativeOid(113549, 1, 1, 1),
                newEnumerated(4),
                newGeneralizedTime(DATE_TIME),
                newUtcTime(DATE_TIME)
        );
        return seq;
    }

    // Applying these implicit tags has no effect since these are
    // the same universal tags that would be present anyway.
    static Asn1BerValue newSequenceValueUniversalTags() {
        Asn1BerValue seq = newSequence(
                implicit(BOOLEAN).newBoolean(true),
                implicit(INTEGER).newInteger(-42),
                implicit(INTEGER).newInteger(new BigInteger("1234567890")),
                implicit(INTEGER).newInteger(M155),
                implicit(BIT_STRING).newBitString(BITSET),
                implicit(OCTET_STRING).newOctetString(B1.clone()),
                implicit(NULL).newNull(),
                implicit(UTF8String).newRcsUTF8String("A String"),
                implicit(PrintableString).newRcs("Another String", PrintableString),
                implicit(OBJECT_IDENTIFIER).newOid("1.2.840.113549.1.1.1"),
                implicit(RELATIVE_OID).newRelativeOid(113549, 1, 1, 1),
                implicit(ENUMERATED).newEnumerated(4),
                implicit(GeneralizedTime).newGeneralizedTime(DATE_TIME),
                implicit(UTCTime).newUtcTime(DATE_TIME)
        );
        return seq;
    }

    static Asn1BerValue newSequenceValueCsTags() {
        Asn1BerValue seq = implicit(42).newSequence(
                implicit(1).newBoolean(true),
                implicit(2).newInteger(-42),
                implicit(3).newInteger(new BigInteger("1234567890")),
                implicit(4).newInteger(M155),
                implicit(5).newBitString(BITSET),
                implicit(6).newOctetString(B1.clone()),
                implicit(7).newNull(),
                implicit(8).newRcsUTF8String("A String"),
                implicit(9).newRcs("Another String", PrintableString),
                implicit(10).newOid("1.2.840.113549.1.1.1"),
                implicit(11).newRelativeOid("113549.1.1.1"),
                implicit(12).newEnumerated(4),
                null, // Ignored
                implicit(13).newGeneralizedTime(DATE_TIME),
                implicit(14).newUtcTime(DATE_TIME)
        );
        return seq;
    }

    static Asn1BerValue newImplicitTagSequenceValue() {
        Asn1BerValue seq = implicit(123).newSequence(
                newBoolean(true),
                null, // Ignored
                newInteger(-42),
                newInteger(new BigInteger("1234567890")),
                newInteger(M155),
                newBitString(BITSET),
                newOctetString(B1.clone()),
                newNull(),
                newRcsUTF8String("A String"),
                newRcs("Another String", PrintableString),
                newOid("1.2.840.113549.1.1.1"),
                newRelativeOid(113549, 1, 1, 1),
                newEnumerated(4),
                newGeneralizedTime(DATE_TIME),
                newUtcTime(DATE_TIME)
        );
        return seq;
    }

    static Asn1BerValue newExplicitTagSequenceValue() {
        Asn1BerValue seq = newExplicitTag(APPLICATION, 456, newSequenceValue());
        return seq;
    }

    static Asn1BerValue newSequenceValueNonDerBoolean() {
        Asn1BerValue seq = newSequence(
                implicit(BOOLEAN).newPrimitive(new byte[]{0x22}),
                newInteger(-42),
                newInteger(new BigInteger("1234567890")),
                newInteger(M155),
                newBitString(BITSET),
                newOctetString(B1.clone()),
                newNull(),
                newRcsUTF8String("A String"),
                newRcs("Another String", PrintableString),
                newOid("1.2.840.113549.1.1.1"),
                newRelativeOid(113549, 1, 1, 1),
                newEnumerated(4),
                newGeneralizedTime(DATE_TIME),
                newUtcTime(DATE_TIME)
        );
        return seq;
    }

    static void checkSequenceValue(Asn1BerValue seq) {
        checkSequenceValue(seq, false);
    }

    static void checkSequenceValue(Asn1BerValue seq, boolean csTags) {
        if (csTags) {
            seq = seq.tagClassDeep(CONTEXT_SPECIFIC).tag(42);
        }
        List<Asn1BerValue> values = seq.count(TEST_SEQUENCE_SIZE).sequence();
        checkSubValues(values, csTags);
    }

    static void checkSubValues(List<Asn1BerValue> values, boolean csTags) {
        if (csTags) {
            List<Asn1BerValue> origValues = values;
            // Assert that all the sub-values have the correct CS tag.
            values = IntStream.range(0, values.size())
                    .mapToObj(i -> origValues.get(i).tag(i + 1))
                    .collect(Collectors.toList());
        }
        assertEquals(TEST_SEQUENCE_SIZE, values.size());
        assertTrue(values.get(0).getBoolean());
        assertEquals(-42, values.get(1).getInteger().intValue());
        assertArrayEquals(M42, values.get(1).getIntegerOctets());
        assertEquals(new BigInteger("1234567890"), values.get(2).getInteger());
        assertArrayEquals(N, values.get(2).getIntegerOctets());
        assertEquals(-155, values.get(3).getInteger().intValue());
        assertArrayEquals(M155, values.get(3).getIntegerOctets());
        assertEquals(BITSET, values.get(4).getBitString());
        assertArrayEquals(BITSTR, values.get(4).getBitStringOctets());
        assertArrayEquals(BITSTRCONT, values.get(4).getBitStringContent().array());
        assertArrayEquals(B1, values.get(5).getOctetString());
        values.get(6).getNull();
        assertEquals("A String", values.get(7).getRcs(UTF8String));
        assertEquals("Another String", values.get(8).getRcs(PrintableString));
        assertEquals("1.2.840.113549.1.1.1", values.get(9).getOid());
        assertEquals("113549.1.1.1", values.get(10).getRelativeOid());
        assertEquals(BigInteger.valueOf(4), values.get(11).getEnumerated());
        assertEquals(DATE_TIME, values.get(12).getGeneralizedTime());
        assertEquals(DATE_TIME, values.get(13).getUtcTime());
    }

    static ByteBuffer indefLenSeq() {
        // Add an end-off-contents marker (two zero octets) at the end.
        ByteBuffer encoded = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 2);
        TEST_SEQUENCE.encodeDer(encoded);
        encoded.rewind();
        encoded.put(1, (byte) 0x80); // Indefinite Length
        return encoded;
    }

    static Asn1BerValue encodeDecode(Asn1BerValue val) {
        return Asn1.decodeOne(val.encodeDer());
    }

    static Asn1BerValue changeId(Asn1BerValue val, int id) {
        ByteBuffer encoded = val.encodeDer();
        encoded.put(0, (byte) id);
        return Asn1.decodeOne(encoded);
    }

    // Tests

    @Test
    public void equalsAndHashCode() {
        Asn1BerValue seq = TEST_SEQUENCE;
        // Verify tag
        seq.tag(SEQUENCE);
        checkSequenceValue(seq);
        Asn1BerValue other = newSequenceValue();
        assertEquals(seq.hashCode(), other.hashCode());
        assertEquals(seq, other);
    }

    @Test
    public void encodeSeqAndDecode() {
        Asn1BerValue seq = TEST_SEQUENCE;
        Asn1BerValue decodedSeq = encodeDecode(seq).der();
        // Verify tag
        assertTrue(decodedSeq.hasTag(SEQUENCE));
        assertTrue(decodedSeq.hasTagClass(UNIVERSAL));
        assertTrue(decodedSeq.hasTagClassDeep(UNIVERSAL));
        decodedSeq.tag(SEQUENCE).tagClass(UNIVERSAL).tagClassDeep(UNIVERSAL);
        checkSequenceValue(decodedSeq);
        assertEquals(seq.hashCode(), decodedSeq.hashCode());
        assertEquals(decodedSeq, seq);
    }

    @Test
    public void decodeOneByteArray() {
        byte[] bytes = TEST_SEQUENCE.encodeDerOctets();
        Asn1BerValue val = Asn1.decodeOne(bytes);
        checkSequenceValue(val);
    }

    @Test
    public void decodeAll() {
        ByteBuffer encoded = TEST_SEQUENCE.encodeDer();
        // Skip Id and Len octets of SEQUENCE
        encoded.position(2);
        List<Asn1BerValue> values = Asn1.decodeAll(encoded);
        checkSubValues(values, false);
    }

    @Test
    public void decodeUntilMark() {
        ByteBuffer encoded = indefLenSeq();
        encoded.position(2); // Skip identifier and length octets
        List<Asn1BerValue> values = Asn1.decodeUntilMark(encoded);
        checkSubValues(values, false);
    }

    @Test
    public void encodeIntegerAndDecode1() {
        Asn1BerValue val = newInteger(NON_BER_M42);
        Asn1BerValue decodedVal = encodeDecode(val);
        assertArrayEquals(M42, decodedVal.getIntegerOctets());
        assertEquals(-42, decodedVal.getInteger().intValueExact());
    }

    @Test
    public void encodeIntegerAndDecode2() {
        Asn1BerValue val = newInteger(NON_BER_M155);
        Asn1BerValue decodedVal = encodeDecode(val);
        assertArrayEquals(M155, decodedVal.getIntegerOctets());
        assertEquals(-155, decodedVal.getInteger().intValueExact());
    }

    @Test
    public void encodeIntegerAndDecode3() {
        Asn1BerValue val = newInteger(NON_BER_N);
        Asn1BerValue decodedVal = encodeDecode(val);
        assertArrayEquals(N, decodedVal.getIntegerOctets());
        assertEquals(new BigInteger("1234567890"), decodedVal.getInteger());
    }

    @Test
    public void encodeOidAndDecode() {
        int[] components = {2, 1, Integer.MAX_VALUE, Integer.MAX_VALUE};
        Asn1BerValue val = newOid(components);
        Asn1BerValue decodedVal = encodeDecode(val).der();
        // Verify tag
        decodedVal.tag(OBJECT_IDENTIFIER);
        assertArrayEquals(components, decodedVal.getOidComponents());
    }

    @Test
    public void encodeRelativeOidAndDecode1() {
        Asn1BerValue val = newRelativeOid(0, 88, 32);
        Asn1BerValue decodedVal = encodeDecode(val).der();
        // Verify tag
        decodedVal.tag(RELATIVE_OID);
        assertArrayEquals(new int[]{0, 88, 32}, decodedVal.getRelativeOidComponents());
    }

    @Test
    public void encodeRelativeOidAndDecode2() {
        int[] components = {Integer.MAX_VALUE, Integer.MAX_VALUE};
        Asn1BerValue val = newRelativeOid(components);
        Asn1BerValue decodedVal = encodeDecode(val).der();
        // Verify tag
        decodedVal.tag(RELATIVE_OID);
        assertArrayEquals(components, decodedVal.getRelativeOidComponents());
    }

    @Test
    public void encodeEmptyRelativeOidAndDecode() {
        Asn1BerValue val = newRelativeOid();
        Asn1BerValue decodedVal = encodeDecode(val).der();
        // Verify tag
        decodedVal.tag(RELATIVE_OID);
        assertEquals(0, decodedVal.getRelativeOidComponents().length);
    }

    @Test
    public void encodeOidString() {
        Asn1BerValue val = newOid("1.2.2147483647");
        assertArrayEquals(new int[]{1, 2, 2147483647}, val.getOidComponents());
    }

    @Test
    public void newRcs1() {
        Asn1BerValue val = implicit(UTF8String).newRcs("A String");
        // Verify tag
        val.tag(UTF8String);
        assertEquals("A String", val.getRcs());
    }

    @Test
    public void newRcs2() {
        Asn1BerValue val = implicit(PrintableString).newRcs("Another String");
        // Verify tag
        val.tag(PrintableString);
        assertEquals("Another String", val.getRcs());
    }

    @Test
    public void encodeLargeOctetStringAndDecode() {
        Asn1BerValue val = newOctetString(ByteBuffer.allocate(70000));
        Asn1BerValue decodedVal = encodeDecode(val);
        // Verify tag
        decodedVal.tag(OCTET_STRING);
        assertArrayEquals(new byte[70000], decodedVal.getOctetString());
    }

    @Test
    public void encodeSeqAndDecodeUniversalTags() {
        Asn1BerValue seq = newSequenceValueUniversalTags();
        // Verify tag
        seq.tag(SEQUENCE);
        Asn1BerValue decodedSeq = encodeDecode(seq).der();
        // Verify tag
        decodedSeq.tag(SEQUENCE);
        checkSequenceValue(decodedSeq);
    }

    @Test
    public void encodeSeqAndDecodeCsTags() {
        Asn1BerValue seq = newSequenceValueCsTags();
        // Verify tag
        seq.tag(42);
        Asn1BerValue decodedSeq = encodeDecode(seq);
        // Verify tag
        assertTrue(decodedSeq.hasTagClass(CONTEXT_SPECIFIC));
        assertTrue(decodedSeq.hasTag(42));
        assertTrue(decodedSeq.hasTagClassDeep(CONTEXT_SPECIFIC));
        decodedSeq = decodedSeq.tag(42);
        checkSequenceValue(decodedSeq, true);

        List<Asn1BerValue> values = decodedSeq.der().sequence();
        assertEquals(TEST_SEQUENCE_SIZE, values.size());
        for (int i = 0; i < values.size(); ++i) {
            Asn1BerValue v = values.get(i);
            assertEquals(i + 1, v.tagValue);
            assertTrue(v.hasTag(i + 1));
        }
    }

    @Test
    public void encodeLargeCsTagBooleanAndDecode() {
        Asn1BerValue val = implicit(Integer.MAX_VALUE).newBoolean(true);
        // Verify tag
        val.tag(Integer.MAX_VALUE);
        Asn1BerValue decodedVal = encodeDecode(val).der();
        // Verify tag
        decodedVal = decodedVal.tag(Integer.MAX_VALUE);
        assertEquals(TagClass.CONTEXT_SPECIFIC, decodedVal.tagClass);
        assertEquals(Integer.MAX_VALUE, decodedVal.tagValue);
        assertTrue(decodedVal.getBoolean());
    }

    @Test
    public void encodeSeqAndDecodeNonDerBoolean() {
        Asn1BerValue seq = newSequenceValueNonDerBoolean();
        // Verify tag
        seq.tag(SEQUENCE);
        Asn1BerValue decodedSeq = encodeDecode(seq);
        assertTrue(decodedSeq.isDer()); // Structurally DER
        // Verify tag
        decodedSeq.tag(SEQUENCE);
        checkSequenceValue(decodedSeq);
    }

    @Test
    public void decodeOctetStringNonDerLength() {
        ByteBuffer buf = ByteBuffer.allocate(2 + 4 + B1.length);
        buf.put((byte) 0x04); // Id, OCTET STRING
        buf.put((byte) 0x84); // 4 Length Octets
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) B1.length); // Length
        buf.put(B1);
        buf.flip();
        Asn1BerValue decodedVal = Asn1.decodeOne(buf);
        assertFalse(decodedVal.isDer()); // Not structurally DER
        // Verify tag
        decodedVal.tag(OCTET_STRING);
        assertArrayEquals(B1, decodedVal.getOctetString());
    }

    @Test
    public void encodeSeqAndDecodeCheckDer() {
        ByteBuffer encoded = TEST_SEQUENCE.encodeDer();
        Asn1BerValue decodedSeq = Asn1.decodeOne(encoded, true);
        // Verify tag
        decodedSeq.tag(SEQUENCE);
        checkSequenceValue(decodedSeq);
    }

    @Test
    public void encodeImplicitTagSeqAndDecode() {
        Asn1BerValue seq = newImplicitTagSequenceValue();
        // Verify tag
        seq.tag(123);
        checkSequenceValue(seq);
        Asn1BerValue decodedSeq = encodeDecode(seq);
        // Verify tag
        assertTrue(decodedSeq.hasTagClass(CONTEXT_SPECIFIC));
        assertTrue(decodedSeq.hasTag(123));
        decodedSeq = decodedSeq.tag(123);
        checkSequenceValue(decodedSeq);
    }

    @Test
    public void encodeExplicitTagSeqAndDecode() {
        Asn1BerValue seq = newExplicitTagSequenceValue();
        // Verify tags
        seq.tag(APPLICATION, 456).explicit().tag(SEQUENCE);
        checkSequenceValue(seq.explicit());
        Asn1BerValue decodedSeq = encodeDecode(seq);
        // Verify tags
        assertTrue(decodedSeq.hasTagClass(APPLICATION));
        assertTrue(decodedSeq.hasTag(APPLICATION, 456));
        Asn1BerValue value = decodedSeq.tag(APPLICATION, 456).explicit().tag(SEQUENCE);
        checkSequenceValue(value);
    }

    @Test
    public void encodeExplicitTagSeqAndDecodeNoTagCheck() {
        Asn1BerValue seq = explicit(APPLICATION, 777).newInteger(888L);
        // Verify tags
        seq.tag(APPLICATION, 777).explicit().tag(INTEGER);
        Asn1BerValue decodedSeq = encodeDecode(seq);
        // Verify tags
        assertTrue(decodedSeq.hasTagClass(APPLICATION));
        assertTrue(decodedSeq.hasTag(APPLICATION, 777));
        decodedSeq.tag(APPLICATION, 777);
        BigInteger n = decodedSeq.noTagCheck().explicit().getInteger();
    }

    @Test
    public void nestedExplicitTags() {
        Asn1BerValue val = explicit(1).explicit(2).explicit(3).newBoolean(false);
        Asn1BerValue decodedVal = encodeDecode(val);
        boolean bool = decodedVal.tag(1).explicit().tag(2).explicit().tag(3).explicit().getBoolean();
        assertFalse(bool);
    }

    @Test
    public void newSetImplicitTag() {
        Asn1BerValue val = implicit(10).newSet(newNull());
    }

    @Test
    public void newSetOfImplicitTag() {
        Asn1BerValue val = implicit(11).newSetOf(newNull());
    }

    @Test
    public void newOctetStringImplicitTag() {
        Asn1BerValue val = implicit(12).newOctetString(ByteBuffer.allocate(5));
    }

    @Test
    public void newOidImplicitTag() {
        Asn1BerValue val = implicit(13).newOid(new int[]{1, 3, 2, 1});
    }

    @Test
    public void newPrimitiveImplicitTag() {
        Asn1BerValue val = implicit(14).newPrimitive(ByteBuffer.allocate(5));
    }

    @Test
    public void newOctetStringExplicitTag() {
        Asn1BerValue val = explicit(20).newOctetString(ByteBuffer.allocate(5));
    }

    @Test
    public void newOidExplicitTag() {
        Asn1BerValue val = explicit(21).newOid(1, 3, 2, 1);
    }

    @Test
    public void newRelativeOidExplicitTag() {
        Asn1BerValue val = explicit(22).newRelativeOid("4.3.2.1");
    }

    @Test
    public void newSetExplicitTag() {
        Asn1BerValue val = explicit(23).newSet(newNull());
    }

    @Test
    public void newSetOfExplicitTag() {
        Asn1BerValue val = explicit(24).newSetOf(newNull());
    }

    @Test
    public void newNullImplicitTagExplicitTag1() {
        Asn1BerValue val = explicit(23).implicit(NULL).newNull();
    }

    @Test
    public void newNullImplicitTagExplicitTag2() {
        Asn1BerValue val = explicit(23).implicit(111).newNull();
    }

    @Test
    public void newExplicitTagCs() {
        Asn1BerValue val = Asn1.newOid("1.2.3.4");
        Asn1BerValue exp = newExplicitTag(2, val);
        assertEquals(2, exp.tagValue);
        assertEquals(TagClass.CONTEXT_SPECIFIC, exp.tagClass);
        assertTrue(exp.constructed);
        assertEquals("1.2.3.4", exp.explicit().getOid());
    }

    @Test(expected = Asn1Exception.class)
    public void newExplicitTagClassUniversal() {
        Asn1BerValue exp = newExplicitTag(UNIVERSAL, 2, Asn1.newBoolean(true));
    }

    @Test
    public void setSortOrder() {
        Asn1BerValue set = newSet(
                explicit(6).newRcsUTF8String("A String"),
                explicit(7).newRcs("Another String", PrintableString),
                explicit(APPLICATION, 42).newBoolean(false),
                explicit(8).newOid("1.2.840.113549.1.1.1"),
                explicit(4).newOctetString(B1.clone()),
                explicit(2).newInteger(-42),
                explicit(9).newRelativeOid(113549, 1, 1, 1),
                explicit(1).newBoolean(true),
                explicit(5).newNull(),
                explicit(3).newInteger(new BigInteger("1234567890"))
        );
        List<Asn1BerValue> values = encodeDecode(set).set();
        assertEquals(10, values.size());

        Asn1BerValue v0 = values.get(0);
        assertEquals(TagClass.APPLICATION, v0.tagClass);
        assertEquals(42, v0.tagValue);

        for (int i = 1; i < values.size(); ++i) {
            Asn1BerValue v = values.get(i);
            assertEquals(TagClass.CONTEXT_SPECIFIC, v.tagClass);
            assertEquals(i, v.tagValue);
            assertTrue(v.hasTag(i));
        }
    }

    @Test
    public void setOfSortOrder() {
        Asn1BerValue setOf = newSetOf(
                newRcsUTF8String("String 10"),
                newRcsUTF8String("String 07"),
                newRcsUTF8String("String 01"),
                newRcsUTF8String("String 03"),
                newRcsUTF8String("String 04"),
                newRcsUTF8String("String"),
                newRcsUTF8String("String 06"),
                newRcsUTF8String("String 05"),
                newRcsUTF8String("String 08"),
                newRcsUTF8String("String 09"),
                newRcsUTF8String("String 02")
        );
        List<Asn1BerValue> values = encodeDecode(setOf).set();
        assertEquals(11, values.size());
        assertEquals("String", values.get(0).getRcs());

        for (int i = 1; i < values.size(); ++i) {
            String expected = String.format("String %02d", i);
            assertEquals(expected, values.get(i).getRcs());
        }
    }

    @Test
    public void decodeIndefiniteLength() {
        ByteBuffer encoded = indefLenSeq();
        Asn1BerValue decodedSeq = Asn1.decodeOne(encoded);
        assertFalse(decodedSeq.isDer());
        checkSequenceValue(decodedSeq);
    }

    @Test
    public void decodeConstructedOctetString() {
        Asn1BerValue os = changeId(newSequence(
                        newOctetString(TestUtil.hexStringToByteArray("040506"))),
                0x20 | OCTET_STRING.tagValue);
        Asn1BerValue val = changeId(newSequence(
                        newOctetString(TestUtil.hexStringToByteArray("010203")),
                        os,
                        newOctetString(TestUtil.hexStringToByteArray("070809"))),
                0x20 | OCTET_STRING.tagValue);
        Asn1BerValue decodedVal = encodeDecode(val);
        assertArrayEquals(TestUtil.hexStringToByteArray("010203040506070809"),
                decodedVal.getOctetString());
    }

    @Test
    public void decodeConstructedPrintableString() {
        UniversalTag ut = PrintableString;
        Asn1BerValue os = changeId(newSequence(
                        changeId(newRcs("bar", ut), OCTET_STRING.tagValue)),
                0x20 | OCTET_STRING.tagValue);
        Asn1BerValue val = changeId(newSequence(
                        changeId(newRcs("foo ", ut), OCTET_STRING.tagValue),
                        os,
                        changeId(newRcs(" baz", ut), OCTET_STRING.tagValue)),
                0x20 | ut.tagValue);
        Asn1BerValue decodedVal = encodeDecode(val);
        assertEquals("foo bar baz", decodedVal.getRcs());
    }

    @Test
    public void testToString() {
        assertEquals("SEQUENCE <constructed>", TEST_SEQUENCE.toString());
        List<Asn1BerValue> values = TEST_SEQUENCE.values();
        assertEquals("TRUE", values.get(0).toString());
        assertEquals("-42", values.get(1).toString());
        assertEquals("1234567890", values.get(2).toString());
        assertEquals("-155", values.get(3).toString());
        assertEquals("02 35 14", values.get(4).toString());
        assertEquals("12 34 56 78 DE AD BE EF", values.get(5).toString());
        assertEquals("NULL", values.get(6).toString());
        assertEquals("'A String'", values.get(7).toString());
        assertEquals("'Another String'", values.get(8).toString());
        assertEquals("(1 2 840 113549 1 1 1)", values.get(9).toString());
        assertEquals("(113549 1 1 1)", values.get(10).toString());
        assertEquals("4", values.get(11).toString());
        assertEquals(DATE_TIME.toString(), values.get(12).toString());
        assertEquals(DATE_TIME.toString(), values.get(13).toString());
    }

    @Test
    public void tagToString1() {
        assertEquals("[null tag class]", Asn1.tagToString(null, 0));
    }

    @Test
    public void tagToString2() {
        assertEquals("[invalid tag value: -5]", Asn1.tagToString(APPLICATION, -5));
    }

    @Test
    public void tagToString3() {
        assertEquals("INTEGER", Asn1.tagToString(UNIVERSAL, INTEGER.tagValue));
    }

    @Test
    public void tagToString4() {
        assertEquals("[APPLICATION 12]", Asn1.tagToString(APPLICATION, 12));
    }

    @Test
    public void tagToString5() {
        assertEquals("[42]", Asn1.tagToString(TagClass.CONTEXT_SPECIFIC, 42));
    }

    // Test assertions

    @Test(expected = Asn1DecodeException.class)
    public void assertSequencePrimitiveFail() {
        TEST_SEQUENCE.primitive();
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertBooleanConstructedFail() {
        newBoolean(true).constructed();
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertBooleanHasCsTagFail() {
        newBoolean(true).tag(88);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertIntegerUniversalTagFail() {
        newInteger(18).tag(BOOLEAN);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertIntegerTagClassFail() {
        newInteger(22).tagClass(CONTEXT_SPECIFIC);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertNullApplicationTagFail() {
        newNull().tag(APPLICATION, 11);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertSequenceTagClassDeepFail1() {
        TEST_SEQUENCE.tagClassDeep(APPLICATION);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertSequenceTagClassDeepFail2() {
        newImplicitTagSequenceValue().tagClassDeep(CONTEXT_SPECIFIC);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertSequenceTagClassDeepFail3() {
        newImplicitTagSequenceValue().tagClassDeep(UNIVERSAL);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertSequenceMinCountFail() {
        TEST_SEQUENCE.minCount(TEST_SEQUENCE_SIZE + 1);
    }

    @Test(expected = Asn1DecodeException.class)
    public void assertSequenceMaxCountFail() {
        TEST_SEQUENCE.maxCount(9);
    }

    // Negative tests

    @Test(expected = Asn1DecodeException.class)
    public void booleanAutoTagClassCheckFail() {
        Asn1BerValue seq = implicit(123).newBoolean(true);
        ByteBuffer encoded = seq.encodeDer();

        Asn1BerValue decodedSeq = Asn1.decodeOne(encoded);
        boolean b = decodedSeq.getBoolean();
    }

    @Test(expected = Asn1DecodeException.class)
    public void explicitTagAutoTagClassCheckFail() {
        Asn1BerValue seq = explicit(123).newBoolean(true);
        ByteBuffer encoded = seq.encodeDer();

        Asn1BerValue decodedSeq = Asn1.decodeOne(encoded);
        Asn1BerValue value = decodedSeq.explicit();
    }

    @Test(expected = Asn1DerDecodeException.class)
    public void decodeNonDerSeqCheckDerFail() {
        Asn1BerValue seq = newSequenceValueNonDerBoolean();
        // Verify tag
        seq.tag(SEQUENCE);
        ByteBuffer encoded = seq.encodeDer();

        Asn1BerValue decodedSeq = Asn1.decodeOne(encoded, true);
        // Verify tag
        decodedSeq.tag(SEQUENCE);
        checkSequenceValue(decodedSeq);
    }

    @Test(expected = Asn1DerDecodeException.class)
    public void decodeNonDerBooleanCheckDerFail() {
        Asn1BerValue val = implicit(BOOLEAN).newPrimitive(new byte[]{0x22});
        ByteBuffer encoded = val.encodeDer();
        Asn1BerValue decodedVal = Asn1.decodeOne(encoded, true);
        decodedVal.getBoolean();
    }

    @Test(expected = Asn1DerDecodeException.class)
    public void decodeIndefiniteLengthCheckDerFail() {
        ByteBuffer encoded = indefLenSeq();
        Asn1BerValue decodedSeq = Asn1.decodeOne(encoded, true);
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void invalidBooleanContentFail1() {
        Asn1BerValue val = implicit(BOOLEAN).newPrimitive(new byte[0]);
        val.getBoolean();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidBooleanContentFail1() {
        Asn1BerValue val = implicit(BOOLEAN).newPrimitive(new byte[0]);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getBoolean();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidBooleanContentFail2() {
        Asn1BerValue val = implicit(BOOLEAN).newPrimitive(new byte[2]);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getBoolean();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidIntegerContentFail1() {
        Asn1BerValue val = implicit(INTEGER).newPrimitive(new byte[0]);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getInteger();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidIntegerContentFail2() {
        Asn1BerValue val = implicit(INTEGER).newPrimitive(NON_BER_M42);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getInteger();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidIntegerContentFail3() {
        Asn1BerValue val = implicit(INTEGER).newPrimitive(NON_BER_M155);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getInteger();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidIntegerContentFail4() {
        Asn1BerValue val = implicit(INTEGER).newPrimitive(NON_BER_N);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getInteger();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidNullContentFail() {
        Asn1BerValue val = implicit(NULL).newPrimitive(new byte[1]);
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getNull();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidOidContentFail1() {
        // Truncated
        Asn1BerValue val = implicit(OBJECT_IDENTIFIER).newPrimitive(
                TestUtil.hexStringToByteArray("010281"));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getOidComponents();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidOidContentFail2() {
        // Non-canonical
        Asn1BerValue val = implicit(OBJECT_IDENTIFIER).newPrimitive(
                TestUtil.hexStringToByteArray("01028003"));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getOidComponents();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidOidContentFail3() {
        // Component exceeds implementation limit
        Asn1BerValue val = implicit(OBJECT_IDENTIFIER).newPrimitive(
                TestUtil.hexStringToByteArray("01028880808000"));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getOidComponents();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidUTCTimeContentFail1() {
        Asn1BerValue val = implicit(UTCTime).newPrimitive(
                "Non-ascii character \uD83D\uDE00".getBytes(StandardCharsets.UTF_8));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getUtcTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidUTCTimeContentFail2() {
        // Fail to match regex. Incomplete tz offset.
        Asn1BerValue val = implicit(UTCTime).newPrimitive(
                "851106210627-".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getUtcTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidUTCTimeContentFail3() {
        // Fail to match regex. Invalid timezone offset, "-Z".
        Asn1BerValue val = implicit(UTCTime).newPrimitive(
                "851106210627-Z".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getUtcTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidUTCTimeContentFail4() {
        // Regex pattern match, but subsequent fail in DateTimeFormatter.parseBest().
        // Month 42.
        Asn1BerValue val = implicit(UTCTime).newPrimitive(
                "854206210627Z".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getUtcTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidUTCTimeContentFail5() {
        // Regex pattern match, but subsequent fail in DateTimeFormatter.parseBest().
        Asn1BerValue val = implicit(UTCTime).newPrimitive(
                "851106210627+9999".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getUtcTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidGeneralizedTimeContentFail1() {
        Asn1BerValue val = implicit(GeneralizedTime).newPrimitive(
                "Non-ascii character \uD83D\uDE00".getBytes(StandardCharsets.UTF_8));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getGeneralizedTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidGeneralizedTimeContentFail2() {
        // Fail to match regex. Incomplete tz offset.
        Asn1BerValue val = implicit(GeneralizedTime).newPrimitive(
                "19851106210627-".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getGeneralizedTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidGeneralizedTimeContentFail3() {
        // Fail to match regex. Invalid timezone offset, "-Z".
        Asn1BerValue val = implicit(GeneralizedTime).newPrimitive(
                "19851106210627-Z".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getGeneralizedTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidGeneralizedTimeContentFail4() {
        // Regex pattern match, but subsequent fail in DateTimeFormatter.parseBest().
        // Month 42.
        Asn1BerValue val = implicit(GeneralizedTime).newPrimitive(
                "19854206210627".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getGeneralizedTime();
    }

    @Test(expected = Asn1ContentDecodeException.class)
    public void decodeInvalidGeneralizedTimeContentFail5() {
        // Regex pattern match, but subsequent fail in DateTimeFormatter.parseBest().
        // TZ offset is "+9999".
        Asn1BerValue val = implicit(GeneralizedTime).newPrimitive(
                "19851106210627.1234+9999".getBytes(StandardCharsets.US_ASCII));
        Asn1BerValue decodedVal = encodeDecode(val);
        decodedVal.getGeneralizedTime();
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeTruncatedPrimitiveFail() {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.put((byte) 4); // OCTET STRING
        buf.put((byte) 16);
        buf.rewind();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeTruncatedDefLenConstructedFail() {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.put((byte) 0x30); // SEQUENCE
        buf.put((byte) 16);
        buf.rewind();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeTruncatedIndefLenConstructedFail() {
        ByteBuffer encoded = TEST_SEQUENCE.encodeDer();
        encoded.put(1, (byte) 0x80); // Indefinite Length
        encoded.limit(encoded.limit() / 2);
        Asn1BerValue decodedVal = Asn1.decode(encoded);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeIndefLenConstructedNoEndOfContFail() {
        ByteBuffer encoded = TEST_SEQUENCE.encodeDer();
        encoded.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(encoded);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeDefLenConstructedUnexpectedEndOfContFail() {
        // Add an end-off-contents marker (two zero octets) at the end.
        ByteBuffer encoded = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 2);
        TEST_SEQUENCE.encodeDer(encoded);
        encoded.rewind();
        encoded.put(1, (byte) (encoded.capacity() - 2));
        Asn1BerValue decodedVal = Asn1.decode(encoded);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeIndefLenPrimitiveFail() {
        Asn1BerValue ival = newInteger(new BigInteger("1234567890"));
        ByteBuffer encoded = ival.encodeDer();
        encoded.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(encoded);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeContainerWithLargerNestedValueFail() {
        Asn1BerValue val = newExplicitTagSequenceValue();
        ByteBuffer encoded = val.encodeDer();
        encoded.limit(encoded.limit() / 2);
        Asn1BerValue decodedVal = Asn1.decode(encoded);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeOneExtraDataFail() {
        ByteBuffer buf = ByteBuffer.allocate(16);
        // Buffer contains two values
        newInteger(42).encodeDer(buf);
        newBoolean(true).encodeDer(buf);
        buf.flip();
        Asn1BerValue decodedVal = Asn1.decodeOne(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidTagFail1() {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.put((byte) 0x1f); // UNIVERSAL
        buf.put((byte) 0x05); // NULL (could fit in Id octet)
        buf.put((byte) 0x00); // Length
        buf.flip();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidTagFail2() {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.put((byte) (0x80 | 0x1f)); // CS
        buf.put((byte) 0x80); // Zero, more to come
        buf.put((byte) 0x20); // 32
        buf.put((byte) 0x00); // Length
        buf.flip();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail1() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 3);
        TEST_SEQUENCE.encodeDer(buf);
        buf.put((byte) 0x1f); // Id
        buf.put((byte) 0x00); // Tag
        buf.put((byte) 0x00); // Length
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail2() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 4);
        TEST_SEQUENCE.encodeDer(buf);
        buf.put((byte) 0x1f); // Id
        buf.put((byte) 0x80); // Tag
        buf.put((byte) 0x00); // Tag
        buf.put((byte) 0x00); // Length
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail3() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 3);
        TEST_SEQUENCE.encodeDer(buf);
        buf.put((byte) 0x00); // Id
        buf.put((byte) 0x01); // Length
        buf.put((byte) 0x00); // Content
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail4() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 2);
        TEST_SEQUENCE.encodeDer(buf);
        buf.put((byte) 0x20); // Id, Constructed
        buf.put((byte) 0x00); // Length
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail5() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 4);
        TEST_SEQUENCE.encodeDer(buf);
        buf.put((byte) 0x00); // Id
        buf.put((byte) 0x80); // Indefinite Length
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail6() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 4);
        TEST_SEQUENCE.encodeDer(buf);
        buf.put((byte) 0x20); // Id, Constructed
        buf.put((byte) 0x80); // Indefinite Length
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeInvalidEndOfContentsFail7() {
        // Add an invalid end-off-contents marker at the end.
        ByteBuffer buf = ByteBuffer.allocate(TEST_SEQUENCE_LEN + 3);
        TEST_SEQUENCE.encodeDer(buf);
        // Non-DER
        buf.put((byte) 0x00); // Id
        buf.put((byte) 0x81); // 1 Length Octet
        buf.put((byte) 0x00); // Length
        buf.rewind();
        buf.put(1, (byte) 0x80); // Indefinite Length
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeTagExceedsImplLimitFail() {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.put((byte) (0x80 | 0x1f)); // Id, CS
        // Tag is 0x80000000
        buf.put((byte) 0x88); // 0b0001000, more to come
        buf.put((byte) 0x80); // 7 zero bits, more to come
        buf.put((byte) 0x80); // 7 zero bits, more to come
        buf.put((byte) 0x80); // 7 zero bits, more to come
        buf.put((byte) 0x00); // 7 zero bits
        buf.put((byte) 0x00); // Length
        buf.flip();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeLengthExceedsImplLimitFail1() {
        ByteBuffer buf = ByteBuffer.allocate(128);
        buf.put((byte) 0x04); // Id, OCTET STRING
        buf.put((byte) 0x85); // 5 Length Octets
        buf.put((byte) 0x40); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.rewind();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeLengthExceedsImplLimitFail2() {
        ByteBuffer buf = ByteBuffer.allocate(128);
        // Failure is due to the number of Length Octets
        buf.put((byte) 0x04); // Id, OCTET STRING
        buf.put((byte) 0x85); // 5 Length Octets
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x08); // Length 8
        buf.rewind();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeLengthExceedsImplLimitFail3() {
        ByteBuffer buf = ByteBuffer.allocate(128);
        buf.put((byte) 0x04); // Id, OCTET STRING
        buf.put((byte) 0x85); // 4 Length Octets
        buf.put((byte) 0x80); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.put((byte) 0x00); // Length
        buf.rewind();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeNestDepthExceedsImplLimitFail() {
        Asn1BerValue deeplyNested = Asn1.newInteger(42);
        for (int i = 0; i < Asn1BerValue.MAX_DECODE_DEPTH + 1; ++i) {
            deeplyNested = Asn1.newSequence(deeplyNested);
        }
        byte[] buf = deeplyNested.encodeDerOctets();
        Asn1BerValue decodedVal = Asn1.decodeOne(buf);
    }

    @Test(expected = Asn1DecodeException.class)
    public void decodeMaxLengthBufferUnderflowFail() {
        ByteBuffer buf = ByteBuffer.allocate(128);
        buf.put((byte)0x04); // Id, OCTET STRING
        buf.put((byte)0x84); // 4 Length Octets
        buf.put((byte)0x7f); // Length
        buf.put((byte)0xff); // Length
        buf.put((byte)0xff); // Length
        buf.put((byte)0xff); // Length
        buf.rewind();
        Asn1BerValue decodedVal = Asn1.decode(buf);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeEmptyOidFail() {
        Asn1BerValue val = newOid();
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidInsufficientComponentsFail() {
        Asn1BerValue val = newOid(1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidComponentRangeFail1() {
        Asn1BerValue val = newOid(-1, 1, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidComponentRangeFail2() {
        Asn1BerValue val = newOid(1, -1, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidComponentRangeFail3() {
        Asn1BerValue val = newOid(0, 40, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidComponentRangeFail4() {
        Asn1BerValue val = newOid(1, 40, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidComponentRangeFail5() {
        Asn1BerValue val = newOid(2, Integer.MAX_VALUE - 79, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidComponentRangeFail6() {
        Asn1BerValue val = newOid(3, 1, 1);
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail1() {
        Asn1BerValue val = newOid("");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail2() {
        Asn1BerValue val = newOid("1.2..3");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail3() {
        Asn1BerValue val = newOid("cat.hat");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail4() {
        Asn1BerValue val = newOid("1,2,3");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail5() {
        Asn1BerValue val = newOid("1 2 3");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail6() {
        Asn1BerValue val = newOid(" 1.2.3");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail7() {
        Asn1BerValue val = newOid("1 . 2 . 3");
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOidInvalidStringFail8() {
        Asn1BerValue val = newOid("1.2.-3");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail9() {
        Asn1BerValue val = newOid("0x01.0x02.0x03");
    }

    @Test(expected = NumberFormatException.class)
    public void encodeOidInvalidStringFail10() {
        Asn1BerValue val = newOid("1.2.2147483648");
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeRelativeOidComponentRangeFail() {
        Asn1BerValue val = newRelativeOid(-1, 1, 1);
    }

    @Test(expected = Asn1Exception.class)
    public void newBooleanMismatchedUnivTagFail1() {
        implicit(INTEGER).newBoolean(false);
    }

    @Test(expected = Asn1Exception.class)
    public void newBooleanMismatchedUnivTagFail2() {
        implicit(SET).newBoolean(false);
    }

    @Test(expected = Asn1Exception.class)
    public void newPrimitiveWithSequenceTagFail() {
        implicit(SEQUENCE).newPrimitive(new byte[] {1, 2, 3});
    }

    @Test(expected = Asn1Exception.class)
    public void newSetWithIntegerTagFail() {
        implicit(INTEGER).newSet(newBoolean(false));
    }

    @Test(expected = Asn1Exception.class)
    public void explicitWithUniversalTagFail() {
        explicit(UNIVERSAL, BOOLEAN.tagValue).newBoolean(false);
    }

    @Test(expected = NullPointerException.class)
    public void newRcsWithNullEncodingFail() {
        newRcs("banana", null);
    }

    @Test(expected = Asn1Exception.class)
    public void newRcsWithInvalidRcsEncodingFail() {
        newRcs("foo", INTEGER);
    }

    @Test(expected = Asn1Exception.class)
    public void newRcsUnknownEncodingFail() {
        implicit(12).newRcs("bar");
    }

    @Test(expected = Asn1Exception.class)
    public void newRcsUnknownEncodingInvalidUniversalFail() {
        implicit(UNIVERSAL, 42).newRcs("baz");
    }

    @Test(expected = Asn1Exception.class)
    public void newRcsInvalidUniversalFail() {
        implicit(UNIVERSAL, 42).newRcs("quux", PrintableString);
    }

    @Test(expected = Asn1DecodeException.class)
    public void getBooleanOnIntegerFail() {
        Asn1BerValue val = newInteger(42);
        val.getBoolean();
    }

    @Test(expected = Asn1DecodeException.class)
    public void getIntegerOnSequenceFail() {
        TEST_SEQUENCE.getInteger();
    }

    @Test(expected = Asn1DecodeException.class)
    public void sequenceOnIntegerFail() {
        Asn1BerValue val = newInteger(42);
        val.sequence();
    }

    @Test(expected = Asn1DecodeException.class)
    public void setOnSequenceFail() {
        TEST_SEQUENCE.set();
    }

    @Test(expected = Asn1DecodeException.class)
    public void explicitOnIntegerFail() {
        Asn1BerValue val = newInteger(42);
        val.explicit();
    }

    @Test(expected = Asn1DecodeException.class)
    public void getIntegerOnConstructedFail() {
        Asn1BerValue val = implicit(321).newSequence(newBoolean(false));
        val.getInteger();
    }

    @Test(expected = Asn1DecodeException.class)
    public void valuesOnPrimitiveFail() {
        Asn1BerValue val = implicit(321).newNull();
        val.values();
    }

    @Test(expected = NullPointerException.class)
    public void getRcsNullEncodingFail() {
        Asn1BerValue val = newRcs("xyzzy", UTF8String);
        val.getRcs(null);
    }

    @Test(expected = Asn1DecodeException.class)
    public void getRcsMismatchedEncodingFail() {
        Asn1BerValue val = newRcs("xyzzy", UTF8String);
        val.getRcs(PrintableString);
    }

    @Test(expected = Asn1DecodeException.class)
    public void getRcsInvalidRcsEncodingFail() {
        Asn1BerValue val = implicit(1).newRcs("plugh", PrintableString);
        val.getRcs(INTEGER);
    }

    @Test(expected = Asn1DecodeException.class)
    public void getRcsUnknownEncodingFail() {
        Asn1BerValue val = implicit(21).newRcs("quux", PrintableString);
        val.getRcs();
    }

    @Test(expected = NullPointerException.class)
    public void assertNullUniversalTagFail() {
        TEST_SEQUENCE.tag(null);
    }

    @Test(expected = NullPointerException.class)
    public void assertNullTagClassFail() {
        TEST_SEQUENCE.tag(null, 16);
    }

    @Test(expected = IllegalArgumentException.class)
    public void assertNegTagValueFail() {
        TEST_SEQUENCE.tag(APPLICATION, -16);
    }

    @Test(expected = IllegalArgumentException.class)
    public void assertNegCsTagValueFail() {
        TEST_SEQUENCE.tag(-16);
    }
}
