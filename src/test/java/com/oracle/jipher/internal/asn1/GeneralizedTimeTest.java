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

import java.time.LocalDateTime;
import java.time.Month;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static com.oracle.jipher.internal.asn1.UniversalTag.GeneralizedTime;
import static com.oracle.jiphertest.util.TimeUtil.dt;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class GeneralizedTimeTest {

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {

        String baseHours = "1985110621";
        String baseMins = "198511062106";
        String baseSecs = "19851106210627"; // DER, if UTC
        String baseMills = "19851106210627.300";
        String baseMillsShort = "19851106210627.3"; // DER, if UTC
        String baseMillsShortComma = "19851106210627,3";
        String baseMillsLong = "19851106210627.30000";
        String baseMillsComma = "19851106210627,300";

        LocalDateTime baseDT = LocalDateTime.of(
                1985, Month.NOVEMBER, 6,
                21, 6, 27, 300_000_000);

        List<Object[]> data = new ArrayList<>();

        ZoneOffset tzUtc =  ZoneOffset.UTC;
        ZoneOffset tzPlus = ZoneOffset.ofHours(8);
        ZoneOffset tzMinus = ZoneOffset.ofHours(-10);

        ZoneOffset[] tzs = new ZoneOffset[]{null, tzUtc, tzPlus, tzMinus};
        String[] tzOffsets = new String[]{"", "Z", "+0800", "-1000"};

        for (int i = 0; i < tzs.length; i++) {
            ZoneOffset tz = tzs[i];
            String tzOffset = tzOffsets[i];
            data.add(new Object[]{
                    baseMills + tzOffset, dt(baseDT, tz, -1, -1, -1),
                    false
            });
            data.add(new Object[]{
                    baseMillsShort + tzOffset, dt(baseDT, tz, -1, -1, -1),
                    tz == ZoneOffset.UTC
            });
            data.add(new Object[]{
                    baseMillsShortComma + tzOffset, dt(baseDT, tz, -1, -1, -1),
                    false
            });
            data.add(new Object[]{
                    baseMillsLong + tzOffset, dt(baseDT, tz, -1, -1, -1),
                    false
            });
            data.add(new Object[]{
                    baseSecs + tzOffset, dt(baseDT, tz, -1, -1, 0),
                    tz == ZoneOffset.UTC
            });
            data.add(new Object[]{
                    baseMins + tzOffset, dt(baseDT, tz, -1, 0, 0),
                    false
            });
            data.add(new Object[]{
                    baseHours + tzOffset, dt(baseDT, tz, 0, 0, 0),
                    false
            });
            data.add(new Object[]{
                    baseMillsComma + tzOffset, dt(baseDT, tz, -1, -1, -1),
                    false
            });
        }
        return data;
    }

    String s;
    TemporalAccessor dt;
    boolean isDer;

    public GeneralizedTimeTest(String s, TemporalAccessor dt, boolean isDer) {
        this.s = s;
        this.dt = dt;
        this.isDer = isDer;
    }

    @Test
    public void parse() {
        Asn1BerValue timeValue = Asn1.implicit(GeneralizedTime).newPrimitive(s.getBytes(US_ASCII));
        TemporalAccessor parsed = timeValue.getGeneralizedTime();
        assertEquals(dt, parsed);
    }

    @Test
    public void formatDer() {
        Assume.assumeTrue(isDer);
        Asn1BerValue timeValue = Asn1.newGeneralizedTime((OffsetDateTime)dt);
        assertEquals(s, new String(timeValue.octets(), US_ASCII));
    }

    @Test
    public void formatParse() {
        OffsetDateTime odt = dt instanceof OffsetDateTime ?
                (OffsetDateTime)dt : OffsetDateTime.of((LocalDateTime)dt, ZoneOffset.UTC);
        Asn1BerValue timeValue = Asn1.newGeneralizedTime(odt);
        assertEquals(odt.withOffsetSameInstant(ZoneOffset.UTC), timeValue.getGeneralizedTime());
    }

    @Test
    public void encodeDecode() {
        OffsetDateTime odt = dt instanceof OffsetDateTime ?
                (OffsetDateTime)dt : OffsetDateTime.of((LocalDateTime)dt, ZoneOffset.UTC);
        Asn1BerValue timeValue = Asn1.newGeneralizedTime(odt);
        byte[] encoded = timeValue.encodeDerOctets();
        Asn1BerValue decoded = Asn1.decodeOne(encoded, true);
        OffsetDateTime expected = odt.withOffsetSameInstant(ZoneOffset.UTC);
        assertEquals(expected, decoded.getGeneralizedTime());
        assertEquals(expected, decoded.getDateTime());
    }

    @Test
    public void decodeDer() {
        Assume.assumeTrue(isDer);
        Asn1BerValue timeValue = Asn1.implicit(GeneralizedTime).newPrimitive(s.getBytes(US_ASCII));
        byte[] encoded = timeValue.encodeDerOctets();
        Asn1BerValue decoded = Asn1.decodeOne(encoded, true);
        TemporalAccessor parsed = decoded.getGeneralizedTime();
        assertEquals(dt, parsed);
    }

    @Test(expected = Asn1DerDecodeException.class)
    public void decodeDerNeg() {
        Assume.assumeFalse(isDer);
        Asn1BerValue timeValue = Asn1.implicit(GeneralizedTime).newPrimitive(s.getBytes(US_ASCII));
        byte[] encoded = timeValue.encodeDerOctets();
        Asn1BerValue decoded = Asn1.decodeOne(encoded, true);
        decoded.getGeneralizedTime();
    }
}
