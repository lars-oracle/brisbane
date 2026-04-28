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

package com.oracle.jipher.internal.spi;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import javax.crypto.spec.DHParameterSpec;

import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.common.Util;

/**
 * This class stores pre-defined DH parameters for with DH key pairs.
 */
final class DhParamCache {

    private static final Debug DEBUG = Debug.getInstance("jipher");

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1">RFC 7919 Appendix A.1</a> - ffdhe2048.
     */
    private static final byte[] FFEDHE2048_P = Util.hexToBytes(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"+
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"+
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"+
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"+
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"+
            "886B423861285C97FFFFFFFFFFFFFFFF");
    private static final byte[] FFEDHE2048_G = Util.hexToBytes("02");

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.2">RFC 7919 Appendix A.2</a> - ffdhe3072.
     */
    private static final byte[] FFEDHE3072_P = Util.hexToBytes(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"+
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"+
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"+
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"+
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"+
            "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"+
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"+
            "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF");
    private static final byte[] FFEDHE3072_G = Util.hexToBytes("02");

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.3">RFC 7919 Appendix A.3</a> - ffdhe4096.
     */
    private static final byte[] FFEDHE4096_P = Util.hexToBytes(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"+
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"+
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"+
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"+
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"+
            "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"+
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"+
            "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"+
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"+
            "A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"+
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF");
    private static final byte[] FFEDHE4096_G = Util.hexToBytes("02");

    /**
     * Retrieve default parameters for the given prime size in bits.
     * @param primeSize the prime modulus size in bits
     * @return a DSAParameterSpec containing valid parameters
     * @throws InvalidParameterException the prime size is not supported
     */
    public static DHParameterSpec get(int primeSize) {
        if (primeSize == 2048) {
            DEBUG.println("Getting default DH parameters: ffedhe2048");
            return new DHParameterSpec(new BigInteger(1, FFEDHE2048_P), new BigInteger(1, FFEDHE2048_G));
        } else if (primeSize == 3072) {
            DEBUG.println("Getting default DH parameters: ffedhe3072");
            return new DHParameterSpec(new BigInteger(1, FFEDHE3072_P), new BigInteger(1, FFEDHE3072_G));
        } else if (primeSize == 4096) {
            DEBUG.println("Getting default DH parameters: ffedhe4096");
            return new DHParameterSpec(new BigInteger(1, FFEDHE4096_P), new BigInteger(1, FFEDHE4096_G));
        } else {
            throw new InvalidParameterException("No DH parameters available for size " + primeSize + ", only 2048, 3072, 4096 supported");
        }
    }
}
