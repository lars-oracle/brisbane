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

package com.oracle.test.integration.keyfactory;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

public class ECKeyFactoryTest {

    KeyFactory kf;

    public ECKeyFactoryTest() throws Exception {
        kf = ProviderUtil.getKeyFactory("EC");
    }

    @Test
    public void rfc5915NonCompliantPrivateKeyEncoding() throws Exception {
        // The following EC private key PKCS #8 ASN.1 encodings do NOT comply with RFC 5915 section 3:
        //    The private key is an octet string of length ceiling (log2(n)/8) (where n is the order of the curve)
        //    obtained from the unsigned integer via the Integer-to-Octet-String-Primitive (I2OSP)
        byte[] secp224r1 = TestUtil.hexToBytes("3039020100301006072A8648CE3D020106052B8104002104223020020101041B75E29141B82FEFCEE01A1BF3453BD37BE463F65B4AF84976B74E08");
        byte[] secp256r1 = TestUtil.hexToBytes("3040020100301306072A8648CE3D020106082A8648CE3D03010704263024020101041F4D718710022B198A4FB5EEC93445DE85C2B65DB2E5CB29CAB24F97E00EA431");
        byte[] secp384r1 = TestUtil.hexToBytes("304D020100301006072A8648CE3D020106052B8104002204363034020101042FDF18F4FBA2D72C2954975A91DD5C0483C2E44CCFF3C184741FE790168A3A20BBF8DD23E46555D2D05B0BC99528E9C5");
        byte[] secp521r1 = TestUtil.hexToBytes("305F020100301006072A8648CE3D020106052B810400230448304602010104416D0E393A538376860B377C92DB7A3A410B20DF7F5FD729EFC4703B7AD55F329C6E78EF446E03FE62038E2661E2D4BD01C8BA27F3D940E389E8700A57F014AD7AF3");
        for (byte[] encoding : Arrays.asList(secp224r1, secp256r1, secp384r1, secp521r1)) {
            kf.generatePrivate(new PKCS8EncodedKeySpec(encoding));
        }
    }
}
