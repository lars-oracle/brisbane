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

package com.oracle.test.integration.parameters;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;

@RunWith(Parameterized.class)
public class Pbes2ParametersDerNegTest {
    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        return Arrays.asList(
            new Object[] {
                "Empty DER", "PBES2", new byte[0]
            },
            new Object[] {
                "Invalid non-universal tag", "PBES2",
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02098100301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong keyDerivationFunc OID", "PBES2",
                hexStringToByteArray("304d302c06092a864886f93901050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong encryptionScheme OID", "PBES2",
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301d060960872c01650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong prf OID", "PBES2",
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a872c86f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid salt", "PBES2",
                hexStringToByteArray("3045302406092a864886f70d01050c30170400020207d0020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid zero iteration count", "PBES2",
                hexStringToByteArray("304c302b06092a864886f70d01050c301e040873616c7431323334020100020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid negative iteration count", "PBES2",
                hexStringToByteArray("304c302b06092a864886f70d01050c301e040873616c74313233340201ff020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid zero key length", "PBES2",
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020100300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid negative key length", "PBES2",
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020207d00201ff300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid unmatched key length", "PBES2",
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020120300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid zero length iv", "PBES2",
                hexStringToByteArray("303d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500300d06096086480165030401020400")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid unmatched iv length", "PBES2",
                hexStringToByteArray("304c302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301c0609608648016503040102040f0102030405060708090a0b0c0d0e0f")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Missing prf NULL", "PBES2",
                hexStringToByteArray("304b302a06092a864886f70d01050c301d040873616c7431323334020207d0020110300a06082a864886f70d0209301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Missing iv OCTET STRING", "PBES2",
                hexStringToByteArray("303b302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500300b0609608648016503040102")
            },
            new Object[] {
                "Invalid non-universal tag (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02098100301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Extra sequence (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("306706092a864886f70d01050d305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong PBE OID (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f93901050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong keyDerivationFunc OID (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f93901050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong encryptionScheme OID (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301d060960872c01650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Wrong prf OID (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a872c86f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid salt (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305206092a864886f70d01050d3045302406092a864886f70d01050c30170400020207d0020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid zero iteration count (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305906092a864886f70d01050d304c302b06092a864886f70d01050c301e040873616c7431323334020100020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid negative iteration count (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305906092a864886f70d01050d304c302b06092a864886f70d01050c301e040873616c74313233340201ff020110300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Invalid zero key length (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("i305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020100300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid negative key length (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d00201ff300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid unmatched key length (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020207d0020120300c06082a864886f70d02090500301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid zero length iv (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("304a06092a864886f70d01050d303d302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500300d06096086480165030401020400")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid unmatched iv length (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305906092a864886f70d01050d304c302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500301c0609608648016503040102040f0102030405060708090a0b0c0d0e0f")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Missing prf NULL (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("305806092a864886f70d01050d304b302a06092a864886f70d01050c301d040873616c7431323334020207d0020110300a06082a864886f70d0209301d060960864801650304010204100102030405060708090a0b0c0d0e0f10")
            },
            new Object[] {
                "Missing iv OCTET STRING (JDK 1.8.0_40)", "PBES2",
                hexStringToByteArray("304806092a864886f70d01050d303b302c06092a864886f70d01050c301f040873616c7431323334020207d0020110300c06082a864886f70d02090500300b0609608648016503040102")
            }
        );
    }

    private final String alg;
    private final byte[] der;
    private AlgorithmParameters params;

    public Pbes2ParametersDerNegTest(String description, String alg, byte[] der) {
        this.alg = alg;
        this.der = der;
    }

    @Before
    public void setUp() throws Exception {
        params = ProviderUtil.getAlgorithmParameters(this.alg);
    }

    @Test(expected = IOException.class)
    public void initDer() throws Exception {
        params.init(this.der);
    }
}
