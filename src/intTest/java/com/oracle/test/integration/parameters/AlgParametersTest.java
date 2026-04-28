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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class AlgParametersTest {

    static final byte[] AES_IV = hexStringToByteArray("12341234123412341234123412341234");
    static final byte[] SALT = "salt1234".getBytes(StandardCharsets.US_ASCII);

    @Parameters(name = "{0}[{index}]")
    public static Collection<Object[]> data() throws Exception {
        ArrayList<Object[]> data = new ArrayList<>(Arrays.asList(
            new Object[] {
                "AES", new IvParameterSpec(AES_IV),
                hexStringToByteArray("041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "DESede", new IvParameterSpec(hexStringToByteArray("1234123412341234")),
                hexStringToByteArray("04081234123412341234"),
                false
            },
            new Object[] {
                "GCM", new GCMParameterSpec(120, new byte[15]),
                hexStringToByteArray("3014040F00000000000000000000000000000002010F"),
                false
            },
            new Object[] {
                "GCM", new GCMParameterSpec(112, new byte[] {1,2,3,4}),
                hexStringToByteArray("300904040102030402010E"),
                false
            },
            new Object[] {
                "GCM", new GCMParameterSpec(128, new byte[40]),
                hexStringToByteArray("302D042800000000000000000000000000000000000000000000000000000000000000000000000000000000020110"),
                false
            },
            new Object[] {
                "OAEP", new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-384"), new PSource.PSpecified(new byte[]{1, 2, 3, 4})),
                hexStringToByteArray("3033a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"),
                false
            },
            new Object[] {
                "OAEP", new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-384"), new PSource.PSpecified(new byte[]{1, 2, 3, 4})),
                hexStringToByteArray("3040a00b300906052b0e03021a0500a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"),
                true
            },
            new Object[] {
                "OAEP", new OAEPParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-1"), new PSource.PSpecified(new byte[]{1, 2, 3, 4})),
                hexStringToByteArray("3026a00f300d06096086480165030402030500a213301106092a864886f70d010109040401020304"),
                false
            },
            new Object[] {
                "OAEP", new OAEPParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-1"), new PSource.PSpecified(new byte[]{1, 2, 3, 4})),
                hexStringToByteArray("3040a00f300d06096086480165030402030500a118301606092a864886f70d010108300906052b0e03021a0500a213301106092a864886f70d010109040401020304"),
                true
            },
            new Object[] {
                "OAEP", new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT),
                hexStringToByteArray("302fa00f300d06096086480165030402040500a11c301a06092a864886f70d010108300d06096086480165030402010500"),
                false
            },
            new Object[] {
                "OAEP", new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT),
                hexStringToByteArray("3040a00f300d06096086480165030402040500a11c301a06092a864886f70d010108300d06096086480165030402010500a20f300d06092a864886f70d0101090400"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA1AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d02070500301d0609608648016503040102041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA224AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d02080500301d0609608648016503040102041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA256AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d02090500301d0609608648016503040102041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA384AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d020a0500301d0609608648016503040102041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA512AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d020b0500301d0609608648016503040102041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA1AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02070500301d060960864801650304012a041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA224AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02080500301d060960864801650304012a041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA256AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02090500301d060960864801650304012a041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA384AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d020a0500301d060960864801650304012a041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                "PBEWithHmacSHA512AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d020b0500301d060960864801650304012a041012341234123412341234123412341234"),
                false
            },
            new Object[] {
                // PBEWithHmacSHA1AndAES_128 - in which OPTIONAL KeyLength and DEFAULT PRF have not been encoded
                "PBES2", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("303c301b06092a864886f70d01050c300e040873616c7431323334020203e8301d0609608648016503040102041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                // PBEWithHmacSHA256AndAES_256
                "PBES2", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02090500301d060960864801650304012a041012341234123412341234123412341234"),
                false
            },

            // Legacy JDK 8 encoding of PBES2 parameters
            new Object[] {
                "PBEWithHmacSHA1AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d02070500301d0609608648016503040102041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA224AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d02080500301d0609608648016503040102041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA256AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d02090500301d0609608648016503040102041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA384AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d020a0500301d0609608648016503040102041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA512AndAES_128", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020110300c06082a864886f70d020b0500301d0609608648016503040102041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA1AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02070500301d060960864801650304012a041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA224AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02080500301d060960864801650304012a041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA256AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02090500301d060960864801650304012a041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA384AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d020a0500301d060960864801650304012a041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                "PBEWithHmacSHA512AndAES_256", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d020b0500301d060960864801650304012a041012341234123412341234123412341234"),
                true
            },
            new Object[] {
                // PBEWithHmacSHA256AndAES_256
                "PBES2", new PBEParameterSpec(SALT, 1000, new IvParameterSpec(AES_IV)),
                hexStringToByteArray("305a06092a864886f70d01050d304d302c06092a864886f70d01050c301f040873616c7431323334020203e8020120300c06082a864886f70d02090500301d060960864801650304012a041012341234123412341234123412341234"),
                true
            },

            new Object[] {
                    "RSASSA-PSS", new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, PSSParameterSpec.TRAILER_FIELD_BC),
                    hexStringToByteArray("3000"),
                    false
            },
            new Object[] {
                    "RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), 32, 1),
                    hexStringToByteArray("3016A00F300D06096086480165030402010500A203020120"),
                    false
            },
            new Object[] {
                    "RSASSA-PSS", new PSSParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), 20, 2),
                    hexStringToByteArray("3005A303020102"),
                    false
            },
            new Object[] {
                    "RSASSA-PSS", new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 0, 0),
                    hexStringToByteArray("300AA203020100A303020100"),
                    false
            },
            new Object[] {
                    "RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-384"), 64, 2),
                    hexStringToByteArray("3039A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402020500A203020140A303020102"),
                    false
            }
        ));

        return data;
    }

    private final String alg;
    private final AlgorithmParameterSpec spec;
    private final byte[] der;
    private final boolean isAltDer;

    private AlgorithmParameters params;

    public AlgParametersTest(String alg, AlgorithmParameterSpec spec, byte[] der, boolean isAltDer) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.toUpperCase().contains("DESEDE"));
        this.alg = alg;
        this.spec = spec;
        this.der = der;
        this.isAltDer = isAltDer;
    }

    @Before
    public void setUp() throws Exception {
        params = ProviderUtil.getAlgorithmParameters(this.alg);
    }

    @Test
    public void initGetEncoded() throws Exception {
        Assume.assumeFalse("Alternate DER encoding", this.isAltDer);
        params.init(der);
        byte[] enc = params.getEncoded();
        assertArrayEquals(der, enc);
        assertArrayEquals(der, params.getEncoded("ASN.1"));
    }

    @Test
    public void initEncodingGetSpec() throws Exception {
        params.init(der);
        checkSpec(params.getParameterSpec(this.spec.getClass()));
    }

    private void checkSpec(AlgorithmParameterSpec aspec) {
        if (this.spec instanceof IvParameterSpec) {
            assertArrayEquals(((IvParameterSpec) this.spec).getIV(), ((IvParameterSpec) aspec).getIV());
        } else if (this.spec instanceof GCMParameterSpec) {
            assertArrayEquals(((GCMParameterSpec) this.spec).getIV(), ((GCMParameterSpec) aspec).getIV());
            assertEquals(((GCMParameterSpec) this.spec).getTLen(), ((GCMParameterSpec) aspec).getTLen());
        } else if (this.spec instanceof OAEPParameterSpec thisSpec) {
            OAEPParameterSpec oSpec = (OAEPParameterSpec) aspec;
            assertEquals(thisSpec.getDigestAlgorithm(), oSpec.getDigestAlgorithm());
            assertEquals(thisSpec.getMGFAlgorithm(), oSpec.getMGFAlgorithm());
            assertEquals(((MGF1ParameterSpec) thisSpec.getMGFParameters()).getDigestAlgorithm(), ((MGF1ParameterSpec) oSpec.getMGFParameters()).getDigestAlgorithm());
            assertArrayEquals(((PSource.PSpecified) thisSpec.getPSource()).getValue(), ((PSource.PSpecified) oSpec.getPSource()).getValue());
        } else if (this.spec instanceof PBEParameterSpec thisPbeSpec) {
            IvParameterSpec thisIvSpec = (IvParameterSpec) thisPbeSpec.getParameterSpec();
            PBEParameterSpec oPbeSpec = (PBEParameterSpec) aspec;
            IvParameterSpec oIvSpec = (IvParameterSpec) oPbeSpec.getParameterSpec();
            assertArrayEquals(thisPbeSpec.getSalt(), oPbeSpec.getSalt());
            assertEquals(thisPbeSpec.getIterationCount(), oPbeSpec.getIterationCount());
            if (thisIvSpec == null) {
                assertNull(oIvSpec);
            } else {
                assertArrayEquals(thisIvSpec.getIV(), oIvSpec.getIV());
            }
        } else if (this.spec instanceof PSSParameterSpec thisSpec) {
            PSSParameterSpec pSpec = (PSSParameterSpec) aspec;
            assertEquals(thisSpec.getDigestAlgorithm(), pSpec.getDigestAlgorithm());
            assertEquals(thisSpec.getMGFAlgorithm(), pSpec.getMGFAlgorithm());
            assertEquals(((MGF1ParameterSpec) thisSpec.getMGFParameters()).getDigestAlgorithm(), ((MGF1ParameterSpec) pSpec.getMGFParameters()).getDigestAlgorithm());
            assertEquals(thisSpec.getSaltLength(), pSpec.getSaltLength());
            assertEquals(thisSpec.getTrailerField(), pSpec.getTrailerField());
        }
    }

    @Test
    public void initEncodingFormatGetSpec() throws Exception {
        params.init(der, "ASN.1");
        checkSpec(params.getParameterSpec(this.spec.getClass()));
    }

    @Test
    public void initGetParameterSpec() throws Exception {
        params.init(this.spec);
        checkSpec(params.getParameterSpec(this.spec.getClass()));
    }

    @Test
    public void initSpecGetEncoded() throws Exception {
        Assume.assumeFalse("Alternate DER encoding", this.isAltDer);
        params.init(this.spec);
        if (this.alg.equals("PBES2")) {
            return;
        }
        assertArrayEquals(der, params.getEncoded());
    }

    /**
     * Only testing of toString after init() is required since AlgorithmParameters.toString()
     * return null if init() has not been called.
     */
    @Test
    public void testToString() throws Exception {
        params.init(this.spec);
        String s = params.toString();
        if (this.spec instanceof IvParameterSpec) {
            assertEquals(this.alg + " Parameters [ iv = " + TestUtil.bytesToHex(((IvParameterSpec) spec).getIV()) + "]", s);
        } else if (this.spec instanceof GCMParameterSpec) {
            assertEquals(this.alg + " Parameters [ tagLen = " + ((GCMParameterSpec)this.spec).getTLen() + ", iv = " + TestUtil.bytesToHex(((GCMParameterSpec) spec).getIV()) + "]", s);
        } else if (this.spec instanceof OAEPParameterSpec) {
            assertTrue(s.startsWith("OAEP Parameters [ "));
        } else if (this.spec instanceof PBEParameterSpec) {
            if (this.alg.startsWith("PBEWithHmac")) {
                assertEquals(this.alg, s);
            } else if (this.alg.equals("PBES2")) {
                assertNull(s);
            } else {
                // "PBEWithSHA1AndDESede" or "PBE"
                assertTrue(s.startsWith("PBE Parameters [ salt="));
            }
        } else if (this.spec instanceof PSSParameterSpec) {
            assertTrue(s.startsWith("RSASSA-PSS Parameters [ "));
        }
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initBadSpec() throws Exception {
        params.init(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void getParameterSpecNull() throws Exception {
        params.init(this.spec);
        params.getParameterSpec(null);
    }

    @Test
    public void getParameterSpecInterfaceAlgorithmParameterSpec() throws Exception {
        params.init(this.spec);
        AlgorithmParameterSpec getSpec = params.getParameterSpec(AlgorithmParameterSpec.class);
        checkSpec(getSpec);
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void getParameterSpecBadSpec() throws Exception {
        params.init(this.spec);
        params.getParameterSpec(RSAKeyGenParameterSpec.class);
    }

}
