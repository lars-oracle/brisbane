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

package com.oracle.systest.fips;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.DhApprovedGroups;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.systest.SysTestUtil.isFipsException;
import static com.oracle.systest.fips.OperationResult.FIPS_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.OTHER_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.SUCCESS;
import static java.security.spec.RSAKeyGenParameterSpec.F4;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class FipsKeyPairGenTest {

    private final String alg;
    private final AlgorithmParameterSpec spec;
    private final int size;
    private final OperationResult expected;

    public FipsKeyPairGenTest(EnvUtil.FipsPolicy policy, String alg, String paramLabel, AlgorithmParameterSpec spec, int size, OperationResult expected) {
        this.alg = alg;
        this.spec = spec;
        this.size = size;
        this.expected = expected;
    }

    @Parameterized.Parameters(name="policy={0}:{1}:{2}:expect={5}")
    public static Collection<Object[]> params() throws Exception {
        List<Object[]> p = new ArrayList<>();
        EnvUtil.FipsPolicy policy = EnvUtil.getPolicy();
        if (policy == EnvUtil.FipsPolicy.NONE) {
            p.add(new Object[] {policy, "RSA", "bits:1024", null, 1024, SUCCESS});
            p.add(new Object[] {policy, "RSA", "bits:2048", null, 2048, SUCCESS});
            p.add(new Object[] {policy, "RSA", "spec:1024", new RSAKeyGenParameterSpec(1024, F4), -1, SUCCESS});
            p.add(new Object[] {policy, "RSA", "spec:2048", new RSAKeyGenParameterSpec(2048, F4), -1, SUCCESS});

            p.add(new Object[] {policy, "EC", "bits:160", null, 160, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "EC", "bits:224", null, 224, SUCCESS});
            p.add(new Object[] {policy, "EC", "spec:secp192r1", new ECGenParameterSpec("secp192r1"), -1, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "EC", "spec:secp224r1", new ECGenParameterSpec("secp224r1"), -1, SUCCESS});

            p.add(new Object[] {policy, "DH", "bits:1024", null, 1024, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "DH", "bits:2048", null, 2048, SUCCESS});
            p.add(new Object[] {policy, "DH", "spec:1536", OtherData.MODP_1536_SPEC, -1, SUCCESS});
            p.add(new Object[] {policy, "DH", "spec:2048", DhApprovedGroups.get().get("ffdhe2048"), -1, SUCCESS});
        } else {
            p.add(new Object[] {policy, "RSA", "bits:1024", null, 1024, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "RSA", "bits:2048", null, 2048, SUCCESS});
            p.add(new Object[] {policy, "RSA", "spec:1024", new RSAKeyGenParameterSpec(1024, F4), -1, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "RSA", "spec:2048", new RSAKeyGenParameterSpec(2048, F4), -1, SUCCESS});

            p.add(new Object[] {policy, "EC", "bits:160", null, 160, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "EC", "bits:224", null, 224, SUCCESS});
            p.add(new Object[] {policy, "EC", "spec:secp192r1", new ECGenParameterSpec("secp192r1"), -1, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "EC", "spec:secp224r1", new ECGenParameterSpec("secp224r1"), -1, SUCCESS});

            p.add(new Object[] {policy, "DH", "bits:1024", null, 1024, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "DH", "spec:1536", OtherData.MODP_1536_SPEC, -1, OTHER_EXCEPTION});
            p.add(new Object[] {policy, "DH", "bits:2048", null, 2048, SUCCESS});
            p.add(new Object[] {policy, "DH", "spec:2048", DhApprovedGroups.get().get("ffdhe2048"), -1, SUCCESS});
        }
        return p;
    }

    @Test
    public void keyPairGen() throws Exception {
        try {
            KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(this.alg);
            if (this.spec != null) {
                kpg.initialize(this.spec);
            } else {
                kpg.initialize(this.size);
            }
            assertEquals("JipherJCE", kpg.getProvider().getName());
            assertEquals(this.expected, SUCCESS);
        } catch (InvalidAlgorithmParameterException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
        }
    }
}
