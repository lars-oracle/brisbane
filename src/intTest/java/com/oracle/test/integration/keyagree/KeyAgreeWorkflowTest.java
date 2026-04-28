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

package com.oracle.test.integration.keyagree;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

@RunWith(Parameterized.class)
public class KeyAgreeWorkflowTest {

    @Parameterized.Parameters(name = "{0}[{index}]")
    public static Collection<Object[]> data() throws Exception {
        List<Object[]> data = new ArrayList<>();
        data.add(new Object[]{"DH", null, "DH", 2048});
        data.add(new Object[]{"DH", null, "DH", 3072});
        data.add(new Object[]{"DH", null, "DH", 4096});
        data.add(new Object[]{"ECDH", null, "EC", 256});
        data.add(new Object[]{"ECDH", null, "EC", 384});
        data.add(new Object[]{"ECDH", null, "EC", 521});
        data.add(new Object[]{"ECDH", null, "EC", new ECGenParameterSpec("secp256r1")});
        data.add(new Object[]{"ECDH", null, "EC", new ECGenParameterSpec("secp384r1")});
        data.add(new Object[]{"ECDH", null, "EC", new ECGenParameterSpec("P-521")});

        data.add(new Object[]{"DH", TestData.getFirst(KeyPairTestData.class, alg("DH").secParam("2048")), null, null});
        data.add(new Object[]{"DH", TestData.getFirst(KeyPairTestData.class, alg("DH").secParam("ffdhe3072")), null, null});
        data.add(new Object[]{"ECDH", TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1")), null, null});
        data.add(new Object[]{"ECDH", TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp384r1")), null, null});
        data.add(new Object[]{"ECDH", TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp521r1")), null, null});
        return data;
    }

    private final String alg;
    private final KeyPairTestData kp;
    private final String kpAlg;
    private final Object kpgInitObject;

    private PrivateKey priv1;
    private PublicKey pub1;
    private PrivateKey priv2;
    private PublicKey pub2;


    public KeyAgreeWorkflowTest(String alg, KeyPairTestData kp, String kpAlg, Object genInit) throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported() ||
                !usesFIPS140_4TypeDomainParameters(kp));
        this.alg = alg;
        this.kp = kp;
        this.kpAlg = kpAlg;
        this.kpgInitObject = genInit;
    }

    private static boolean usesFIPS140_4TypeDomainParameters(KeyPairTestData kp) {
        if (kp == null) {
            return false;
        }
        if (kp.getAlg().equals("DH")) {
            return !(kp.getSecParam().startsWith("MODP-") || kp.getSecParam().startsWith("ffdhe"));
        }
        return false;
    }

    @Before
    public void setUp() throws Exception {
        if (this.kp != null) {
            this.priv1 = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
            this.pub1 = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
        } else {
            KeyPair keyPair = generateKp();
            this.priv1 = keyPair.getPrivate();
            this.pub1 = keyPair.getPublic();
        }

        KeyPair keyPair = generateKp();
        this.pub2 = keyPair.getPublic();
        this.priv2 = keyPair.getPrivate();
    }

    private KeyPair generateKp() throws Exception {
        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(kpAlg == null ? this.priv1.getAlgorithm() : this.kpAlg);
        if (this.kp != null) {
            if (this.alg.equals("ECDH")) {
                kpg.initialize(((ECPublicKey) this.pub1).getParams());
            } else {
                kpg.initialize(((DHPublicKey) this.pub1).getParams());
            }
        } else if (this.kpgInitObject instanceof Integer) {
            kpg.initialize((Integer) this.kpgInitObject);
        } else {
            kpg.initialize((AlgorithmParameterSpec) this.kpgInitObject);
        }
        return kpg.generateKeyPair();
    }

    @Test
    public void keyAgreement() throws Exception {
        KeyAgreement ka1 = ProviderUtil.getKeyAgreement(this.alg);
        ka1.init(this.priv1);
        assertNull(ka1.doPhase(this.pub2, true));
        byte[] result1 = ka1.generateSecret();

        KeyAgreement ka2 = ProviderUtil.getKeyAgreement(this.alg);
        ka2.init(this.priv2);
        assertNull(ka2.doPhase(this.pub1, true));
        byte[] result2 = ka2.generateSecret();

        assertArrayEquals(result1, result2);
    }
}
