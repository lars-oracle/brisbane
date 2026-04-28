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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.MdCtx.Signature.PssParams;
import com.oracle.jipher.internal.openssl.Pkey;

/**
 * Abstract base class implementation of {@link java.security.SignatureSpi}
 * for RSA-PSS with digest signatures.
 */
public abstract class RsaPssDigestSig extends RsaDigestSig {

    private int saltLen;
    private boolean saltLenSet;

    /**
     * Constructor with specified digest type and default salt length.
     * @param md the message digest type
     * @param saltLen the default salt length of the digest
     */
    RsaPssDigestSig(MdAlg md, int saltLen) {
        super(md);
        this.saltLen = saltLen;
        this.saltLenSet = false;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (!this.isInitialized || this.ctx == null) {
            throw new IllegalStateException("Object not initialized");
        }
        if (!(params instanceof PSSParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException("Must be PSSParameterSpec");
        }
        MdAlg specMd = MdAlg.byName(spec.getDigestAlgorithm());
        if (specMd != this.md) {
            throw new InvalidAlgorithmParameterException("Digest algorithm must match signature digest: " + this.md.getAlg());
        }
        RsaPssGeneralSig.verifyParams(this.md, spec);

        this.saltLen = spec.getSaltLength();
        this.saltLenSet = true;

        try {
            doInit(this.lastPkey, this.initializedForSign);
        } catch (InvalidKeyException e) {
            throw new InvalidAlgorithmParameterException("Invalid key");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", InternalProvider.get());
            params.init(new PSSParameterSpec(this.md.getAlg(), "MGF1", new MGF1ParameterSpec(this.md.getAlg()), this.saltLen, 1));
            return params;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new ProviderException(e);
        }
    }

    @Override
    void doInit(Pkey pkey, boolean isSign) throws InvalidKeyException {
        int saltLen = isSign || this.saltLenSet ? this.saltLen : EVP_PKEY.PKEY_PARAM_VALUE_RSA_PSS_SALTLEN_AUTO;
        doInit(pkey, isSign, new PssParams(saltLen));
    }

    /**
     * RSA-PSS with SHA-1 (for digesting message and MGF).
     */
    public static final class RsaPssSha1 extends RsaPssDigestSig {
        public RsaPssSha1() {
            super(MdAlg.SHA1, 20);
        }
    }

    /**
     * RSA-PSS with SHA-224 (for digesting message and MGF).
     */
    public static final class RsaPssSha224 extends RsaPssDigestSig {
        public RsaPssSha224() {
            super(MdAlg.SHA224, 28);
        }
    }

    /**
     * RSA-PSS with SHA-256 (for digesting message for and MGF).
     */
    public static final class RsaPssSha256 extends RsaPssDigestSig {
        public RsaPssSha256() {
            super(MdAlg.SHA256, 32);
        }
    }

    /**
     * RSA-PSS with SHA-384 (for digesting message and MGF).
     */
    public static final class RsaPssSha384 extends RsaPssDigestSig {
        public RsaPssSha384() {
            super(MdAlg.SHA384, 48);
        }
    }

    /**
     * RSA-PSS with SHA-512 (for digesting message and MGF).
     */
    public static final class RsaPssSha512 extends RsaPssDigestSig {
        public RsaPssSha512() {
            super(MdAlg.SHA512, 64);
        }
    }
}
