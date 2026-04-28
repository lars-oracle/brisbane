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
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.MdCtx.Signature.PssParams;
import com.oracle.jipher.internal.openssl.Pkey;


/**
 * Implementation of {@link java.security.SignatureSpi} for RSA-PSS with digest signatures.
 *
 * <p>This implementation differs from the other RSA PSS implementations in that:
 * <ol>
 *     <li>digest is not known until {@code engineSetParameter} is set</li>
 *     <li>{@code engineSetParameter} can be called before {@code engineInitSign}
 *          or {@code engineInitVerify} is called</li>
 * </ol>
 */
public final class RsaPssGeneralSig extends RsaDigestSig {

    // Keep track whether engineInitSign/engineInitVerify has been called.
    private boolean initCalled = false;

    // Keep track of whether engineInit called for sign or verify
    private boolean initSign = false;

    // Keep track of whether update is in progress.
    private boolean updateInProgress = false;
    private int saltLen;

    static void verifyParams(MdAlg md, PSSParameterSpec spec) throws InvalidAlgorithmParameterException {
        int digestLength = (md == MdAlg.SHA1) ? 20 :  Integer.parseInt(md.getAlg().split("-")[1]) / 8;
        if (spec.getSaltLength() > digestLength) {
            throw new InvalidAlgorithmParameterException("PSS salt length must not be larger than the digest size");
        }
        if (!spec.getMGFAlgorithm().equals("MGF1")) {
            throw new InvalidAlgorithmParameterException("Only MGF1 supported as MGF algorithm");
        }
        if (!(spec.getMGFParameters() instanceof MGF1ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Expected MGF1ParameterSpec");
        }
        MdAlg mgfMd = MdAlg.byName(((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());
        if (mgfMd != md) {
            throw new InvalidAlgorithmParameterException("MGF1ParameterSpec digest must match signature digest.");
        }
        if (spec.getTrailerField() != 1) {
            throw new InvalidAlgorithmParameterException("Unsupported TrailerField option, must be 1");
        }
    }

    /**
     * Constructor. Pass in null as digest, since it will not be
     * known until {@code engineSetParameter} is called.
     */
    public RsaPssGeneralSig() {
        super(null);
    }

    @Override
    protected void engineUpdate(byte[] data, int off, int len) throws SignatureException {
        if (!this.isInitialized) {
            throw new SignatureException("PSS parameters have not been set.");
        }
        super.engineUpdate(data, off, len);
        this.updateInProgress = true;
    }

    @Override
    public byte[] engineSign() throws SignatureException {
        if (!this.isInitialized) {
            throw new SignatureException("PSS parameters have not been set.");
        }
        this.updateInProgress = false;
        return super.engineSign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int len) throws SignatureException {
        if (!this.isInitialized) {
            throw new SignatureException("PSS parameters have not been set.");
        }
        this.updateInProgress = false;
        return super.engineVerify(sigBytes, offset, len);

    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        super.engineInitSign(privateKey);
        this.initCalled = true;
        this.initSign = true;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        super.engineInitVerify(publicKey);
        this.initCalled = true;
        this.initSign = false;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (this.updateInProgress) {
            throw new ProviderException("Cannot call setParameter during signature operation.");
        }
        if (!(params instanceof PSSParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException("Must be PSSParameterSpec");
        }
        this.md = MdAlg.byName(spec.getDigestAlgorithm());

        try {
            Fips.enforcement().checkAlg(this.initSign  ? CryptoOp.SIGN : CryptoOp.VERIFY, this.md.getAlg());
        } catch (FIPSPolicyException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }

        verifyParams(this.md, spec);
        this.saltLen = spec.getSaltLength();

        if (this.initCalled) {
            // initSign or initVerify has been called, so try to init.
            try {
                doInit(this.lastPkey, this.initSign);
            } catch (InvalidKeyException e) {
                throw new InvalidAlgorithmParameterException("Invalid key");
            }
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        try {
            if (this.md == null) {
                throw new ProviderException("Digest algorithm not yet set");
            }
            AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", InternalProvider.get());
            params.init(new PSSParameterSpec(this.md.getAlg(), "MGF1", new MGF1ParameterSpec(this.md.getAlg()), this.saltLen, 1));
            return params;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new ProviderException(e);
        }
    }

    @Override
    void doInit(Pkey pkey, boolean isSign) throws InvalidKeyException {
        if (this.md == null) {
            // We can't create the ctx since digest not known yet, so just store the pkey and
            // wait to use it for when setParameters is called.
            this.lastPkey = pkey;
        } else {
            // setParameters has been called, so we can do all the init work now.
            doInit(pkey, isSign, new PssParams(this.saltLen));
        }
    }

}
