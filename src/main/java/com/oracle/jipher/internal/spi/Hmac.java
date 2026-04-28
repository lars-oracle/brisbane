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

import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.MacCtx;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.common.Util.clearArray;
import static com.oracle.jipher.internal.fips.CryptoOp.MAC;

/**
 * Implementation of {@link MacSpi} for HMAC.
 */
public abstract class Hmac extends MacSpi implements Cloneable {

    /**
     * Cleaner instance.
     */
    private static final Cleaner CLEANER_INSTANCE = Cleaner.create();

    record State(byte[] keyData) implements Runnable {
        public void run() {
            clearArray(this.keyData);
        }
    }

    private State state;
    private Cleaner.Cleanable cleanable;
    final int macLen;
    final MdAlg mdAlg;
    private MacCtx.Hmac ctx;
    private boolean reInitPending;

    Hmac(MdAlg mdAlg, int macLen) {
        this.mdAlg = mdAlg;
        this.macLen = macLen;
    }

    @Override
    protected int engineGetMacLength() {
        return this.macLen;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (this.state != null) {
            if (this.cleanable != null) {
                this.cleanable.clean();
            }
            this.state = null;
            this.cleanable = null;
        }
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Expected SecretKey");
        }
        if (algorithmParameterSpec != null) {
            throw new InvalidAlgorithmParameterException("Did not expect parameters");
        }
        byte[] kb = key.getEncoded();
        try {
            Fips.enforcement().checkStrength(MAC, "HMAC", kb.length * 8);
            initInternal(kb);
            this.state = new State(kb);
            this.cleanable = CLEANER_INSTANCE.register(this, this.state);
            this.reInitPending = false;
            kb = null;
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        } finally {
            clearArray(kb);
        }
    }

    private void initInternal(byte[] key) throws InvalidKeyException {
        if (this.ctx == null) {
            this.ctx = new MacCtx.Hmac(this.mdAlg);
        }
        boolean initialized = false;
        try {
            this.ctx.init(key);
            initialized = true;
        } finally {
            if (!initialized) {
                releaseCtx();
            }
        }
    }

    private void reInitIfNecessary() {
        if (this.state == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (this.reInitPending) {
            reInit();
        }
    }

    @Override
    protected void engineUpdate(byte b) {
        engineUpdate(new byte[]{b},0,1);
    }

    @Override
    protected void engineUpdate(byte[] bytes, int offset, int len) {
        reInitIfNecessary();
        this.ctx.update(bytes, offset, len);
    }

    @Override
    protected void engineReset() {
        this.reInitPending = true;
        releaseCtx();
    }

    @Override
    protected byte[] engineDoFinal() {
        reInitIfNecessary();
        try {
            byte[] output = new byte[this.macLen];
            int len = this.ctx.mac(output, 0);
            if (output.length == len) {
                return output;
            } else {
                return Arrays.copyOf(output, len);
            }
        } finally {
            this.reInitPending = true;
            releaseCtx();
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        Hmac clone = (Hmac) super.clone();
        if (this.ctx != null) {
            clone.ctx = new MacCtx.Hmac(this.ctx);
        }
        if (this.state != null) {
            // Copy key data inside state and create new state
            byte[] kb = this.state.keyData.clone();
            clone.state = new State(kb);

            // Register cleaner for the new state
            clone.cleanable = CLEANER_INSTANCE.register(clone, clone.state);
        }

        return clone;
    }

    private void reInit() {
        try {
            initInternal(this.state.keyData);
            Reference.reachabilityFence(this);
            this.reInitPending = false;
        } catch (InvalidKeyException e) {
            throw new ProviderException("Unexpected exception", e);
        }
    }

    private void releaseCtx() {
        MacCtx ctxToRelease = this.ctx;
        if (ctxToRelease != null) {
            this.ctx = null;
            ctxToRelease.release();
        }
    }

    /** HMAC-SHA1 */
    public static class HmacSha1 extends Hmac {
        public HmacSha1() {
            super(MdAlg.SHA1, 20);
        }
    }

    /** HMAC-SHA224 */
    public static class HmacSha224 extends Hmac {
        public HmacSha224() {
            super(MdAlg.SHA224, 28);
        }
    }

    /** HMAC-SHA256 */
    public static class HmacSha256 extends Hmac {
        public HmacSha256() {
            super(MdAlg.SHA256, 32);
        }
    }

    /** HMAC-SHA384 */
    public static class HmacSha384 extends Hmac {
        public HmacSha384() {
            super(MdAlg.SHA384, 48);
        }
    }

    /** HMAC-SHA512 */
    public static class HmacSha512 extends Hmac {
        public HmacSha512() {
            super(MdAlg.SHA512, 64);
        }
    }
}
