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

import java.security.MessageDigestSpi;

import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.MdCtx;

/**
 * Abstract implementation of {@link MessageDigestSpi} containing the core
 * implementation. Subclasses for specific algorithm are contained
 * as inner classes.
 */
public abstract class Digest extends MessageDigestSpi implements Cloneable {

    private MdCtx.Digest ctx;
    private final MdAlg alg;
    private final int digestLen;

    Digest(MdAlg mdAlg, int digestLen) {
        super();
        this.digestLen = digestLen;
        this.alg = mdAlg;
    }

    @Override
    protected void engineReset() {
        releaseCtx();
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected int engineGetDigestLength() {
        return this.digestLen;
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        initializeIfRequired();
        this.ctx.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        initializeIfRequired();
        try {
            byte[] output = new byte[this.digestLen];
            this.ctx.digest(output, 0);
            return output;
        } finally {
            releaseCtx();
        }
    }

    private void initializeIfRequired() {
        if (this.ctx == null) {
            this.ctx = new MdCtx.Digest();
            this.ctx.init(this.alg);
        }
    }

    private void releaseCtx() {
        MdCtx.Digest ctxToRelease = this.ctx;
        if (ctxToRelease != null) {
            this.ctx = null;
            ctxToRelease.release();
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        Digest clone = (Digest) super.clone();
        if (this.ctx != null) {
            clone.ctx = new MdCtx.Digest(this.ctx);
        }
        return clone;
    }

    /** SHA-1 */
    public static final class Sha1 extends Digest {
        public Sha1() {
            super(MdAlg.SHA1, 20);
        }
    }

    /** SHA-224 */
    public static final class Sha224 extends Digest {
        public Sha224() {
            super(MdAlg.SHA224, 28);
        }
    }

    /** SHA-256 */
    public static final class Sha256 extends Digest {
        public Sha256() {
            super(MdAlg.SHA256, 32);
        }
    }

    /** SHA-384 */
    public static final class Sha384 extends Digest {
        public Sha384() {
            super(MdAlg.SHA384, 48);
        }
    }

    /** SHA-512 */
    public static final class Sha512 extends Digest {
        public Sha512() {
            super(MdAlg.SHA512, 64);
        }
    }

    /** SHA3-224 */
    public static final class Sha3_224 extends Digest {
        public Sha3_224() {
            super(MdAlg.SHA3_224, 28);
        }
    }

    /** SHA3-256 */
    public static final class Sha3_256 extends Digest {
        public Sha3_256() {
            super(MdAlg.SHA3_256, 32);
        }
    }

    /** SHA3-384 */
    public static final class Sha3_384 extends Digest {
        public Sha3_384() {
            super(MdAlg.SHA3_384, 48);
        }
    }

    /** SHA3-512 */
    public static final class Sha3_512 extends Digest {
        public Sha3_512() {
            super(MdAlg.SHA3_512, 64);
        }
    }

}
