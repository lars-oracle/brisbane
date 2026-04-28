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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jipher.internal.openssl.EcCurve;

/**
 * Implementation of {@link AlgorithmParametersSpi} for elliptic curves.
 */
public final class EcParameters extends AlgorithmParametersSpi {

    private ECParameterSpec spec;

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(ECParameterSpec.class)) {
            return paramSpec.cast(spec);
        } else if (paramSpec != null && paramSpec.isAssignableFrom(ECGenParameterSpec.class)) {
            EcCurve curveParams = NamedCurves.lookup(this.spec);
            if (curveParams == null) {
                throw new InvalidParameterSpecException("Could not get ECGenParameterSpec for these parameters.");
            }
            return paramSpec.cast(new ECGenParameterSpec(curveParams.oid()));
        } else {
            throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from ECParameterSpec or ECGenParameterSpec");
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        this.spec = NamedCurves.decodeParams(params);
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        this.spec = NamedCurves.decodeParams(params);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof ECGenParameterSpec) {
            this.spec = NamedCurves.lookup(((ECGenParameterSpec) paramSpec).getName());
            if (this.spec == null) {
                throw new InvalidParameterSpecException("Unsupported EC curve name");
            }
        } else if (paramSpec instanceof ECParameterSpec) {
            this.spec = (ECParameterSpec) paramSpec;
        } else {
            throw new InvalidParameterSpecException("Invalid parameter spec for EC parameters");
        }
    }

    @Override
    protected String engineToString() {
        return "EC Parameters (" + NamedCurves.lookup(this.spec) + ")";
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        return NamedCurves.getEncoded(this.spec);
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return NamedCurves.getEncoded(this.spec);
    }
}
