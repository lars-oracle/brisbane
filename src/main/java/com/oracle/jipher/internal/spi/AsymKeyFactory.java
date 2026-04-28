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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.oracle.jipher.internal.common.Util;


/**
 * Parent class for KeyFactorySpi implementation.
 */
abstract class AsymKeyFactory extends KeyFactorySpi {

    @Override
    protected abstract Key engineTranslateKey(Key key) throws InvalidKeyException;

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            byte[] privDer = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            try {
                return generatePrivateInternal(privDer);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException("Could not decode private key", e);
            } finally {
                Util.clearArray(privDer);
            }
        } else {
            throw new InvalidKeySpecException("Cannot create private key from " + keySpec.getClass());
        }
    }

    abstract PrivateKey generatePrivateInternal(byte[] privDer) throws InvalidKeyException;

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            byte[] pubDer = ((X509EncodedKeySpec) keySpec).getEncoded();
            try {
                return generatePublicInternal(pubDer);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException("Could not decode public key", e);
            }
        } else {
            throw new InvalidKeySpecException("Cannot create public key from " + keySpec.getClass());
        }
    }

    abstract PublicKey generatePublicInternal(byte[] pubDer) throws InvalidKeyException;

    Key translatePrivate(PrivateKey privKey) throws InvalidKeyException {
        return generatePrivateInternal(privKey.getEncoded());
    }

    Key translatePublic(PublicKey pubKey) throws InvalidKeyException {
        return generatePublicInternal(pubKey.getEncoded());
    }

}
