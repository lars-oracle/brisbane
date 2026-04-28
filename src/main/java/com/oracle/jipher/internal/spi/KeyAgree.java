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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jipher.internal.common.TripleDesUtil;
import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.key.JceDhPrivateKey;
import com.oracle.jipher.internal.key.JceDhPublicKey;
import com.oracle.jipher.internal.key.JceEcPrivateKey;
import com.oracle.jipher.internal.key.JceEcPublicKey;
import com.oracle.jipher.internal.key.JceOsslKey;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.openssl.PkeyCtx;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Parent class for {@link KeyAgreementSpi} implementations.
 */
public abstract class KeyAgree extends KeyAgreementSpi {

    /**
     * Cleaner instance.
     */
    private static final Cleaner CLEANER_INSTANCE = Cleaner.create();

    static final class State implements Runnable {
        private final byte[] secret;

        State(byte[] secret) {
            this.secret = secret;
        }

        public void run() {
            clearArray(this.secret);
        }
    }

    private State state;
    private Cleaner.Cleanable cleanable;
    private Pkey pkey;

    @Override
    protected void engineInit(Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            engineInit(key, null, secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    /**
     * Check that the private key and parameters are valid for this KeyAgree, and return a {@link JceOsslKey} representation of it.
     * @param privKey the private key to check
     * @param spec the parameters to check against
     * @return a {@link JceOsslKey}
     * @throws InvalidKeyException if the key is invalid
     * @throws InvalidAlgorithmParameterException if the parameters are invalid
     */
    abstract JceOsslKey checkPrivateKey(PrivateKey privKey, AlgorithmParameterSpec spec)
            throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Check that the public key is valid for this KeyAgree, and return a {@link Pkey} representation of it.
     * @param pubKey the public key to check
     * @return a {@link Pkey}
     * @throws InvalidKeyException if the key is invalid
     */
    abstract Pkey checkPublicKey(PublicKey pubKey) throws InvalidKeyException;

    /**
     * Creates a TlsPremasterSecret Key from secret key material
     * @param secret the secret key material to use
     * @return a {@link SecretKey} suitable for use by the JSSE
     */
    abstract SecretKey createTlsPremasterSecretKey(byte[] secret);

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            if (!(key instanceof PrivateKey)) {
                throw new InvalidKeyException("Expected PrivateKey");
            }
            JceOsslKey priv = checkPrivateKey((PrivateKey) key, algorithmParameterSpec);
            Fips.enforcement().checkStrength(CryptoOp.KEYAGREE, priv);

            // If priv is a java reference to the original key (no key translation took place)
            // then create a native reference to the original PKEY so that this service object
            // will be independent of the original key (which the application might destroy)
            initInternal(priv == key ? Pkey.createReference(priv.getPkey()) : priv.getPkey());
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    private void initInternal(Pkey pkey) {
        if (this.state != null) {
            clearSecret();
        }
        if (this.pkey != null) {
            // Free the EVP_PKEY now rather than wait for GC to do so eventually.
            // If the EVP_PKEY was created by key translation then it will be freed otherwise
            // if the EVP_PKEY was created by creating a reference the reference count will be decremented.
            this.pkey.free();
        }
        this.pkey = pkey;
    }

    private void checkInitialized() {
        if (this.pkey == null) {
            throw new IllegalStateException("KeyAgreement not initialized.");
        }
    }

    @Override
    protected Key engineDoPhase(Key peerKey, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (!lastPhase) {
            throw new IllegalStateException("Multi-party key agreement not supported.");
        }
        checkInitialized();
        if (this.state != null) {
            clearSecret();
        }
        if (!(peerKey instanceof PublicKey peerPublicKey)) {
            throw new InvalidKeyException("Expected PublicKey for doPhase");
        }
        try (OsslArena confinedArena = OsslArena.ofConfined()) {
            PkeyCtx.Derive ctx = new PkeyCtx.Derive(pkey, confinedArena);
            Pkey pub = checkPublicKey(peerPublicKey);
            this.state = new State(ctx.derive(pub));
            this.cleanable = CLEANER_INSTANCE.register(this, this.state);
            return null;
        }
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (this.state == null) {
            throw new IllegalStateException("secret not generated.");
        }
        byte[] ret = this.state.secret.clone();
        clearSecret();
        return ret;
    }

    @Override
    protected int engineGenerateSecret(byte[] output, int offset) throws IllegalStateException, ShortBufferException {
        if (this.state == null) {
            throw new IllegalStateException("secret not generated.");
        }
        int len = this.state.secret.length;
        if (offset < 0 || len > output.length - offset) {
            throw new ShortBufferException("output buffer too short.");
        }
        System.arraycopy(this.state.secret, 0, output, offset, len);
        clearSecret();
        return len;
    }

    private void clearSecret() {
        if (this.cleanable != null) {
            this.cleanable.clean();
        }
        this.state = null;
        this.cleanable = null;
    }

    @Override
    protected SecretKey engineGenerateSecret(String alg) throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException {
        if (this.state == null) {
            throw new IllegalStateException("secret not generated.");
        }
        try {
            if (alg.equalsIgnoreCase("AES")) {
                // Generate the strongest possible AES key using the available key material
                SecretKeySpec secretKeySpec = null;
                for (int keyLength : new int[]{32, 24, 16}) {
                    if (this.state.secret.length >= keyLength) {
                        secretKeySpec = new SecretKeySpec(this.state.secret, 0, keyLength, alg);
                        break;
                    }
                }
                if (secretKeySpec == null) {
                    throw new InvalidKeyException("Key material is too short");
                }
                return secretKeySpec;
            } else if (alg.equalsIgnoreCase("DESede") || alg.equalsIgnoreCase("TripleDES")) {
                return TripleDesUtil.createKey(this.state.secret);
            } else if (alg.equals("TlsPremasterSecret")) {
                return createTlsPremasterSecretKey(this.state.secret);
            } else {
                throw new NoSuchAlgorithmException("Unsupported secret key algorithm: " + alg);
            }
        } finally {
            clearSecret();
        }
    }

    /**
     * Elliptic Curve Diffie-Hellman KeyAgreement.
     */
    public static class ECDH extends KeyAgree {

        private final EcKeyFactory kf = new EcKeyFactory();

        @Override
        JceOsslKey checkPrivateKey(PrivateKey privKey, AlgorithmParameterSpec params)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            JceEcPrivateKey ecPriv = null;

            if (privKey instanceof ECPrivateKey ecPrivKey) {

                // 'Dummy' ECPrivateKey's that override getS() and/or getParams()
                // to be null will be handled by translatePrivate() below
                if (ecPrivKey.getS() != null && ecPrivKey.getParams() != null) {
                    ECPrivateKeySpec ecSpec = new ECPrivateKeySpec(ecPrivKey.getS(), ecPrivKey.getParams());

                    try {
                        ecPriv = (JceEcPrivateKey) this.kf.engineGeneratePrivate(ecSpec);
                    } catch (InvalidKeySpecException e) {
                        throw new InvalidKeyException(e);
                    }
                }
            }
            if (ecPriv == null) {
                ecPriv = (JceEcPrivateKey) this.kf.translatePrivate(privKey);
            }
            if (params != null) {
                if (!(params instanceof ECParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("Parameters did not match key parameters");
                }
                if (!NamedCurves.paramsEquals(ecPriv.getParams(), (ECParameterSpec) params)) {
                    throw new InvalidAlgorithmParameterException("Parameters did not match key parameters");
                }
            }
            return ecPriv;
        }

        @Override
        Pkey checkPublicKey(PublicKey pubKey) throws InvalidKeyException {
            JceEcPublicKey ecPriv = (JceEcPublicKey) this.kf.engineTranslateKey(pubKey);
            return ecPriv.getPkey();
        }

        @Override
        SecretKey createTlsPremasterSecretKey(byte[] secret) {
            return new SecretKeySpec(secret, "TlsPremasterSecret");
        }
    }

    /**
     * Diffie-Hellman KeyAgreement.
     */
    public static class DH extends KeyAgree {

        private final DhKeyFactory kf = new DhKeyFactory();

        @Override
        JceOsslKey checkPrivateKey(PrivateKey privKey, AlgorithmParameterSpec params)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            JceDhPrivateKey dhPriv = (JceDhPrivateKey) this.kf.engineTranslateKey(privKey);
            if (params != null) {
                if (!(params instanceof DHParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("Parameters did not match key parameters");
                }
                if (!paramsEquals(dhPriv.getParams(), (DHParameterSpec) params)) {
                    throw new InvalidAlgorithmParameterException("Parameters did not match key parameters");
                }
            }
            return dhPriv;
        }

        @Override
        Pkey checkPublicKey(PublicKey pubKey) throws InvalidKeyException {
            JceDhPublicKey dhPriv = (JceDhPublicKey) this.kf.engineTranslateKey(pubKey);
            return dhPriv.getPkey();
        }

        @Override
        SecretKey createTlsPremasterSecretKey(byte[] secret) {
            // For DH, the JSSE does not handle TLS pre-master secret keys with leading zeros.
            // Strip leading bytes that contain all zero bits as specified in RFC-5246 section 8.1.2
            if (secret == null) {
                throw new IllegalArgumentException("Secret key material must not be null");
            }
            if (secret.length != 0 && secret[0] == 0) {
                int index = 1;
                while ((index < secret.length) && (secret[index] == 0)) {
                    index++;
                }
                return new SecretKeySpec(secret, index, secret.length - index, "TlsPremasterSecret");
            } else {
                return new SecretKeySpec(secret, "TlsPremasterSecret");
            }
        }

        boolean paramsEquals(DHParameterSpec spec1, DHParameterSpec spec2) {
            if (!spec1.getP().equals(spec2.getP())) {
                return false;
            }
            return spec1.getG().equals(spec2.getG());
        }
    }
}
