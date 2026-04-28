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
import java.security.spec.InvalidParameterSpecException;
import java.util.List;
import java.util.Map;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.asn1.UniversalTag;

import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;

/**
 * Base {@link AlgorithmParametersSpi} implementation for PBES2 parameters.
 */
public abstract class Pbes2Parameters extends AlgorithmParametersSpi {

    private static final int AES_BLOCK_SIZE = 16;

    private static final Asn1BerValue ID_PBES2 = newOid("1.2.840.113549.1.5.13");
    private static final Asn1BerValue ID_PBKDF2 = newOid("1.2.840.113549.1.5.12");
    private static final Asn1BerValue ID_AES128_CBC_PAD = newOid("2.16.840.1.101.3.4.1.2");
    private static final Asn1BerValue ID_AES256_CBC_PAD = newOid("2.16.840.1.101.3.4.1.42");
    private static final Asn1BerValue ID_HMAC_WITH_SHA1 = newOid("1.2.840.113549.2.7");
    private static final Asn1BerValue ID_HMAC_WITH_SHA224 = newOid("1.2.840.113549.2.8");
    private static final Asn1BerValue ID_HMAC_WITH_SHA256 = newOid("1.2.840.113549.2.9");
    private static final Asn1BerValue ID_HMAC_WITH_SHA384 = newOid("1.2.840.113549.2.10");
    private static final Asn1BerValue ID_HMAC_WITH_SHA512 = newOid("1.2.840.113549.2.11");

    private static final Map<Asn1BerValue,String> CIPHER_MAP = Map.of(
            ID_AES128_CBC_PAD, "AES_128",
            ID_AES256_CBC_PAD, "AES_256"
    );
    private static final Map<Asn1BerValue,String> PRF_MAP = Map.of(
            ID_HMAC_WITH_SHA1, "HmacSHA1",
            ID_HMAC_WITH_SHA224, "HmacSHA224",
            ID_HMAC_WITH_SHA256, "HmacSHA256",
            ID_HMAC_WITH_SHA384, "HmacSHA384",
            ID_HMAC_WITH_SHA512, "HmacSHA512"
    );

    private Asn1BerValue prfOid;
    private Asn1BerValue cipherOid;
    private PBEParameterSpec pbeSpec;

    Pbes2Parameters(Asn1BerValue prfOid, Asn1BerValue cipherOid) {
        this.prfOid = prfOid;
        this.cipherOid = cipherOid;
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        IvParameterSpec ivSpec = (IvParameterSpec) this.pbeSpec.getParameterSpec();
        if (ivSpec == null) {
            throw new IOException("Wrong parameter type: IV expected");
        }
        byte[] iv = ivSpec.getIV();
        byte[] salt = this.pbeSpec.getSalt();
        int iterationCount = this.pbeSpec.getIterationCount();
        int keyLength = this.cipherOid.equals(ID_AES128_CBC_PAD) ? 16 : 32;

        // PBES2-params
        Asn1BerValue pbes2Params = newSequence(
            // keyDerivationFunc AlgorithmIdentifier
            newSequence(
                ID_PBKDF2,
                // PBKDF2-params
                newSequence(
                    Asn1.newOctetString(salt),
                    Asn1.newInteger(iterationCount),
                    Asn1.newInteger(keyLength), // OPTIONAL
                    // prf
                    newSequence(
                        this.prfOid,
                        Asn1.newNull()
                    )
                )
            ),
            // encryptionScheme AlgorithmIdentifier
            newSequence(
                this.cipherOid,
                // AES-IV
                Asn1.newOctetString(iv)
            )
        );
        return pbes2Params.encodeDerOctets();
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return engineGetEncoded();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(PBEParameterSpec.class)) {
            return paramSpec.cast(this.pbeSpec);
        }
        throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from PBEParameterSpec");
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            Asn1BerValue pbes2Params = Asn1.decodeOne(params).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> pbes2PValues = pbes2Params.count(2).sequence();

            // Check for incorrect DER encoding used by JDK 8
            if (pbes2PValues.get(0).hasTag(UniversalTag.OBJECT_IDENTIFIER)) {
                // Decode PBES2 AlgorithmIdentifier
                pbes2PValues = getParam(pbes2Params, ID_PBES2, 2, 2);
            }

            // Process encryptionScheme
            List<Asn1BerValue> aesAlgId = getParam(pbes2PValues.get(1));
            Asn1BerValue aesOid = aesAlgId.get(0);
            if (!CIPHER_MAP.containsKey(aesOid)) {
                throw new Asn1DecodeException("Unsupported cipher algorithm: " + aesOid.getOid());
            }
            // The IV must match the block size of the cipher.
            byte[] aesIv = aesAlgId.get(1).getOctetString();
            if (aesIv.length != AES_BLOCK_SIZE) {
                throw new Asn1DecodeException("Invalid IV length; was: " + aesIv.length + ", expected: " + AES_BLOCK_SIZE);
            }

            // Process keyDerivationFunc
            List<Asn1BerValue> pbkdf2Params = getParam(pbes2PValues.get(0), ID_PBKDF2, 2, 4);
            byte[] salt = pbkdf2Params.get(0).getOctetString();
            if (salt.length == 0) {
                throw new Asn1DecodeException("Invalid salt parameter");
            }
            int iterationCount = pbkdf2Params.get(1).getInteger().intValueExact();
            if (iterationCount < 1) {
                throw new Asn1DecodeException("Invalid iterationCount parameter");
            }
            // Process OPTIONAL/DEFAULT elements
            int i = 2;
            if (pbkdf2Params.size() > i) {
                if (pbkdf2Params.get(i).hasTag(UniversalTag.INTEGER)) {
                    // If a key length is present then it must match the cipher.
                    int keyLength = pbkdf2Params.get(i++).getInteger().intValueExact();
                    int aesKeyLen = aesOid.equals(ID_AES128_CBC_PAD) ? 16 : 32;
                    if (keyLength != aesKeyLen) {
                        throw new Asn1DecodeException("Invalid keyLength parameter for cipher; was: " + keyLength + ", expected: " + aesKeyLen);
                    }
                }
            }

            // prf - defaults to hmacWithSHA1
            Asn1BerValue hmacOid = ID_HMAC_WITH_SHA1;
            if (pbkdf2Params.size() > i) {
                // Process prf
                List<Asn1BerValue> prfAlgId = getParam(pbkdf2Params.get(i));
                hmacOid = prfAlgId.get(0);
                if (!PRF_MAP.containsKey(hmacOid)) {
                    throw new Asn1DecodeException("Unsupported PRF algorithm: " + hmacOid.getOid());
                }
                prfAlgId.get(1).getNull();
            }

            this.pbeSpec = new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(aesIv));
            this.prfOid = hmacOid;
            this.cipherOid = aesOid;
        } catch (ArithmeticException | Asn1DecodeException ex) {
            throw new IOException("Invalid PBES2 parameters", ex);
        }
    }

    private static List<Asn1BerValue> getParam(Asn1BerValue algId, Asn1BerValue expectedOid, int min, int max) {
        return getParam(algId, expectedOid).count(min, max).sequence();
    }

    private static Asn1BerValue getParam(Asn1BerValue algId, Asn1BerValue expectedOid) {
        List<Asn1BerValue> values = getParam(algId);
        Asn1BerValue algorithm = values.get(0);
        if (!algorithm.equals(expectedOid)) {
            throw new Asn1DecodeException("Unsupported PBE algorithm; was: " + algorithm.getOid() + ", expected: " + expectedOid.getOid());
        }
        return values.get(1);
    }

    private static List<Asn1BerValue> getParam(Asn1BerValue algId) {
        List<Asn1BerValue> values = algId.count(2).sequence();
        values.get(0).tag(UniversalTag.OBJECT_IDENTIFIER);
        return values;
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected String engineToString() {
        if (this.prfOid == null || this.cipherOid == null) {
            return null;
        }
        String prfAlg = PRF_MAP.get(this.prfOid);
        String cipherAlg = CIPHER_MAP.get(this.cipherOid);
        return "PBEWith" + prfAlg + "And" + cipherAlg;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (this.pbeSpec != null) {
            throw new InvalidParameterSpecException("already initialized");
        }

        if (!(paramSpec instanceof PBEParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        this.pbeSpec = (PBEParameterSpec) paramSpec;
    }

    public static final class PBES2 extends Pbes2Parameters {
        public PBES2() {
            super(null, null);
        }
    }

    public static final class PBEWithHmacSHA1AndAES128 extends Pbes2Parameters {
        public PBEWithHmacSHA1AndAES128() {
            super(ID_HMAC_WITH_SHA1, ID_AES128_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA224AndAES128 extends Pbes2Parameters {
        public PBEWithHmacSHA224AndAES128() {
            super(ID_HMAC_WITH_SHA224, ID_AES128_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA256AndAES128 extends Pbes2Parameters {
        public PBEWithHmacSHA256AndAES128() {
            super(ID_HMAC_WITH_SHA256, ID_AES128_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA384AndAES128 extends Pbes2Parameters {
        public PBEWithHmacSHA384AndAES128() {
            super(ID_HMAC_WITH_SHA384, ID_AES128_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA512AndAES128 extends Pbes2Parameters {
        public PBEWithHmacSHA512AndAES128() {
            super(ID_HMAC_WITH_SHA512, ID_AES128_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA1AndAES256 extends Pbes2Parameters {
        public PBEWithHmacSHA1AndAES256() {
            super(ID_HMAC_WITH_SHA1, ID_AES256_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA224AndAES256 extends Pbes2Parameters {
        public PBEWithHmacSHA224AndAES256() {
            super(ID_HMAC_WITH_SHA224, ID_AES256_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA256AndAES256 extends Pbes2Parameters {
        public PBEWithHmacSHA256AndAES256() {
            super(ID_HMAC_WITH_SHA256, ID_AES256_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA384AndAES256 extends Pbes2Parameters {
        public PBEWithHmacSHA384AndAES256() {
            super(ID_HMAC_WITH_SHA384, ID_AES256_CBC_PAD);
        }
    }

    public static final class PBEWithHmacSHA512AndAES256 extends Pbes2Parameters {
        public PBEWithHmacSHA512AndAES256() {
            super(ID_HMAC_WITH_SHA512, ID_AES256_CBC_PAD);
        }
    }

}
