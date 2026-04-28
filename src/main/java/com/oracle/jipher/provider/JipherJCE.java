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

package com.oracle.jipher.provider;

import java.io.Serial;
import java.security.Provider;
import java.security.ProviderException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.FipsProviderInfo;
import com.oracle.jipher.internal.openssl.OpenSslValidator;
import com.oracle.jipher.internal.openssl.OpenSslVersion;
import com.oracle.jipher.internal.spi.AeadCipher;
import com.oracle.jipher.internal.spi.AesKeyGenerator;
import com.oracle.jipher.internal.spi.Capabilities;
import com.oracle.jipher.internal.spi.CipherParameters;
import com.oracle.jipher.internal.spi.DhKeyFactory;
import com.oracle.jipher.internal.spi.DhParameters;
import com.oracle.jipher.internal.spi.Digest;
import com.oracle.jipher.internal.spi.Drbg;
import com.oracle.jipher.internal.spi.DsaDigestSig;
import com.oracle.jipher.internal.spi.DsaKeyFactory;
import com.oracle.jipher.internal.spi.DummyJCEVerifierSignature;
import com.oracle.jipher.internal.spi.DummySunJSSESignature;
import com.oracle.jipher.internal.spi.EcKeyFactory;
import com.oracle.jipher.internal.spi.EcParameters;
import com.oracle.jipher.internal.spi.EcdsaDigestSig;
import com.oracle.jipher.internal.spi.FeedbackCipher;
import com.oracle.jipher.internal.spi.GcmParameters;
import com.oracle.jipher.internal.spi.Hmac;
import com.oracle.jipher.internal.spi.HmacKeyGenerator;
import com.oracle.jipher.internal.spi.KeyAgree;
import com.oracle.jipher.internal.spi.KeyPairGen;
import com.oracle.jipher.internal.spi.NoDigestSig;
import com.oracle.jipher.internal.spi.OaepParameters;
import com.oracle.jipher.internal.spi.PbeCipher;
import com.oracle.jipher.internal.spi.PbeKeyFactory;
import com.oracle.jipher.internal.spi.PbeParameters;
import com.oracle.jipher.internal.spi.Pbes2Parameters;
import com.oracle.jipher.internal.spi.Pbkdf2KeyFactory;
import com.oracle.jipher.internal.spi.PssParameters;
import com.oracle.jipher.internal.spi.RsaCipher;
import com.oracle.jipher.internal.spi.RsaDigestSig;
import com.oracle.jipher.internal.spi.RsaKeyFactory;
import com.oracle.jipher.internal.spi.RsaPssDigestSig;
import com.oracle.jipher.internal.spi.RsaPssGeneralSig;
import com.oracle.jipher.internal.spi.SymmKeyFactory;
import com.oracle.jipher.internal.spi.TlsKeyMaterialGenerator;
import com.oracle.jipher.internal.spi.TlsMasterSecretGenerator;
import com.oracle.jipher.internal.spi.TlsPrfGenerator;
import com.oracle.jipher.internal.spi.TlsRsaPremasterSecretGenerator;
import com.oracle.jipher.internal.spi.WrapCipher;

/**
 * Defines the JipherJCE provider.
 *
 * <p> The JipherJCE provider drives the OpenSSL FIPS provider to provide cryptographic algorithms.
 * It provides instances of the following cryptographic services and algorithms:
 * <ul>
 *     <li>{@link java.security.AlgorithmParameters}:
 *         AES, DESede, DiffieHellman, EC, GCM, OAEP, PBE,
 *         PBEWith&lt;prf&gt;And&lt;encryption&gt;, PBES2, RSASSA-PSS
 *     </li>
 *     <li>{@link javax.crypto.Cipher}:
 *         AES (modes: CBC, CFB, CTR, ECB, GCM, OFB), AESWrap, AESWrapPad, DESede,
 *         PBEWith&lt;prf&gt;And&lt;encryption&gt;, RSA
 *     </li>
 *     <li>{@link javax.crypto.KDF}: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512</li>
 *     <li>{@link javax.crypto.KeyAgreement}: DiffieHellman, ECDH</li>
 *     <li>{@link java.security.KeyFactory}: DiffieHellman, DSA, EC, RSA, RSASSA-PSS</li>
 *     <li>{@link javax.crypto.KeyGenerator}:
 *         AES, Hmac&lt;digest&gt;, SunTls12Prf, SunTlsExtendedMasterSecret, SunTlsKeyMaterial, SunTlsRsaPremasterSecret
 *     </li>
 *     <li>{@link java.security.KeyPairGenerator}: DiffieHellman, EC, RSA, RSASSA-PSS </li>
 *     <li>{@link javax.crypto.Mac}: Hmac&lt;digest&gt;</li>
 *     <li>{@link java.security.MessageDigest}:
 *         SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384, SHA3-512
 *      </li>
 *     <li>{@link java.security.SecureRandom}: DRBG</li>
 *     <li>{@link javax.crypto.SecretKeyFactory}:
 *         AES, DESede, PBEWith&lt;prf&gt;And&lt;encryption&gt;,
 *         PBKDF2With&lt;prf&lt;
 *     </li>
 *     <li>{@link java.security.Signature}:
 *         NONEwithRSA, &lt;digest&gt;withRSA, &lt;digest&gt;withRSAandMGF1, RSASSA-PSS, NONEwithDSA,
 *         &lt;digest&gt;withDSA, NONEwithECDSA, &lt;digest&gt;withECDSA
 *     </li>
 * </ul>
 * Where:
 * <ul>
 *     <li>&lt;prf&gt; is any of HmacSHA1, HmacSHA224, HmacSHA384, or HmacSHA512,</li>
 *     <li>&lt;encryption&gt; is any of AES_128 or AES_256, and</li>
 *     <li>&lt;digest&gt; is any of SHA1, SHA224, SHA384, or SHA512.</li>
 * </ul>
 * <p>The AES Cipher modes CBC and ECB, and the DES Cipher mode CBC, support PKCS5Padding.
 *
 * <p>The RSA Cipher supports the paddings OAEPPadding and OAEPWith&lt;digest&gt;AndMGF1Padding,
 * where &lt;digest&gt; is any of SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512.
 *
 * <p>Aliases and OIDs corresponding to the Java Security Standard Algorithm Names listed
 * above are supported by JipherJCE if they are supported by the JDK providers.
 *
 * <p>SunTls12Prf, SunTlsExtendedMasterSecret, SunTlsKeyMaterial and SunTlsRsaPremasterSecret
 * are non-standard KeyGenerator algorithms that are required by the built-in SunJSSE provider.
 *
 * <p>SecureRandom DRBG instances provided by JipherJCE use the underlying deterministic random
 * bit generator algorithm in OpenSSL, which generates random bits with a security strength of 256 bits.
 */
public final class JipherJCE extends Provider {

    @Serial
    private static final long serialVersionUID = 3921916336502456833L;

    private static final Debug DEBUG_ALG = Debug.getInstance("algorithms");

    public static final String PROVIDER_NAME = "JipherJCE";

    /**
     * Generates a textual description of this provider.
     *
     * @param withOpenSSLVersion {@code true} to include the OpenSSL version and FIPS provider
     *                           information; {@code false} to omit those details
     * @return a {@link String} containing the provider name, version, OpenSSL version if requested,
     *         and list of supported algorithms
     */
    static String info(boolean withOpenSSLVersion) {
        StringBuilder sb = new StringBuilder();
        sb.append(PROVIDER_NAME);
        sb.append(" Provider ").append("@VERSION@");
        if (withOpenSSLVersion) {
            sb.append("[");
            sb.append(OpenSslVersion.get());
            sb.append(" with ");
            sb.append(FipsProviderInfo.getNameString());
            sb.append(" version ");
            sb.append(FipsProviderInfo.getVersionString());
            sb.append("]");
        }
        sb.append(" (implements AES");
        if (isDESEDESupported()) {
            sb.append(", DESede");
        }
        sb.append(", Diffie-Hellman");
        if (isDSASupported()) {
            sb.append(", DSA");
        }
        sb.append(", ECDSA, ECDH, HMAC, PBKDF2, RSA, SHA-1, SHA-2, SHA-3)");

        return sb.toString();
    }

    /**
     * Verifies that the OpenSSL native library is available before returning the provider
     * information string that includes OpenSSL details.
     *
     * @return the result of {@link #info(boolean)} with {@code true} to include OpenSSL info
     * @throws ProviderException if OpenSSL cannot be loaded; the original loading exception is
     *         wrapped as the cause
     */
    private static String checkOpenSSLIsAvailableThenCallInfo() {
        if (!isAvailable()) {
            throw new ProviderException("OpenSSL is not available", loadingException());
        }
        return info(true);
    }

    /**
     * Determines whether the DESede algorithm should be advertised.
     *
     * <p>When the FIPS enforcement policy is {@code FIPS_STRICT}, legacy use of DESede is disallowed
     * according to SP 800-131A Rev. 2 Table 1. In that case this method returns {@code false}; otherwise the
     * decision is delegated to {@link Capabilities#isDESEDESupported()}.</p>
     *
     * @return {@code true} if DESede is supported and may be registered, {@code false} otherwise
     */
    private static boolean isDESEDESupported() {
        if (ToolkitProperties.getFipsEnforcementValue() == Fips.EnforcementPolicy.FIPS_STRICT) {
            // The FIPS_STRICT enforcement policy, which does not permit operations with a "legacy use" status,
            // does not allow DESEDE keys to be used for encryption or decryption. SP 800-131A Rev. 2 Table 1,
            // Acceptable usage. Consequently, when the FIPS_STRICT enforcement policy is activated
            // Jipher does not register support for the DESEDE algorithm for any service with the JCA.
            return false;
        } else {
            return Capabilities.isDESEDESupported();
        }
    }

    /**
     * Determines whether the DSA algorithm should be advertised.
     *
     * <p>When the FIPS enforcement policy is {@code FIPS_STRICT}, DSA operations are prohibited (see
     * FIPS 140-3 IG, section C.K). In that case this method returns {@code false}; otherwise the decision is
     * delegated to {@link Capabilities#isDSASupported()}.</p>
     *
     * @return {@code true} if DSA is supported and may be registered, {@code false} otherwise
     */
    private static boolean isDSASupported() {
        if (ToolkitProperties.getFipsEnforcementValue() == Fips.EnforcementPolicy.FIPS_STRICT) {
            // The FIPS_STRICT enforcement policy, which does not permit operations with a "legacy use" status,
            // does not allow DSA keys to be used for signature generation or verification. See FIPS 140-3 IG,
            // section C.K, Resolution 1. Consequently, when the FIPS_STRICT enforcement policy is activated
            // Jipher does not register support for the DSA algorithm for any service with the JCA.
            return false;
        } else {
            return Capabilities.isDSASupported();
        }
    }

    /**
     * Indicates whether SHA-1 based digest signatures are permitted under the current FIPS policy.
     *
     * @return {@code false} when the policy is {@code FIPS_STRICT} (SHA-1 is disallowed), otherwise the
     *         result of {@link Capabilities#isSHA1DigestSignatureSupported()}
     */
    private static boolean isSHA1DigestSignatureSupported() {
        if (ToolkitProperties.getFipsEnforcementValue() == Fips.EnforcementPolicy.FIPS_STRICT) {
            // The FIPS_STRICT enforcement policy, which does not permit operations with a "legacy use" status,
            // does not allow SHA-1 to be used for digest signature generation or verification.
            // See SP 800-131A Rev. 2 Table 8, Acceptable usage. Consequently, when the FIPS_STRICT enforcement policy
            // is activated Jipher does not register support for the SHA-1 digest signatures with the JCA.
            return false;
        }
        else {
            return Capabilities.isSHA1DigestSignatureSupported();
        }
    }

    // Returns the integer value of the major version component of the value of java.runtime.version
    // or 0 if the major version component of the value of java.runtime.version cannot be parsed
    private static int getJavaRuntimeMajorVersion() {
        try {
            return Util.getJavaRuntimeMajorVersion();
        } catch (ParseException e) {
            return 0;
        }
    }

    /**
     * Checks whether the underlying OpenSSL native library is available.
     *
     * @return {@code true} if OpenSSL can be loaded and used, {@code false} otherwise
     */
    public static boolean isAvailable() {
        return OpenSslValidator.isAvailable();
    }

    /**
     * Retrieves the exception that occurred while attempting to load OpenSSL.
     *
     * @return a {@link ProviderException} describing the failure, or {@code null} if no error occurred
     */
    public static ProviderException loadingException() {
        return OpenSslValidator.loadingException();
    }

    /**
     * Constructs a new {@code JipherJCE} provider instance.
     *
     * <p>The constructor verifies that OpenSSL is available; if not, a {@link ProviderException} is thrown.
     * It then registers all cryptographic services supported by this provider.</p>
     */
    public JipherJCE() {
        super(PROVIDER_NAME, "@VERSION@", checkOpenSSLIsAvailableThenCallInfo());
        addServices();
    }

    /**
     * Registers all cryptographic algorithm implementations with the JCA runtime.
     *
     * <p>This method populates the provider with {@link java.security.AlgorithmParameters},
     * {@link javax.crypto.Cipher}, {@link javax.crypto.KDF}, {@link javax.crypto.KeyAgreement},
     * {@link java.security.KeyFactory}, {@link javax.crypto.KeyGenerator},
     * {@link java.security.KeyPairGenerator}, {@link javax.crypto.Mac},
     * {@link java.security.MessageDigest}, {@link java.security.SecureRandom},
     * {@link javax.crypto.SecretKeyFactory} and {@link java.security.Signature}
     * services supported by Jipher.</p>
     */
    private void addServices() {

        // AlgorithmParameters Implementations
        putService("AlgorithmParameters", "EC", EcParameters.class.getName(),
                "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1");
        putService("AlgorithmParameters", "AES", CipherParameters.AesParameters.class.getName(),
                "OID.2.16.840.1.101.3.4.1", "2.16.840.1.101.3.4.1",
                "OID.2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.2",
                "OID.2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.3",
                "OID.2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.4",
                "OID.2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.6",
                "OID.2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.22",
                "OID.2.16.840.1.101.3.4.1.23", "2.16.840.1.101.3.4.1.23",
                "OID.2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.24",
                "OID.2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.26",
                "OID.2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.42",
                "OID.2.16.840.1.101.3.4.1.43", "2.16.840.1.101.3.4.1.43",
                "OID.2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.44",
                "OID.2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.46");
        if (isDESEDESupported()) {
            putService("AlgorithmParameters", "DESede", CipherParameters.DESedeParameters.class.getName(),
                    "OID.1.2.840.113549.3.7", "1.2.840.113549.3.7");
        }
        putService("AlgorithmParameters", "GCM", GcmParameters.class.getName());
        putService("AlgorithmParameters", "OAEP", OaepParameters.class.getName(),
                "OID.1.2.840.113549.1.1.7", "1.2.840.113549.1.1.7");
        putService("AlgorithmParameters", "RSASSA-PSS", PssParameters.class.getName(),
                "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10");
        putService("AlgorithmParameters", "DH", DhParameters.class.getName(), "DiffieHellman",
                "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1");
        putService("AlgorithmParameters", "PBES2", Pbes2Parameters.PBES2.class.getName(),
                "OID.1.2.840.113549.1.5.13", " 1.2.840.113549.1.5.13");
        putService("AlgorithmParameters", "PBEWithHmacSHA1AndAES_128", Pbes2Parameters.PBEWithHmacSHA1AndAES128.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA224AndAES_128", Pbes2Parameters.PBEWithHmacSHA224AndAES128.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA256AndAES_128", Pbes2Parameters.PBEWithHmacSHA256AndAES128.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA384AndAES_128", Pbes2Parameters.PBEWithHmacSHA384AndAES128.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA512AndAES_128", Pbes2Parameters.PBEWithHmacSHA512AndAES128.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA1AndAES_256", Pbes2Parameters.PBEWithHmacSHA1AndAES256.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA224AndAES_256", Pbes2Parameters.PBEWithHmacSHA224AndAES256.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA256AndAES_256", Pbes2Parameters.PBEWithHmacSHA256AndAES256.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA384AndAES_256", Pbes2Parameters.PBEWithHmacSHA384AndAES256.class.getName());
        putService("AlgorithmParameters", "PBEWithHmacSHA512AndAES_256", Pbes2Parameters.PBEWithHmacSHA512AndAES256.class.getName());
        putService("AlgorithmParameters", "PBE", PbeParameters.class.getName());

        // Cipher implementations
        putService("Cipher", "AES", FeedbackCipher.AES.class.getName(), "Rijndael",
                "OID.2.16.840.1.101.3.4.1", "2.16.840.1.101.3.4.1");
        putService("Cipher", "AES/GCM/NoPadding", AeadCipher.AesGcm.class.getName());
        putService("Cipher", "AES_128/ECB/NoPadding", FeedbackCipher.Aes128EcbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.1", "2.16.840.1.101.3.4.1.1");
        putService("Cipher", "AES_192/ECB/NoPadding", FeedbackCipher.Aes192EcbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.21", "2.16.840.1.101.3.4.1.21");
        putService("Cipher", "AES_256/ECB/NoPadding", FeedbackCipher.Aes256EcbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.41", "2.16.840.1.101.3.4.1.41");
        putService("Cipher", "AES_128/CBC/PKCS5Padding", FeedbackCipher.Aes128CbcPkcs5Pad.class.getName(),
                "AES_128/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.2");
        putService("Cipher", "AES_192/CBC/PKCS5Padding", FeedbackCipher.Aes192CbcPkcs5Pad.class.getName(),
                "AES_192/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.22");
        putService("Cipher", "AES_256/CBC/PKCS5Padding", FeedbackCipher.Aes256CbcPkcs5Pad.class.getName(),
                "AES_256/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.42");
        putService("Cipher", "AES_128/OFB/NoPadding", FeedbackCipher.Aes128OfbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.3");
        putService("Cipher", "AES_192/OFB/NoPadding", FeedbackCipher.Aes192OfbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.23", "2.16.840.1.101.3.4.1.23");
        putService("Cipher", "AES_256/OFB/NoPadding", FeedbackCipher.Aes256OfbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.43", "2.16.840.1.101.3.4.1.43");
        putService("Cipher", "AES_128/CFB/NoPadding", FeedbackCipher.Aes128CfbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.4");
        putService("Cipher", "AES_192/CFB/NoPadding", FeedbackCipher.Aes192CfbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.24");
        putService("Cipher", "AES_256/CFB/NoPadding", FeedbackCipher.Aes256CfbNoPad.class.getName(),
                "OID.2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.44");
        putService("Cipher", "AES_128/GCM/NoPadding", AeadCipher.Aes128Gcm.class.getName(),
                "OID.2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.6");
        putService("Cipher", "AES_192/GCM/NoPadding", AeadCipher.Aes192Gcm.class.getName(),
                "OID.2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.26");
        putService("Cipher", "AES_256/GCM/NoPadding", AeadCipher.Aes256Gcm.class.getName(),
                "OID.2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.46");
        putService("Cipher", "AES/KW/NoPadding", WrapCipher.AesWrap.class.getName(),
                "AESWrap", "AES-KW");
        putService("Cipher", "AES_128/KW/NoPadding", WrapCipher.AesWrap128.class.getName(), "AESWrap_128",
                "OID.2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.5");
        putService("Cipher", "AES_192/KW/NoPadding", WrapCipher.AesWrap192.class.getName(), "AESWrap_192",
                "OID. 2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.25");
        putService("Cipher", "AES_256/KW/NoPadding", WrapCipher.AesWrap256.class.getName(), "AESWrap_256",
                "OID.2.16.840.1.101.3.4.1.45", "2.16.840.1.101.3.4.1.45");
        putService("Cipher", "AES/KWP/NoPadding", WrapCipher.AesWrapPad.class.getName(),
                "AESWrapPad", "AES-KWP");
        putService("Cipher", "AES_128/KWP/NoPadding", WrapCipher.AesWrapPad128.class.getName(), "AESWrapPad_128",
                "OID.2.16.840.1.101.3.4.1.8", "2.16.840.1.101.3.4.1.8");
        putService("Cipher", "AES_192/KWP/NoPadding", WrapCipher.AesWrapPad192.class.getName(), "AESWrapPad_192",
                "OID.2.16.840.1.101.3.4.1.28", "2.16.840.1.101.3.4.1.28");
        putService("Cipher", "AES_256/KWP/NoPadding", WrapCipher.AesWrapPad256.class.getName(), "AESWrapPad_256",
                "OID.2.16.840.1.101.3.4.1.48", "2.16.840.1.101.3.4.1.48");
        putService("Cipher", "PBEWithHmacSHA1AndAES_128", PbeCipher.PBEWithHmacSHA1AndAES128.class.getName());
        putService("Cipher", "PBEWithHmacSHA224AndAES_128", PbeCipher.PBEWithHmacSHA224AndAES128.class.getName());
        putService("Cipher", "PBEWithHmacSHA256AndAES_128", PbeCipher.PBEWithHmacSHA256AndAES128.class.getName());
        putService("Cipher", "PBEWithHmacSHA384AndAES_128", PbeCipher.PBEWithHmacSHA384AndAES128.class.getName());
        putService("Cipher", "PBEWithHmacSHA512AndAES_128", PbeCipher.PBEWithHmacSHA512AndAES128.class.getName());
        putService("Cipher", "PBEWithHmacSHA1AndAES_256", PbeCipher.PBEWithHmacSHA1AndAES256.class.getName());
        putService("Cipher", "PBEWithHmacSHA224AndAES_256", PbeCipher.PBEWithHmacSHA224AndAES256.class.getName());
        putService("Cipher", "PBEWithHmacSHA256AndAES_256", PbeCipher.PBEWithHmacSHA256AndAES256.class.getName());
        putService("Cipher", "PBEWithHmacSHA384AndAES_256", PbeCipher.PBEWithHmacSHA384AndAES256.class.getName());
        putService("Cipher", "PBEWithHmacSHA512AndAES_256", PbeCipher.PBEWithHmacSHA512AndAES256.class.getName());
        if (isDESEDESupported()) {
            putService("Cipher", "DESede", FeedbackCipher.DESEDE.class.getName(), "TripleDES");
            putService("Cipher", "DESede/CBC/PKCS5Padding", FeedbackCipher.DesEdeCbcPkcs5Pad.class.getName(),
                    "DESede/CBC/PKCS7Padding", "OID.1.2.840.113549.3.7", "1.2.840.113549.3.7");
        }

        // SP 800-131A Rev. 2 Table 5, Acceptable + SP 800-56B Rev. 2 Section 9
        putService("Cipher", "RSA/ECB/OAEPPadding", RsaCipher.RsaOaep.class.getName());
        putService("Cipher", "RSA/ECB/OAEPWithSHA-1andMGF1Padding", RsaCipher.RsaOaepSha1.class.getName(),
                "RSA/ECB/OAEPWithSHA1andMGF1Padding");
        putService("Cipher", "RSA/ECB/OAEPWithSHA-224andMGF1Padding", RsaCipher.RsaOaepSha224.class.getName(),
                "RSA/ECB/OAEPWithSHA224andMGF1Padding");
        putService("Cipher", "RSA/ECB/OAEPWithSHA-256andMGF1Padding", RsaCipher.RsaOaepSha256.class.getName(),
                "RSA/ECB/OAEPWithSHA256andMGF1Padding");
        putService("Cipher", "RSA/ECB/OAEPWithSHA-384andMGF1Padding", RsaCipher.RsaOaepSha384.class.getName(),
                "RSA/ECB/OAEPWithSHA384andMGF1Padding");
        putService("Cipher", "RSA/ECB/OAEPWithSHA-512andMGF1Padding", RsaCipher.RsaOaepSha512.class.getName(),
                "RSA/ECB/OAEPWithSHA512andMGF1Padding");

        // KDF Implementations
        // KDF API was added as a preview feature in JDK 24 and a core feature in JDK 25
        if (getJavaRuntimeMajorVersion() >= 25) {
            putService("KDF", "HKDF-SHA256", "com.oracle.jipher.internal.spi.Hkdf$HkdfSha256");
            putService("KDF", "HKDF-SHA384", "com.oracle.jipher.internal.spi.Hkdf$HkdfSha384");
            putService("KDF", "HKDF-SHA512", "com.oracle.jipher.internal.spi.Hkdf$HkdfSha512");
        }

        // KeyAgreement Implementations
        putService("KeyAgreement", "ECDH", KeyAgree.ECDH.class.getName(), new HashMap<>()); // Empty attribs map satisfies jacoco branches covered %
        putService("KeyAgreement", "DH", KeyAgree.DH.class.getName(), "DiffieHellman",
                "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1");

        // KeyFactory Implementations
        putService("KeyFactory", "RSA", RsaKeyFactory.class.getName(),
                "OID.1.2.840.113549.1.1", "1.2.840.113549.1.1",
                "OID.1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1");
        putService("KeyFactory", "RSASSA-PSS", RsaKeyFactory.class.getName(), "PSS",
                "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10");
        putService("KeyFactory", "EC", EcKeyFactory.class.getName(), "EllipticCurve",
                "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1");
        if (isDSASupported()) {
            putService("KeyFactory", "DSA", DsaKeyFactory.class.getName(),
                    "OID.1.2.840.10040.4.1", "1.2.840.10040.4.1",
                    "OID.1.3.14.3.2.12", "1.3.14.3.2.12");
        }
        putService("KeyFactory", "DH", DhKeyFactory.class.getName(), "DiffieHellman",
                "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1");

        // KeyGenerator implementations
        putService("KeyGenerator", "AES", AesKeyGenerator.class.getName(), "Rijndael",
                "OID.2.16.840.1.101.3.4.1", "2.16.840.1.101.3.4.1");
        putService("KeyGenerator", "AES_128/ECB/NoPadding", AesKeyGenerator.Aes128.class.getName(),
                "OID.2.16.840.1.101.3.4.1.1", "2.16.840.1.101.3.4.1.1");
        putService("KeyGenerator", "AES_192/ECB/NoPadding", AesKeyGenerator.Aes192.class.getName(),
                "OID.2.16.840.1.101.3.4.1.21", "2.16.840.1.101.3.4.1.21");
        putService("KeyGenerator", "AES_256/ECB/NoPadding", AesKeyGenerator.Aes256.class.getName(),
                "OID.2.16.840.1.101.3.4.1.41", "2.16.840.1.101.3.4.1.41");
        putService("KeyGenerator", "AES_128/CBC/PKCS5Padding", AesKeyGenerator.Aes128.class.getName(),
                "AES_128/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.2");
        putService("KeyGenerator", "AES_192/CBC/PKCS5Padding", AesKeyGenerator.Aes192.class.getName(),
                "AES_192/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.22");
        putService("KeyGenerator", "AES_256/CBC/PKCS5Padding", AesKeyGenerator.Aes256.class.getName(),
                "AES_256/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.42");
        putService("KeyGenerator", "AES_128/OFB/NoPadding", AesKeyGenerator.Aes128.class.getName(),
                "OID.2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.3");
        putService("KeyGenerator", "AES_192/OFB/NoPadding", AesKeyGenerator.Aes192.class.getName(),
                "OID.2.16.840.1.101.3.4.1.23", "2.16.840.1.101.3.4.1.23");
        putService("KeyGenerator", "AES_256/OFB/NoPadding", AesKeyGenerator.Aes256.class.getName(),
                "OID.2.16.840.1.101.3.4.1.43", "2.16.840.1.101.3.4.1.43");
        putService("KeyGenerator", "AES_128/CFB/NoPadding", AesKeyGenerator.Aes128.class.getName(),
                "OID.2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.4");
        putService("KeyGenerator", "AES_192/CFB/NoPadding", AesKeyGenerator.Aes192.class.getName(),
                "OID.2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.24");
        putService("KeyGenerator", "AES_256/CFB/NoPadding", AesKeyGenerator.Aes256.class.getName(),
                "OID.2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.44");
        putService("KeyGenerator", "AES_128/GCM/NoPadding", AesKeyGenerator.Aes128.class.getName(),
                "OID.2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.6");
        putService("KeyGenerator", "AES_192/GCM/NoPadding", AesKeyGenerator.Aes192.class.getName(),
                "OID.2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.26");
        putService("KeyGenerator", "AES_256/GCM/NoPadding", AesKeyGenerator.Aes256.class.getName(),
                "OID.2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.46");
        putService("KeyGenerator", "SunTls12Prf", TlsPrfGenerator.class.getName());
        putService("KeyGenerator", "SunTlsExtendedMasterSecret", TlsMasterSecretGenerator.class.getName());
        putService("KeyGenerator", "SunTlsKeyMaterial", TlsKeyMaterialGenerator.class.getName(),
                "SunTls12KeyMaterial");
        putService("KeyGenerator", "SunTlsRsaPremasterSecret", TlsRsaPremasterSecretGenerator.class.getName(),
                "SunTls12RsaPremasterSecret");

        putService("KeyGenerator", "HmacSHA1", HmacKeyGenerator.HmacSha1.class.getName(),
                "OID.1.2.840.113549.2.7", "1.2.840.113549.2.7");
        putService("KeyGenerator", "HmacSHA224", HmacKeyGenerator.HmacSha224.class.getName(),
                "OID.1.2.840.113549.2.8", "1.2.840.113549.2.8");
        putService("KeyGenerator", "HmacSHA256", HmacKeyGenerator.HmacSha256.class.getName(),
                "OID.1.2.840.113549.2.9", "1.2.840.113549.2.9");
        putService("KeyGenerator", "HmacSHA384", HmacKeyGenerator.HmacSha384.class.getName(),
                "OID.1.2.840.113549.2.10", "1.2.840.113549.2.10");
        putService("KeyGenerator", "HmacSHA512", HmacKeyGenerator.HmacSha512.class.getName(),
                "OID.1.2.840.113549.2.11", "1.2.840.113549.2.11");

        // KeyPairGenerator Implementations
        putService("KeyPairGenerator", "RSA", KeyPairGen.Rsa.class.getName(),
                "OID.1.2.840.113549.1.1", "1.2.840.113549.1.1",
                "OID.1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1");
        putService("KeyPairGenerator", "RSASSA-PSS", KeyPairGen.Rsa.class.getName(), "PSS",
                "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10");
        putService("KeyPairGenerator", "EC", KeyPairGen.Ec.class.getName(), "EllipticCurve",
                "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1");
        putService("KeyPairGenerator", "DH", KeyPairGen.Dh.class.getName(), "DiffieHellman",
                "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1");

        // Mac Implementations
        putService("Mac", "HmacSHA1", Hmac.HmacSha1.class.getName(),
                "OID.1.2.840.113549.2.7", "1.2.840.113549.2.7");
        putService("Mac", "HmacSHA224", Hmac.HmacSha224.class.getName(),
                "OID.1.2.840.113549.2.8", "1.2.840.113549.2.8");
        putService("Mac", "HmacSHA256", Hmac.HmacSha256.class.getName(),
                "OID.1.2.840.113549.2.9", "1.2.840.113549.2.9");
        putService("Mac", "HmacSHA384", Hmac.HmacSha384.class.getName(),
                "OID.1.2.840.113549.2.10", "1.2.840.113549.2.10");
        putService("Mac", "HmacSHA512", Hmac.HmacSha512.class.getName(),
                "OID.1.2.840.113549.2.11", "1.2.840.113549.2.11");

        // MessageDigest Implementations
        putService("MessageDigest", "SHA-1", Digest.Sha1.class.getName(),
                "SHA1", "SHA", "OID.1.3.14.3.2.26", "1.3.14.3.2.26");
        putService("MessageDigest", "SHA-224", Digest.Sha224.class.getName(),
                "SHA224", "OID.2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.4");
        putService("MessageDigest", "SHA-256", Digest.Sha256.class.getName(),
                "SHA256", "OID.2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.1");
        putService("MessageDigest", "SHA-384", Digest.Sha384.class.getName(),
                "SHA384", "OID.2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.2");
        putService("MessageDigest", "SHA-512", Digest.Sha512.class.getName(),
                "SHA512", "OID.2.16.840.1.101.3.4.2.3", "2.16.840.1.101.3.4.2.3");
        putService("MessageDigest", "SHA3-224", Digest.Sha3_224.class.getName(),
                "OID.2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.2.7");
        putService("MessageDigest", "SHA3-256", Digest.Sha3_256.class.getName(),
                "OID.2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.2.8");
        putService("MessageDigest", "SHA3-384", Digest.Sha3_384.class.getName(),
                "OID.2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.2.9");
        putService("MessageDigest", "SHA3-512", Digest.Sha3_512.class.getName(),
                "OID.2.16.840.1.101.3.4.2.10", "2.16.840.1.101.3.4.2.10");

        // SecureRandom Implementations
        Map<String,String> threadSafeAttr = new HashMap<>();
        threadSafeAttr.put("ThreadSafe", "true");
        putService("SecureRandom", "DRBG", Drbg.class.getName(),
                threadSafeAttr, "Default", "DefaultRandom", "SHA1PRNG", "CTRDRBG", "CTRDRBG128",
                "NativePRNG", "NativePRNGNonBlocking");

        // SecretKeyFactory implementations
        putService("SecretKeyFactory", "AES", SymmKeyFactory.AES.class.getName());
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA1", Pbkdf2KeyFactory.SHA1.class.getName(), "PBKDF2WithSHA1",
                "OID.1.2.840.113549.1.5.12", "1.2.840.113549.1.5.12");
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA224", Pbkdf2KeyFactory.SHA224.class.getName(), "PBKDF2WithSHA224");
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA256", Pbkdf2KeyFactory.SHA256.class.getName(), "PBKDF2WithSHA256");
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA384", Pbkdf2KeyFactory.SHA384.class.getName(), "PBKDF2WithSHA384");
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA512", Pbkdf2KeyFactory.SHA512.class.getName(), "PBKDF2WithSHA512");
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA1and8BIT", Pbkdf2KeyFactory.SHA1_8BIT.class.getName(), "PBKDF2withASCII", "PBKDF2with8BIT");
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA224and8BIT", Pbkdf2KeyFactory.SHA224_8BIT.class.getName());
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA256and8BIT", Pbkdf2KeyFactory.SHA256_8BIT.class.getName());
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA384and8BIT", Pbkdf2KeyFactory.SHA384_8BIT.class.getName());
        putService("SecretKeyFactory", "PBKDF2WithHmacSHA512and8BIT", Pbkdf2KeyFactory.SHA512_8BIT.class.getName());
        putService("SecretKeyFactory", "PBES2", PbeKeyFactory.PBES2.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA1AndAES_128", PbeKeyFactory.PBEWithHmacSHA1AndAES128.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA224AndAES_128", PbeKeyFactory.PBEWithHmacSHA224AndAES128.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA256AndAES_128", PbeKeyFactory.PBEWithHmacSHA256AndAES128.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA384AndAES_128", PbeKeyFactory.PBEWithHmacSHA384AndAES128.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA512AndAES_128", PbeKeyFactory.PBEWithHmacSHA512AndAES128.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA1AndAES_256", PbeKeyFactory.PBEWithHmacSHA1AndAES256.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA224AndAES_256", PbeKeyFactory.PBEWithHmacSHA224AndAES256.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA256AndAES_256", PbeKeyFactory.PBEWithHmacSHA256AndAES256.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA384AndAES_256", PbeKeyFactory.PBEWithHmacSHA384AndAES256.class.getName());
        putService("SecretKeyFactory", "PBEWithHmacSHA512AndAES_256", PbeKeyFactory.PBEWithHmacSHA512AndAES256.class.getName());
        putService("SecretKeyFactory", "PBE", PbeKeyFactory.PBE.class.getName());
        if (isDESEDESupported()) {
            putService("SecretKeyFactory", "DESede", SymmKeyFactory.DESede.class.getName(), "TripleDES");
        }

        // Signature Implementations
        if (System.getProperty("java.vendor").startsWith("Oracle") && getJavaRuntimeMajorVersion() < 26) {
            // Workaround: Signal javax.crypto.JarVerifier class that Signature support is operational
            putService("Signature", "MD5WithRSA", DummyJCEVerifierSignature.class.getName());
        }
        if (isSHA1DigestSignatureSupported()) {
            putService("Signature", "SHA1withRSA", RsaDigestSig.Sha1WithRsa.class.getName(),
                    "OID.1.2.840.113549.1.1.5", "1.2.840.113549.1.1.5",
                    "OID.1.3.14.3.2.29", "1.3.14.3.2.29");
        }
        putService("Signature", "SHA224withRSA", RsaDigestSig.Sha224WithRsa.class.getName(),
                "OID.1.2.840.113549.1.1.14", "1.2.840.113549.1.1.14");
        putService("Signature", "SHA256withRSA", RsaDigestSig.Sha256WithRsa.class.getName(),
                "OID.1.2.840.113549.1.1.11", "1.2.840.113549.1.1.11");
        putService("Signature", "SHA384withRSA", RsaDigestSig.Sha384WithRsa.class.getName(),
                "OID.1.2.840.113549.1.1.12", "1.2.840.113549.1.1.12");
        putService("Signature", "SHA512withRSA", RsaDigestSig.Sha512WithRsa.class.getName(),
                "OID.1.2.840.113549.1.1.13", "1.2.840.113549.1.1.13");
        putService("Signature", "NONEwithRSA", NoDigestSig.NoneWithRsa.class.getName());

        if (isSHA1DigestSignatureSupported()) {
            putService("Signature", "SHA1withRSAandMGF1", RsaPssDigestSig.RsaPssSha1.class.getName());
        }
        putService("Signature", "SHA224withRSAandMGF1", RsaPssDigestSig.RsaPssSha224.class.getName(),
                "SHA224withRSA/PSS");
        putService("Signature", "SHA256withRSAandMGF1", RsaPssDigestSig.RsaPssSha256.class.getName(),
                "SHA256withRSA/PSS");
        putService("Signature", "SHA384withRSAandMGF1", RsaPssDigestSig.RsaPssSha384.class.getName(),
                "SHA384withRSA/PSS");
        putService("Signature", "SHA512withRSAandMGF1", RsaPssDigestSig.RsaPssSha512.class.getName(),
                "SHA512withRSA/PSS");
        putService("Signature", "RSASSA-PSS", RsaPssGeneralSig.class.getName(), "PSS",
                "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10");
        putService("Signature", "NONEwithECDSA", NoDigestSig.NoneWithEcdsa.class.getName());
        if (isSHA1DigestSignatureSupported()) {
            putService("Signature", "SHA1withECDSA", EcdsaDigestSig.Sha1WithEcdsa.class.getName(),
                    "OID.1.2.840.10045.4.1", "1.2.840.10045.4.1");
        } else if (getJavaRuntimeMajorVersion() < 27) {
            // Workaround: Signal the SunJSSE that EC support is available
            putService("Signature", "SHA1withECDSA", DummySunJSSESignature.class.getName());
        }
        putService("Signature", "SHA224withECDSA", EcdsaDigestSig.Sha224WithEcdsa.class.getName(),
                "OID.1.2.840.10045.4.3.1", "1.2.840.10045.4.3.1");
        putService("Signature", "SHA256withECDSA", EcdsaDigestSig.Sha256WithEcdsa.class.getName(),
                "OID.1.2.840.10045.4.3.2", "1.2.840.10045.4.3.2");
        putService("Signature", "SHA384withECDSA", EcdsaDigestSig.Sha384WithEcdsa.class.getName(),
                "OID.1.2.840.10045.4.3.3", "1.2.840.10045.4.3.3");
        putService("Signature", "SHA512withECDSA", EcdsaDigestSig.Sha512WithEcdsa.class.getName(),
                "OID.1.2.840.10045.4.3.4", "1.2.840.10045.4.3.4");

        if (isDSASupported()) {
            putService("Signature", "NONEwithDSA", NoDigestSig.NoneWithDsa.class.getName(),
                    "RawDSA");
            if (isSHA1DigestSignatureSupported()) {
                putService("Signature", "SHA1withDSA", DsaDigestSig.Sha1WithDsa.class.getName(),
                        "DSA", "DSS", "SHA/DSA", "SHA-1/DSA", "SHA1/DSA", "SHAwithDSA", "DSAWithSHA1",
                        "OID.1.2.840.10040.4.3", "1.2.840.10040.4.3",
                        "OID.1.3.14.3.2.13", "1.3.14.3.2.13",
                        "OID.1.3.14.3.2.27", "1.3.14.3.2.27");
            }
            putService("Signature", "SHA224withDSA", DsaDigestSig.Sha224WithDsa.class.getName(),
                    "OID.2.16.840.1.101.3.4.3.1", "2.16.840.1.101.3.4.3.1");
            putService("Signature", "SHA256withDSA", DsaDigestSig.Sha256WithDsa.class.getName(),
                    "OID.2.16.840.1.101.3.4.3.2", "2.16.840.1.101.3.4.3.2");
            putService("Signature", "SHA384withDSA", DsaDigestSig.Sha384WithDsa.class.getName(),
                    "OID.2.16.840.1.101.3.4.3.3", "2.16.840.1.101.3.4.3.3");
            putService("Signature", "SHA512withDSA", DsaDigestSig.Sha512WithDsa.class.getName(),
                    "OID.2.16.840.1.101.3.4.3.4", "2.16.840.1.101.3.4.3.4");
        }
    }

    private void putService(String type, String alg, String className, String...aliases) {
        putService(new Provider.Service(this, type, alg, className, Arrays.asList(aliases), null));
    }

    private void putService(String type, String alg, String className, Map<String,String> attrs, String...aliases) {
        // Lazy state evaluation of legacy property put() calls cause
        // previously processed putService() registrations of prngAlgos to be forgotten.
        // Workaround: Use legacy properties put() calls to register SecureRandom algorithms.
        if (type.equals("SecureRandom")) {
            putLegacy(type, alg, className, Arrays.asList(aliases), attrs);
        } else {
            putService(new Provider.Service(this, type, alg, className, Arrays.asList(aliases), attrs));
        }
    }

    private void putLegacy(String type, String alg, String className, List<String> aliases, Map<String,String> attrs)
    {
        put(type + "." + alg, className);
        aliases.forEach(alias ->  put("Alg.Alias." + type + "." + alias, alg));
        attrs.forEach((key, value) -> put(type + "." + alg + " " + key, value));
    }

    @Override
    public Provider.Service getService(String type, String algorithm) {
        Provider.Service service = super.getService(type, algorithm);

        DEBUG_ALG.println(() -> "Getting algorithm: " + (service != null ? service.toString() : type + "." + algorithm + " (not supported)"));
        return service;
    }

    /**
     * Entry point for the {@code JipherJCE} provider.
     *
     * <p>This method prints the provider information to {@code System.out}. If the
     * underlying OpenSSL native library cannot be loaded, it falls back to printing
     * basic provider information (without OpenSSL details) and writes the cause of
     * the failure to {@code System.err}.</p>
     *
     * @param args command-line arguments (currently unused)
     */
    public static void main(String[] args) {
        try {
            System.out.println(new JipherJCE().getInfo());
        } catch (ProviderException e) {
            System.out.println(info(false));
            System.err.print("OpenSSL version information unavailable due to ");
            e.printStackTrace();
        }
    }

}
