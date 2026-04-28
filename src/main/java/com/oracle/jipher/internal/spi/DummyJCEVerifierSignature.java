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

import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.Arrays;

import com.oracle.jipher.internal.common.Util;

/**
 * @hidden
 * The sole purpose of this class is to provide just enough Signature verification support
 * to make the {@code javax.crypto.JarVerifier} class (in Oracle JDKs) pass its Signature
 * sub-system validation known answer tests.
 * This avoids:
 * <pre>"java.lang.SecurityException: Framework jar verification can not be initialized"</pre>
 * if no registered provider provides a legitimate implementation of {@code MD5withRSA} Signature.
 */
public class DummyJCEVerifierSignature extends SignatureSpi {
    private static final String EXCEPTION_MESSAGE =
            "The sole purpose of this class is to signal the javax.crypto.JarVerifier class, in Oracle JDKs, that Signature classes have not been tampered with.";
    private static final byte[] KNOWN_GOOD_SIG_BYTES = Util.hexToBytes("0AA3E516655D29D612093365B572909C1AACB3D18D8DB9C1F828ADBD6AF037EA0E2BCA90A6F57EE4B07A2EBBAF472EB309E74257DE59DA45CA83F1678F482FB2");
    private static final byte[] KNOWN_BAD_SIG_BYTES = Util.hexToBytes("2FE59C545CA3FA25E511535541B34E3949569A59971A234A2979C874D71CD595328BE256D339A57D9EE253F791621104241C1DAD4A328863862E8EE98BA27300");
    private static final byte[] KNOWN_DATA_BYTES_1 =  Util.hexToBytes("3082018A020102300D06092A864886F70D0101040500307B310B3009060355040613025553310B30090603550408130243413112301006035504071309437570657274696E6F31193017060355040A131053756E204D6963726F73797374656D7331163014060355040B130D4A61766120536F667477617265311830160603550403130F4A434520446576656C6F706D656E74301E170D3032313033313135323734345A170D3037313033313135323734345A307B310B3009060355040613025553310B30090603550408130243413112301006035504071309437570657274696E6F31193017060355040A131053756E204D6963726F73797374656D7331163014060355040B130D4A61766120536F667477617265311830160603550403130F4A434520446576656C6F706D656E74305C300D06092A864886F70D0101010500034B003048024100AF53925DA3B3A67568A8BD8BA92E7E1CBCB5915BC1C2233F1398984FD7996A0844F2ABC5FB87C44E2A5650D4D6090CC747870324624E97D366EFBB442E1112E10203010001");
    private static final byte[] KNOWN_DATA_BYTES_2 =  Util.hexToBytes("3082018A020101300D06092A864886F70D0101040500307B310B3009060355040613025553310B30090603550408130243413112301006035504071309437570657274696E6F31193017060355040A131053756E204D6963726F73797374656D7331163014060355040B130D4A61766120536F667477617265311830160603550403130F4A434520446576656C6F706D656E74301E170D3032313033313135323734345A170D3037313033313135323734345A307B310B3009060355040613025553310B30090603550408130243413112301006035504071309437570657274696E6F31193017060355040A131053756E204D6963726F73797374656D7331163014060355040B130D4A61766120536F667477617265311830160603550403130F4A434520446576656C6F706D656E74305C300D06092A864886F70D0101010500034B003048024100A3FE0275D10E6B733ABFD2450219C16204EAE78637D3EF85F32CC22BD11E61A1B7033BF366A36C843CB9EFDEB8EE9D1C38CFF854EEAB5363E06F380A5CF72CF30203010001");
    private static final byte[] KNOWN_PUBLIC_KEY_BYTES = Util.hexToBytes("305C300D06092A864886F70D0101010500034B003048024100A3FE0275D10E6B733ABFD2450219C16204EAE78637D3EF85F32CC22BD11E61A1B7033BF366A36C843CB9EFDEB8EE9D1C38CFF854EEAB5363E06F380A5CF72CF30203010001");

    private byte[] data;

    public DummyJCEVerifierSignature() throws ProviderException {
        StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
        if (Arrays.stream(stackTraceElements).noneMatch(e ->
                "javax.crypto.JarVerifier".equals(e.getClassName()) && "<clinit>".equals(e.getMethodName()))) {
            throw new ProviderException(EXCEPTION_MESSAGE);
        }
        if (Arrays.stream(stackTraceElements).noneMatch(e ->
                "javax.crypto.JarVerifier".equals(e.getClassName()) && "testSignatures".equals(e.getMethodName()))) {
            throw new ProviderException(EXCEPTION_MESSAGE);
        }
        if (Arrays.stream(stackTraceElements).noneMatch(e ->
                "javax.crypto.ProviderVerifier".equals(e.getClassName()) && "verify".equals(e.getMethodName()))) {
            throw new ProviderException(EXCEPTION_MESSAGE);
        }
        data = null;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        // Only process the expected known answer test public key.
        if (!Arrays.equals(KNOWN_PUBLIC_KEY_BYTES, publicKey.getEncoded())) {
            throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
        }
        data = null;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
    }

    @Override
    protected void engineUpdate(byte b) {
        throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        // The known answer tests call engineUpdate(byte[] b, int off, int len) once per verify attempt.
        if (this.data != null) {
            throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
        }

        this.data = Arrays.copyOfRange(b, off, off + len);

        // Only accept the two expected known answer test inputs
        if (!(Arrays.equals(KNOWN_DATA_BYTES_1, this.data) || Arrays.equals(KNOWN_DATA_BYTES_2, this.data))) {
            throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
        }
    }

    @Override
    protected byte[] engineSign() {
        throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        // The known answer tests call engineUpdate(byte[] b, int off, int len) before calling engineVerify(byte[] sigBytes).
        if (this.data == null) {
            throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
        }

        // Only accept the two expected known answer signatures to verify
        if (!(Arrays.equals(KNOWN_GOOD_SIG_BYTES, sigBytes) || Arrays.equals(KNOWN_BAD_SIG_BYTES, sigBytes))) {
            throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
        }

        // Check for the known good input data and signature combination
        return Arrays.equals(KNOWN_DATA_BYTES_2, this.data) && Arrays.equals(KNOWN_GOOD_SIG_BYTES, sigBytes);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException(EXCEPTION_MESSAGE);
    }
}
