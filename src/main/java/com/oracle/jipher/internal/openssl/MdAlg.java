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

package com.oracle.jipher.internal.openssl;

/**
 * Message Digest algorithms.
 */
public enum MdAlg {

    SHA1("SHA-1",  "1.3.14.3.2.26", "SHA", "SHA1"),
    SHA224("SHA-224", "2.16.840.1.101.3.4.2.4","SHA224"),
    SHA256("SHA-256", "2.16.840.1.101.3.4.2.1","SHA256"),
    SHA384("SHA-384", "2.16.840.1.101.3.4.2.2","SHA384"),
    SHA512("SHA-512", "2.16.840.1.101.3.4.2.3","SHA512"),
    SHA3_224("SHA3-224",  "2.16.840.1.101.3.4.2.7"),
    SHA3_256("SHA3-256",  "2.16.840.1.101.3.4.2.8"),
    SHA3_384("SHA3-384",  "2.16.840.1.101.3.4.2.9"),
    SHA3_512("SHA3-512",  "2.16.840.1.101.3.4.2.10");

    private final String standardName;
    private final String oid;
    private final String[] aliases;

    MdAlg(String standardName, String oid, String... aliases) {
        this.standardName = standardName;
        this.oid = oid;
        this.aliases = aliases;
    }

    public String getAlg() {
        return this.standardName;
    }

    public String getOID() {
        return this.oid;
    }

    public static MdAlg byName(String alg) {
        for (MdAlg md : MdAlg.values()) {
            if (md.standardName.equalsIgnoreCase(alg)) {
                return md;
            }
            if (md.oid.equalsIgnoreCase(alg) || ("OID." + md.oid).equalsIgnoreCase(alg)) {
                return md;
            }
            if (md.aliases != null) {
                for (String alias : md.aliases) {
                    if (alias.equalsIgnoreCase(alg)) {
                        return md;
                    }
                }
            }
        }
        return null;
    }
}
