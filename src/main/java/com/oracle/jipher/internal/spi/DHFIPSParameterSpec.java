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

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;

/**
 * FIPS-compatible Diffie-Hellman parameter specification.
 * <p>
 * This class extends {@link DHParameterSpec} by adding
 * <ul>
 *     <li> the prime order {@code q} of the prime field {@code p} (where {@code q} divides {@code p-1})</li>
 *     <li> an optional cofactor parameter that satisfies {@code p = j.q + 1}</li>
 *     <li> an optional seed and parameter generation counter (see {@link DHFIPSParameterValidationSpec})</li>
 * </ul>
 * These additional optional parameters facilitate verification of the group parameters.
 */
public class DHFIPSParameterSpec extends DHParameterSpec {

    /** Prime factor {@code q} of {@code p-1}. Must be non-null. */
    private final BigInteger q;
    /** Optional cofactor parameter {@code j} satisfying {@code p = j.q + 1}. May be {@code null}. */
    private final BigInteger j;

    /** Optional validation specification for the domain-parameter generation process. */
    DHFIPSParameterValidationSpec validation;

    /**
     * Constructs a DH parameter spec with the essential values {@code p}, {@code q}, and {@code g}.
     * The optional cofactor value {@code j} and validation spec are set to {@code null}.
     *
     * @param p the prime modulus
     * @param q the prime factor of {@code p-1}
     * @param g the generator
     */
    public DHFIPSParameterSpec(BigInteger p, BigInteger q, BigInteger g) {
        this(p, q, g, null, null);
    }

    /**
     * Constructs a DH parameter spec with optional cofactor value {@code j} and validation spec.
     *
     * @param p the prime modulus
     * @param q the prime factor of {@code p-1}
     * @param g the generator
     * @param j optional cofactor value satisfying {@code p = j.q + 1} (may be {@code null})
     * @param validation optional validation spec (may be {@code null})
     */
    public DHFIPSParameterSpec(BigInteger p, BigInteger q, BigInteger g, BigInteger j,
                               DHFIPSParameterValidationSpec validation) {
        this(p, q, g, j, validation, 0);
    }

    /**
     * Full constructor allowing specification of the private-value length {@code l}.
     *
     * @param p the prime modulus (must be non-null)
     * @param q the prime factor of {@code p-1} (must be non-null)
     * @param g the generator (must be non-null)
     * @param j optional cofactor value satisfying {@code p = j.q + 1}
     * @param validation optional validation spec
     * @param l the private-value length in bits; passed to the superclass
     * @throws IllegalArgumentException if {@code p}, {@code q}, or {@code g} are {@code null}
     */
    public DHFIPSParameterSpec(BigInteger p, BigInteger q, BigInteger g, BigInteger j,
                               DHFIPSParameterValidationSpec validation, int l) {
        super(p, g, l);
        if (p == null || q == null || g == null) {
            throw new IllegalArgumentException("p, q and g must be non-null");
        }
        this.q = q;
        this.j = j;
        this.validation = validation;
    }

    /** Returns the prime factor {@code q} of {@code p-1}. */
    public BigInteger getQ() {
        return this.q;
    }

    /** Returns the optional cofactor {@code j} value (may be {@code null}). */
    public BigInteger getJ() {
        return this.j;
    }

    /** Returns the optional {@link DHFIPSParameterValidationSpec} used for validation. */
    public DHFIPSParameterValidationSpec getParameterValidationSpec() {
        return validation;
    }
}
