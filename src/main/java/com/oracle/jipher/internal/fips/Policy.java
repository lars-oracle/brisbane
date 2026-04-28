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

package com.oracle.jipher.internal.fips;

import java.security.Key;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import javax.crypto.interfaces.DHKey;

/**
 * A FIPS Enforcement policy.
 * <p>
 * A policy consists of a set of rules.
 * Two 'types' of rules are supported: strength and algorithm rules.
 */
public class Policy {

    private final Map<RuleId, Rule> rules;
    private final String name;

    private Policy(String name, Map<RuleId, Rule> rules) {
        this.name = name;
        this.rules = rules;
    }

    String getPolicyName() {
        return this.name;
    }

    /**
     * Check the key type used for the crypto operation.
     * <p>
     * Example: for signature generation, check the key type is not DSA
     *
     * @param op the operation
     * @param keyType the key type parameter
     */
    public void checkKeyType(CryptoOp op, String keyType) {
        Rule rule = this.rules.get(new RuleId(op, Type.KEY_TYPE, null));
        if (rule != null) {
            Fips.DEBUG.println(() -> "Checking " + op + " key type " + keyType + " against FIPS Policy (" + this.name + ")");
            if (!rule.test(keyType)) {
                Fips.DEBUG.println("FIPS alg check failed.");
                throw new FIPSPolicyException("FIPS violation: policy " + this.name + " does not allow " + keyType + " for operation " + op.toString().toLowerCase());
            }
        }
    }

    /**
     * Check the algorithm parameter for the crypto operation.
     * <p>
     * Example: for signature signing, check the digest parameter.
     *
     * @param op the operation
     * @param alg the algorithm parameter
     */
    public void checkAlg(CryptoOp op, String alg) {
        Rule rule = this.rules.get(new RuleId(op, Type.ALG));
        if (rule != null) {
            Fips.DEBUG.println(() -> "Checking " + op + " algorithm parameter " + alg + " against FIPS Policy (" + this.name + ")");
            if (!rule.test(alg)) {
                Fips.DEBUG.println("FIPS alg check failed.");
                throw new FIPSPolicyException("FIPS violation: policy " + this.name + " does not allow " + alg + " for operation " + op.toString().toLowerCase());
            }
        }
    }

    /**
     * Check a strength of a key size parameter for the given operation and key algorithm.
     * <p>
     * Note that only DSA key strength can include more than size parameter.
     *
     * @param op the operation
     * @param alg the key algorithm
     * @param size the size (or sizes) to check
     */
    public void checkStrength(CryptoOp op, String alg, int... size) {
        Rule rule = this.rules.get(new RuleId(op, Type.STRENGTH, alg));
        if (rule != null) {
            Fips.DEBUG.println(() -> "Checking " + op + " " + alg + " size against FIPS Policy (" + this.name + ")");
            if (size.length == 1 && !alg.equals("DSA")) {
                if (!rule.test(size[0])) {
                    Fips.DEBUG.println("FIPS strength check failed.");
                    throw new FIPSPolicyException("FIPS violation: policy " + this.name + " does not allow " + alg + " strength/key size " + size[0] + " for operation " + op.toString().toLowerCase());
                }
            } else {
                if (!rule.test(size)) {
                    Fips.DEBUG.println("FIPS strength check failed.");
                    throw new FIPSPolicyException("FIPS violation: policy " + this.name + " does not allow " + alg + " strength/key size " + Arrays.toString(size) + " for operation " + op.toString().toLowerCase());
                }
            }
        }
    }

    /**
     * Check the strength of the asymmetric key against the policy for the given operation.
     * @param op the crypto operation
     * @param key the asymmetric key to check
     */
    public void checkStrength(CryptoOp op, Key key) {
        if (key instanceof RSAKey) {
            checkStrength(op, "RSA", ((RSAKey) key).getModulus().bitLength());
        } else if (key instanceof DSAKey) {
            checkStrength(op, "DSA", ((DSAKey) key).getParams().getP().bitLength(), ((DSAKey) key).getParams().getQ().bitLength());
        } else if (key instanceof ECKey) {
            checkStrength(op, "EC", ((ECKey) key).getParams().getOrder().bitLength());
        } else if (key instanceof DHKey) {
            checkStrength(op, "DH", ((DHKey) key).getParams().getP().bitLength());
        } else {
            throw new IllegalArgumentException("Unexpected key for checking strength");
        }
    }

    /**
     * Enum that identifies type of enforcement rule.
     */
    enum Type {
        STRENGTH, KEY_TYPE, ALG,
    }

    /**
     * Builder class for creating a Policy of rules.
     */
    static class Builder {

        final String name;
        final Map<RuleId, Rule> rules = new HashMap<>();

        Builder(String name) {
            this.name = name;
        }

        Builder strengthRule(String alg, Predicate<Object> checker, CryptoOp... ops) {
            for (CryptoOp op : ops) {
                rules.put(new RuleId(op, Type.STRENGTH, alg), new Rule(checker));
            }
            return this;
        }

        Builder keyTypeRule(Predicate<Object> checker, CryptoOp... ops) {
            for (CryptoOp op : ops) {
                rules.put(new RuleId(op, Type.KEY_TYPE, null), new Rule(checker));
            }
            return this;
        }


        Builder algRule(Predicate<Object> checker, CryptoOp... ops) {
            for (CryptoOp op : ops) {
                rules.put(new RuleId(op, Type.ALG, null), new Rule(checker));
            }
            return this;
        }

        Policy build() {
            return new Policy(name, rules);
        }

    }

    private record RuleId(CryptoOp op, Type type, String keyOrService) {
        private RuleId(CryptoOp op, Type type) {
            this(op, type, null);
        }
    }

    private record Rule(Predicate<Object> checker) {
        private boolean test(Object object) {
            return checker.test(object);
        }
    }
}
