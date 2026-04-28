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

package com.oracle.jiphertest.leak.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback.OpType;
import com.oracle.jipher.internal.openssl.OpenSsl;

public class NativeObjectUsageMonitor {
    static final OpenSsl INSTANCE = OpenSslFactoryUtil.getOpenSslSingleton();
    static final List<Error> ERRORS = Collections.synchronizedList(new ArrayList<>());
    static final Map<Long, Allocation> ALLOCATION_MAP = Collections.synchronizedMap(new HashMap<>());

    static public void callbackHandler(OpType opType, String funcName, long address) {

        StackTraceElement[] stackTrace;
        Allocation allocation;

        switch (opType) {
            case NEW:
                stackTrace = Thread.currentThread().getStackTrace();
                allocation = ALLOCATION_MAP.computeIfAbsent(address, a -> new Allocation(funcName, stackTrace));

                // If the Map already contained an entry for address
                if (stackTrace != allocation.getAllocatorStackTrace()) {
                    // Calling 'EVP_*_fetch' for an algorithm that has already been fetched is equivalent to
                    // calling up ref.
                    if (funcName.endsWith("_fetch")) {
                        allocation.addReference(funcName, stackTrace);
                    } else {
                        throwError(opType, funcName, address);
                    }
                }
                break;

            case UP_REF:
                allocation = ALLOCATION_MAP.get(address);
                if (allocation != null) {
                    stackTrace = Thread.currentThread().getStackTrace();
                    allocation.addReference(funcName, stackTrace);
                } else {
                    throwError(opType, funcName, address);
                }
                break;

            case FREE:
                synchronized (ALLOCATION_MAP) {
                    allocation = ALLOCATION_MAP.get(address);
                    if (allocation != null) {
                        if (allocation.decrementReferenceCount() == 0) {
                            ALLOCATION_MAP.remove(address);
                        }
                    } else {
                        throwError(opType, funcName, address);
                    }
                }
        }
    }

    // Throwing an error during a test execution will cause the test to be aborted.
    // No error will be reported but the test will simply not be listed as having been run.
    // Storing the error in the ERRORS list ensures that any errors thrown can
    // also be reported by calling reportErrors() at the end of a test suite run.
    static void throwError(OpType opType, String funcName, Long address) throws Error {
        Error error = new Error(opType, funcName, address);
        ERRORS.add(error);
        throw error;
    }

    public static void clearObjectPools() {
        INSTANCE.clearObjectPools();
    }

    public static void activate() {
        // Guard against improper usage
        if (!Boolean.getBoolean("java.testing.lifecycleHooks.enable")) {
            throw new java.lang.Error(
                    "System property 'java.testing.lifecycleHooks.enable' not set to 'true'.\n" +
                    "Setting a native object lifecycle callback will have no impact.");
        }
        INSTANCE.setNativeObjectLifecycleCallback(NativeObjectUsageMonitor::callbackHandler);
    }

    public static void deactivate() {
        INSTANCE.clearNativeObjectLifecycleCallback();
    }

    public static void reset() {
        ERRORS.clear();
        ALLOCATION_MAP.clear();
    }

    public static boolean detectedErrors() {
        return !ERRORS.isEmpty();
    }

    public static String reportErrors() {
        StringBuilder sb = new StringBuilder();

        for (Error error : ERRORS) {
            sb.append(error).append("\n");
            for (StackTraceElement ste : error.getStackTrace()) {
                sb.append("\tat ").append(ste).append('\n');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    public static boolean isTrackingLiveObjects() {
        return !ALLOCATION_MAP.isEmpty();
    }

    public static String reportLiveObjects() {
        StringBuilder sb = new StringBuilder();

        for (Map.Entry<Long,Allocation> entry : ALLOCATION_MAP.entrySet()) {
            sb.append("0x").append(Long.toHexString(entry.getKey())).append(" ").append(entry.getValue());
        }
        return sb.toString();
    }

    public static final class Error extends java.lang.Error {
        final OpType opType;
        final String funcName;
        final Long address;

        Error(OpType opType, String funcName, Long address) {
            this.opType = opType;
            this.funcName = funcName;
            this.address = address;
        }

        @Override
        public String getMessage() {
            String action = switch (opType) {
                case NEW -> "realloc an"; // Called when a NEW call returns an address that that has already been allocated.
                case FREE -> "free an unknown";
                case UP_REF -> "up reference an unknown";
            };

             return "Attempt to " + action + " OpenSSL object at address 0x" +
                   Long.toHexString(address) + " using " + funcName;
        }
    }

    record Reference(String funcName, StackTraceElement[] stackTrace) {

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(this.funcName).append('\n');
            for (StackTraceElement ste : this.stackTrace) {
                sb.append("\tat ").append(ste).append('\n');
            }
            return sb.toString();
        }
    }

    static final class Allocation {
        final Reference allocator;
        int referenceCount;  // The number of live references to this allocation (including original allocator)

        // OpenSSL supports 'new', 'up_ref' and 'free'.  On a 'free' call it is impossible to know which 'new' or
        // 'up_ref' call the 'free' corresponds to.  Consequently, the following list contains all references ever made
        // to the allocation (typically via an up_ref call) even if free has subsequently been called one or more times.
        // This means that references.size() may be greater than referenceCount.
        final List<Reference> references;

        StackTraceElement[] getAllocatorStackTrace() {
            return allocator.stackTrace;
        }

        Allocation(String funcName, StackTraceElement[] stackTrace) {
            referenceCount = 1;
            allocator = new Reference(funcName, stackTrace);
            references = new ArrayList<>();
        }

        synchronized void addReference(String funcName, StackTraceElement[] stackTrace) {
            references.add(new Reference(funcName, stackTrace));
            referenceCount++;
        }

        synchronized int decrementReferenceCount() {
            this.referenceCount--;
            return this.referenceCount;
        }

        synchronized public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Allocated by ");
            sb.append(allocator);

            if (!references.isEmpty()) {
                sb.append("Referenced by: \n");
                for (Reference reference : references) {
                    sb.append(reference);
                }
            }
            return sb.toString();
        }
    }
}
