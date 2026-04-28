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

package com.oracle.jipher.internal.openssl.ffm;

import java.lang.foreign.AddressLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.openssl.EVP_CIPHER_CTX;
import com.oracle.jipher.internal.openssl.EVP_KDF;
import com.oracle.jipher.internal.openssl.EVP_KDF_CTX;
import com.oracle.jipher.internal.openssl.EVP_MAC;
import com.oracle.jipher.internal.openssl.EVP_MAC_CTX;
import com.oracle.jipher.internal.openssl.EVP_MD_CTX;
import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.EVP_RAND;
import com.oracle.jipher.internal.openssl.EVP_RAND_CTX;
import com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback;
import com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback.OpType;
import com.oracle.jipher.internal.openssl.OSSL_LIB_CTX;
import com.oracle.jipher.internal.openssl.OSSL_PARAM;
import com.oracle.jipher.internal.openssl.OSSL_PROVIDER;
import com.oracle.jipher.internal.openssl.OpenSsl;
import com.oracle.jipher.internal.openssl.OpenSslErrorCode;
import com.oracle.jipher.internal.openssl.OpenSslException;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback.OpType.FREE;
import static com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback.OpType.NEW;
import static com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback.OpType.UP_REF;
import static com.oracle.jipher.internal.openssl.ffm.EvpMacCtx.getEvpMacCtxAutoArena;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_SEQUENCE_PTR;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.OfInt;
import static java.lang.foreign.ValueLayout.OfLong;

public final class FfmOpenSsl implements OpenSsl {

    private static final Debug LOG_NATIVE = Debug.getInstance("native");

    static final int INFO_SELECTOR_OFFSET = 1001;
    static final long UNBOUNDED_MAX = 1048576L; // 1 MiB

    /**
     * The maximum amount of data to process in a native method called via
     * a downcall created with the HEAP_ACCESS LinkerOption (i.e.
     * Linker.Option.critical(true)).
     * Limiting the amount of data processed in such a call is done to ensure
     * a bounded TTSP (time to safepoint).
     */
    static final long TTSP_MAX_DATA = 16384L; // 16 KiB

    @FunctionalInterface
    interface Callback {
        boolean call(MemorySegment ptr);
    }

    public enum LinkerOption {
        NONE, OPTIONAL, CRITICAL, HEAP_ACCESS
    }

    static final OfInt C_INT = JAVA_INT;            // 'I'
    static final ValueLayout C_LONG;                // 'L'
    static final OfLong C_LONG_LONG = JAVA_LONG;    // 'J'
    static final OfLong C_SIZE_T = JAVA_LONG;       // 'S'
    static final AddressLayout C_POINTER = ADDRESS; // 'M'
    static final AddressLayout C_POINTER_UNBOUNDED = C_POINTER.withTargetLayout(
            MemoryLayout.sequenceLayout(UNBOUNDED_MAX, JAVA_BYTE)); // 'U'

    static final SymbolLookup LIBCRYPTO;
    static final Linker LINKER;
    static final MethodHandles.Lookup MH_LOOKUP;

    static final boolean LIFECYCLE_HOOKS_ENABLED;
    static volatile NativeObjectLifecycleCallback lifecycleCallback;

    static final String ERROR_CODE_FUNCDESC = "()L";
    static final String DO_ALL_PROVIDED_FUNCDESC = "(MMM)V";
    static final String DO_ALL_FUNCDESC = "(MMM)Z";
    static final String FETCH_FUNCDESC = "(MMM)M";
    static final String IS_A_FUNCDESC = "(MM)Z";
    static final String UP_REF_FUNCDESC = "(M)I";
    static final String NEW_FUNCDESC = "()M";
    static final String NEW_FROM_TYPE_FUNCDESC = "(M)M";
    static final String NEW_FROM_TYPE_AND_PARENT_FUNCDESC = "(MM)M";
    static final String DUP_FUNCDESC = "(M)M";
    static final String COPY_FUNCDESC = "(MM)I";
    static final String RETURN_CONST_PARAMS_FUNCDESC = "(M)P";
    static final String RETURN_SELECTED_CONST_PARAMS_FUNCDESC = "(MI)P";
    static final String PARAMS_FUNCDESC = "(MM)I";
    static final String BOOL_FUNCDESC = "(M)Z";
    static final String INT_FUNCDESC = "(M)I";
    static final String LONG_FUNCDESC = "(M)L";
    static final String SIZE_FUNCDESC = "(M)S";
    static final String PTR_FUNCDESC = "(M)M";
    static final String GET0_STRING_FUNCDESC = "(M)U";
    static final String FREE_FUNCDESC = "(M)V";
    // ERROR_CALLBACK_FUNCDESC: "(USM)I";
    static final FunctionDescriptor ERROR_CALLBACK_FUNCDESC = FunctionDescriptor.of(C_INT, C_POINTER_UNBOUNDED, C_SIZE_T, C_POINTER);
    // NAME_CALLBACK_FUNCDESC: "(UM)V";
    static final FunctionDescriptor NAME_CALLBACK_FUNCDESC = FunctionDescriptor.ofVoid(C_POINTER_UNBOUNDED, C_POINTER);
    // ALL_PROVIDED_CALLBACK_FUNCDESC: "(MM)V";
    static final FunctionDescriptor ALL_PROVIDED_CALLBACK_FUNCDESC = FunctionDescriptor.ofVoid(C_POINTER, C_POINTER);
    // PROVIDER_CALLBACK_FUNCDESC: "(MM)I";
    static final FunctionDescriptor PROVIDER_CALLBACK_FUNCDESC = FunctionDescriptor.of(C_INT, C_POINTER, C_POINTER);
    static final String VERSION_INT_FUNCDESC = "()I";
    static final String INFO_STRING_FUNCDESC = "(I)U";

    static final MethodHandle CHECK_ZERO_NEG_RETURN_VALUE_FUNC;
    static final MethodHandle CHECK_NULL_RETURN_VALUE_FUNC;

    static final MethodHandle LIFECYCLE_HOOK_FUNC;
    static final MethodHandle LIFECYCLE_HOOK_P_PKEY_OUT_FUNC;

    static class CallbackContext {
        final Callback callback;
        Throwable throwable;
        CallbackContext(Callback callback) {
            this.callback = callback;
        }
        boolean call(MemorySegment memorySegment) {
            return this.callback.call(memorySegment);
        }
        boolean hasPendingException() {
            return this.throwable != null;
        }
        void catchException(Throwable throwable) {
            this.throwable = throwable;
        }
        void rethrowException() {
            if (hasPendingException()) {
                if (this.throwable instanceof RuntimeException runtimeException) {
                    throw runtimeException;
                }
                if (this.throwable instanceof Error error) {
                    throw error;
                }
                throw new AssertionError(this.throwable);
            }
        }
    }
    static final ScopedValue<CallbackContext> CALLBACK_CONTEXT = ScopedValue.newInstance();
    static final MemorySegment ERROR_CALLBACK_UPCALL_STUB;
    static final MemorySegment NAME_CALLBACK_UPCALL_STUB;
    static final MemorySegment ALL_PROVIDED_CALLBACK_UPCALL_STUB;
    static final MemorySegment PROVIDER_CALLBACK_UPCALL_STUB;

    static final MethodHandle OPENSSL_INIT_CRYPTO_FUNC;
    static final MethodHandle OPENSSL_VERSION_MAJOR_FUNC;
    static final MethodHandle OPENSSL_VERSION_MINOR_FUNC;
    static final MethodHandle OPENSSL_VERSION_PATCH_FUNC;
    static final MethodHandle OPENSSL_VERSION_FUNC;
    static final MethodHandle OPENSSL_INFO_FUNC;
    static final MethodHandle OPENSSL_VERSION_BUILD_METADATA_FUNC;

    static final MethodHandle ERR_GET_ERROR_FUNC;
    static final MethodHandle ERR_PEEK_ERROR_FUNC;
    static final MethodHandle ERR_PEEK_LAST_ERROR_FUNC;
    static final MethodHandle ERR_PRINT_ERRORS_CB_FUNC;
    static final MethodHandle ERR_CLEAR_ERROR_FUNC;

    static {
        LIBCRYPTO = OpenSslLoader.libCrypto;
        if (LIBCRYPTO == null) {
            throw new AssertionError("FfmOpenSsl static initialization triggered prematurely");
        }
        LIFECYCLE_HOOKS_ENABLED = OpenSslLoader.lifecycleHooksEnabled;
        LINKER = Linker.nativeLinker();

        // C_LONG is JAVA_LONG on Linux 64 bit (LP64), JAVA_INT on Windows 64 bit (LLP64)
        // See: https://en.wikipedia.org/wiki/64-bit_computing
        C_LONG = (ValueLayout) LINKER.canonicalLayouts().get("long");

        MH_LOOKUP = MethodHandles.lookup();

        MethodHandle errorCallbackFunc;
        MethodHandle ptrCallbackFunc;
        MethodHandle providerCallbackFunc;
        try {
            CHECK_ZERO_NEG_RETURN_VALUE_FUNC = MH_LOOKUP.findStatic(FfmOpenSsl.class, "checkReturnValue",
                    MethodType.methodType(void.class, int.class, String.class));
            CHECK_NULL_RETURN_VALUE_FUNC = MH_LOOKUP.findStatic(FfmOpenSsl.class, "checkReturnValue",
                    MethodType.methodType(MemorySegment.class, MemorySegment.class, String.class));

            LIFECYCLE_HOOK_FUNC = MH_LOOKUP.findStatic(FfmOpenSsl.class, "lifecycleHook",
                    MethodType.methodType(MemorySegment.class, OpType.class, String.class, MemorySegment.class));
            LIFECYCLE_HOOK_P_PKEY_OUT_FUNC = MH_LOOKUP.findStatic(FfmOpenSsl.class, "lifecycleHookPPkeyOut",
                    MethodType.methodType(int.class, OpType.class, String.class, Throwable.class, int.class, MemorySegment.class));

            errorCallbackFunc = MH_LOOKUP.findStatic(FfmOpenSsl.class, "errorCallback",
                    MethodType.methodType(int.class, MemorySegment.class, long.class, MemorySegment.class));
            ptrCallbackFunc = MH_LOOKUP.findStatic(FfmOpenSsl.class, "ptrCallback",
                    MethodType.methodType(void.class, MemorySegment.class, MemorySegment.class));
            providerCallbackFunc = MH_LOOKUP.findStatic(FfmOpenSsl.class, "providerCallback",
                    MethodType.methodType(int.class, MemorySegment.class, MemorySegment.class));
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new AssertionError(e);
        }
        ERROR_CALLBACK_UPCALL_STUB = LINKER.upcallStub(errorCallbackFunc, ERROR_CALLBACK_FUNCDESC, Arena.global());
        NAME_CALLBACK_UPCALL_STUB = LINKER.upcallStub(ptrCallbackFunc, NAME_CALLBACK_FUNCDESC, Arena.global());
        ALL_PROVIDED_CALLBACK_UPCALL_STUB = LINKER.upcallStub(ptrCallbackFunc, ALL_PROVIDED_CALLBACK_FUNCDESC, Arena.global());
        PROVIDER_CALLBACK_UPCALL_STUB = LINKER.upcallStub(providerCallbackFunc, PROVIDER_CALLBACK_FUNCDESC, Arena.global());

        OPENSSL_INIT_CRYPTO_FUNC = downcallHandleCheckZeroNeg(
                "OPENSSL_init_crypto", "(JM)I");
        OPENSSL_VERSION_MAJOR_FUNC = downcallHandle(
                "OPENSSL_version_major", VERSION_INT_FUNCDESC);
        OPENSSL_VERSION_MINOR_FUNC = downcallHandle(
                "OPENSSL_version_minor", VERSION_INT_FUNCDESC);
        OPENSSL_VERSION_PATCH_FUNC = downcallHandle(
                "OPENSSL_version_patch", VERSION_INT_FUNCDESC);
        OPENSSL_VERSION_FUNC = downcallHandle(
                "OpenSSL_version", INFO_STRING_FUNCDESC);
        OPENSSL_INFO_FUNC = downcallHandleCheckNull(
                "OPENSSL_info", INFO_STRING_FUNCDESC);
        OPENSSL_VERSION_BUILD_METADATA_FUNC = downcallHandle(
                "OPENSSL_version_build_metadata", "()U");

        ERR_GET_ERROR_FUNC = downcallHandle(
                "ERR_get_error", ERROR_CODE_FUNCDESC);
        ERR_PEEK_ERROR_FUNC = downcallHandle(
                "ERR_peek_error", ERROR_CODE_FUNCDESC);
        ERR_PEEK_LAST_ERROR_FUNC = downcallHandle(
                "ERR_peek_last_error", ERROR_CODE_FUNCDESC);
        ERR_PRINT_ERRORS_CB_FUNC = downcallHandle(
                "ERR_print_errors_cb", "(MM)V");
        ERR_CLEAR_ERROR_FUNC = downcallHandle(
                "ERR_clear_error", "()V");
    }

    FfmOpenSsl() {
        // Prevent instantiation outside this package.
    }

    static void checkReturnValue(int returnValue, String funcName) {
        if (returnValue <= 0) {
            throw newOpenSslException(funcName);
        }
    }

    static MemorySegment checkReturnValue(MemorySegment returnValue, String funcName) {
        if (returnValue.address() == 0L) {
            throw newOpenSslException(funcName);
        }
        return returnValue;
    }

    static MemorySegment lifecycleHook(OpType opType, String funcName, MemorySegment ptr) {
        NativeObjectLifecycleCallback cb = lifecycleCallback;
        if (cb != null && ptr != null) {
            long address = ptr.address();
            if (address != 0L) {
                try {
                    cb.lifecycleOp(opType, funcName, address);
                } catch (Throwable t) {
                    t.printStackTrace();
                }
            }
        }
        return ptr;
    }

    static int lifecycleHookPPkeyOut(OpType opType, String funcName, Throwable throwable, int result, MemorySegment pPkey) {
        NativeObjectLifecycleCallback cb = lifecycleCallback;
        if (cb != null && throwable == null && result > 0 && pPkey != null && pPkey.address() != 0L) {
            try {
                long address = pPkey.get(C_POINTER, 0L).address();
                if (address != 0L) {
                    cb.lifecycleOp(opType, funcName, address);
                }
            } catch (Throwable t) {
                t.printStackTrace();
            }
        }
        return result;
    }

    static boolean isLifecycleNewPPkeyOut(String funcName) {
        return funcName.equals("EVP_PKEY_generate") || funcName.equals("EVP_PKEY_fromdata");
    }

    static Optional<OpType> getLifecycleOpType(String funcName, String funcDescStr) {
        // NEW
        if (
                funcName.equals("CRYPTO_malloc") ||
                funcName.equals("CRYPTO_zalloc") ||
                funcName.equals("OSSL_LIB_CTX_new") ||
                funcName.equals("NCONF_new_ex") ||
                funcName.equals("BIO_new_mem_buf") ||
                funcName.equals("EVP_PKEY_CTX_new_from_name") ||
                funcName.equals("EVP_PKEY_CTX_new_from_pkey") ||
                (funcName.startsWith("EVP_") && (
                        funcName.endsWith("_fetch") || funcName.endsWith("_new") || funcName.endsWith("_dup"))) ||
                isLifecycleNewPPkeyOut(funcName)
        ) {
            if (!(
                    funcDescStr.endsWith(")M") ||
                    (funcDescStr.startsWith("(MM") && funcDescStr.endsWith(")I")) // ppkey out param
            )) {
                throw new AssertionError("Invalid funcDescStr for lifecycle NEW func (" + funcName + "): " + funcDescStr);
            }
            return Optional.of(NEW);
        }

        // UP_REF
        if (funcName.startsWith("EVP_") && funcName.endsWith("_up_ref")) {
            if (!funcDescStr.equals(UP_REF_FUNCDESC)) {
                throw new AssertionError("Invalid funcDescStr for lifecycle UP_REF func (" + funcName + "): " + funcDescStr);
            }
            return Optional.of(UP_REF);
        }

        // FREE
        if (
                funcName.equals("CRYPTO_free") ||
                funcName.equals("CRYPTO_clear_free") ||
                funcName.equals("OSSL_LIB_CTX_free") ||
                funcName.equals("NCONF_free") ||
                funcName.equals("BIO_vfree") ||
                (funcName.startsWith("EVP_") && funcName.endsWith("_free"))
        ) {
            if (
                    !funcDescStr.equals("(MMI)V") &&
                    !funcDescStr.equals("(MSMI)V") &&
                    !funcDescStr.equals(FREE_FUNCDESC)
            ) {
                throw new AssertionError("Invalid funcDescStr for lifecycle FREE func (" + funcName + "): " + funcDescStr);
            }
            return Optional.of(FREE);
        }

        return Optional.empty();
    }

    // This method is used as the target of an upcallStub so its signature must match the arity and parameter types of
    // the OpenSSL error callback function pointer. Consequently, the unused parameters `len` and `u` cannot be removed.
    static int errorCallback(MemorySegment str, long len, MemorySegment u) {
        CallbackContext context;
        if (!CALLBACK_CONTEXT.isBound() || (context = CALLBACK_CONTEXT.get()).hasPendingException()) {
            return 0;
        }
        try {
            return context.call(str) ? 1 : 0;
        } catch (Throwable t) {
            context.catchException(t);
            return 0;
        }
    }

    // This method is used as the target of an upcallStub so its signature must match the arity and parameter types of
    // the OpenSSL callback function pointer. Consequently, the unused parameter `data` cannot be removed.
    static void ptrCallback(MemorySegment ptr, MemorySegment data) {
        CallbackContext context;
        if (!CALLBACK_CONTEXT.isBound() || (context = CALLBACK_CONTEXT.get()).hasPendingException()) {
            return;
        }
        try {
            context.call(ptr);
        } catch (Throwable t) {
            context.catchException(t);
        }
    }

    // This method is used as the target of an upcallStub so its signature must match the arity and parameter types of
    // the OpenSSL callback function pointer. Consequently, the unused parameter `cbData` cannot be removed.
    static int providerCallback(MemorySegment osslProvider, MemorySegment cbData) {
        CallbackContext context;
        if (!CALLBACK_CONTEXT.isBound() || (context = CALLBACK_CONTEXT.get()).hasPendingException()) {
            return 0;
        }
        try {
            return context.call(osslProvider) ? 1 : 0;
        } catch (Throwable t) {
            context.catchException(t);
            return 0;
        }
    }

    public static boolean callProviderCallback(ScopedValue.CallableOp<Boolean,RuntimeException> op, Predicate<OSSL_PROVIDER> callback) {
        try (Arena arena = Arena.ofConfined()) {
            CallbackContext context = new CallbackContext(p -> callback.test(new OsslProvider(p, arena)));
            boolean ret = ScopedValue.where(CALLBACK_CONTEXT, context).call(op);
            context.rethrowException();
            return ret;
        }
    }

    public static boolean callNameCallback(ScopedValue.CallableOp<Boolean,RuntimeException> op, Consumer<String> consumer) {
        CallbackContext context = new CallbackContext(name -> {
            consumer.accept(name.getString(0L));
            return true;
        });
        boolean ret = ScopedValue.where(CALLBACK_CONTEXT, context).call(op);
        context.rethrowException();
        return ret;
    }

    static RuntimeException mapException(Throwable t) {
        if (t instanceof Error error) {
            throw error;
        }
        if (t instanceof OpenSslException oe) {
            if (!oe.isSystemError()) {
                int reason = oe.getReason();
                if (reason == OpenSslErrorCode.ERR_R_MALLOC_FAILURE) {
                    Error oom = new OutOfMemoryError("malloc failure");
                    oom.initCause(oe);
                    throw oom;
                }
                if (reason == OpenSslErrorCode.EVP_R_NO_CIPHER_SET ||
                        reason == OpenSslErrorCode.EVP_R_NO_DIGEST_SET ||
                        reason == OpenSslErrorCode.EVP_R_MESSAGE_DIGEST_IS_NULL) {
                    return new IllegalStateException("Not initialized", oe);
                }
            }
            return oe;
        }
        if (t instanceof RuntimeException re) {
            return re;
        }
        throw new AssertionError(t);
    }

    static OpenSslException newOpenSslException(String funcName) {
        StringBuilder exMsg = new StringBuilder(funcName);
        exMsg.append(" failed");
        int errorCode = peekLastErrorInternal();
        if (errorCode != 0) {
            exMsg.append(", with:");
            forEachErrorInternal(errorString -> exMsg.append('\n').append(errorString));
        }
        return new OpenSslException(exMsg.toString(), null, errorCode);
    }

    private static MethodHandle throwUnsupportedOperationException(MethodType methodType, String funcName) {
        MethodHandle throwUoe = MethodHandles.insertArguments(
                MethodHandles.throwException(methodType.returnType(), UnsupportedOperationException.class), 0,
                new UnsupportedOperationException("OpenSSL function not supported: " + funcName));
        return MethodHandles.dropArguments(throwUoe, 0, methodType.parameterList());
    }

    private static FunctionDescriptor toFunctionDescriptor(String funcDescStr) {
        int len = funcDescStr.length();
        if (funcDescStr.length() < 3 || funcDescStr.charAt(0) != '(' ||
                funcDescStr.charAt(len - 2) != ')') {
            throw new AssertionError("Invalid funcDescStr");
        }
        MemoryLayout[] argLayouts = funcDescStr.subSequence(1, len - 2).chars()
                .mapToObj(FfmOpenSsl::toMemoryLayout).toArray(MemoryLayout[]::new);
        int resLayoutId = funcDescStr.charAt(len - 1);
        if (resLayoutId == 'V') {
            return FunctionDescriptor.ofVoid(argLayouts);
        }
        return FunctionDescriptor.of(toMemoryLayout(resLayoutId), argLayouts);
    }

    private static MemoryLayout toMemoryLayout(int layoutId) {
        return switch (layoutId) {
            case 'I', 'Z' -> C_INT;
            case 'L' -> C_LONG;
            case 'J' -> C_LONG_LONG;
            case 'S' -> C_SIZE_T;
            case 'M' -> C_POINTER;
            case 'U' -> C_POINTER_UNBOUNDED;
            case 'P' -> C_OSSL_PARAM_SEQUENCE_PTR;
            default -> throw new AssertionError("Unexpected layoutId value: " + layoutId);
        };
    }

    static MethodHandle downcallHandle(String funcName, String funcDescStr) {
        return downcallHandle(funcName, funcDescStr, LinkerOption.NONE);
    }

    static MethodHandle downcallHandle(String funcName, String funcDescStr, LinkerOption linkerOption) {
        LOG_NATIVE.println(() -> String.format("DOWNCALL: %s %s %s", funcName, funcDescStr, linkerOption));

        FunctionDescriptor functionDescriptor = toFunctionDescriptor(funcDescStr);
        Linker.Option[] linkerOptions = switch (linkerOption) {
            case NONE, OPTIONAL -> new Linker.Option[] {};
            case CRITICAL -> new Linker.Option[] {Linker.Option.critical(false)};
            case HEAP_ACCESS -> new Linker.Option[] {Linker.Option.critical(true)};
        };
        Optional<MemorySegment> optFn = LIBCRYPTO.find(funcName);
        if (optFn.isEmpty()) {
            if (linkerOption != LinkerOption.OPTIONAL) {
                throw new NoSuchElementException("Symbol not found: " + funcName);
            }
            return throwUnsupportedOperationException(functionDescriptor.toMethodType(), funcName);
        }
        MethodHandle mh = LINKER.downcallHandle(optFn.get(), functionDescriptor, linkerOptions);

        if (LIFECYCLE_HOOKS_ENABLED) {
            Optional<OpType> lifecycleOpType = getLifecycleOpType(funcName, funcDescStr);
            if (lifecycleOpType.isPresent()) {
                OpType opType = lifecycleOpType.orElseThrow();
                boolean hasPPKeyOutParam = opType == NEW && isLifecycleNewPPkeyOut(funcName);
                MethodHandle hookFunc = hasPPKeyOutParam ? LIFECYCLE_HOOK_P_PKEY_OUT_FUNC : LIFECYCLE_HOOK_FUNC;
                hookFunc = MethodHandles.insertArguments(hookFunc, 0, opType, funcName);
                switch (opType) {
                    case NEW -> {
                        if (hasPPKeyOutParam) {
                            // Drop parameters beyond the first two original method parameters (if any).
                            List<Class<?>> trailingParamTypes = mh.type().dropParameterTypes(0, 2).parameterList();
                            if (!trailingParamTypes.isEmpty()) {
                                hookFunc = MethodHandles.dropArguments(hookFunc, 3, trailingParamTypes);
                            }

                            // Drop the first original method parameter, since the hook does not require it.
                            hookFunc = MethodHandles.dropArguments(hookFunc, 2, MemorySegment.class);

                            mh = MethodHandles.tryFinally(mh, hookFunc);
                        } else {
                            mh = MethodHandles.filterReturnValue(mh, hookFunc);
                        }
                    }
                    case UP_REF, FREE -> mh = MethodHandles.filterArguments(mh, 0, hookFunc);
                }
            }
        }

        if (funcDescStr.endsWith(")L") && C_LONG.byteSize() == 4L) {
            // Special handling for 64-bit platforms where C_LONG == JAVA_INT, such as
            // Microsoft(R) Windows(R) 64-bit platforms.

            // Note that currently all OpenSSL functions needed by Jipher that return a long-sized value
            // actually return an unsigned long.  The sign extension to a 64-bit Java long that occurs on
            // Windows will result in a negative value if bit 31 is set.  This must be taken into account
            // by code that calls such OpenSSL functions.
            // In particular, the return values of the EVP_CIPHER_get_flags() and EVP_CIPHER_get_mode()
            // functions don't currently have valid return values where bit 31 is set.
            // The error codes returned by ERR_get_error(), ERR_peek_error() and ERR_peek_last_error()
            // use bit 31 to indicate OpenSSL System Errors, but all Jipher code that calls those
            // functions expects the error codes to be negative in that case. (The Jipher adapter layer
            // truncates them to 32-bit Java ints, though system errors would be negative regardless.)

            // Cast the return type to a java long (by a widening primitive conversion).
            // This is a no-op on platforms where C_LONG == JAVA_LONG, such as Linux.
            MethodType newType = functionDescriptor.toMethodType().changeReturnType(long.class);
            mh = mh.asType(newType);
        } else if (funcDescStr.endsWith(")Z")) {
            // Cast the primitive return type to a boolean (by a narrowing primitive to boolean conversion).
            MethodType newType = functionDescriptor.toMethodType().changeReturnType(boolean.class);
            mh = MethodHandles.explicitCastArguments(mh, newType);
        }
        return mh;

    }

    static MethodHandle downcallHandleCheckZeroNeg(String funcName, String funcDescStr) {
        return downcallHandleCheckZeroNeg(funcName, funcDescStr, LinkerOption.NONE);
    }

    static MethodHandle downcallHandleCheckZeroNeg(String funcName, String funcDescStr, LinkerOption linkerOption) {
        if (!funcDescStr.endsWith(")I")) {
            throw new AssertionError("Return type must be int");
        }
        return downcallHandleCheck(funcName, funcDescStr, CHECK_ZERO_NEG_RETURN_VALUE_FUNC, linkerOption);
    }

    static MethodHandle downcallHandleCheckNull(String funcName, String funcDescStr) {
        return downcallHandleCheckNull(funcName, funcDescStr, LinkerOption.NONE);
    }

    static MethodHandle downcallHandleCheckNull(String funcName, String funcDescStr, LinkerOption linkerOption) {
        if (!funcDescStr.endsWith(")M") && !funcDescStr.endsWith(")U") && !funcDescStr.endsWith(")P")) {
            throw new AssertionError("Return type must be pointer");
        }
        return downcallHandleCheck(funcName, funcDescStr, CHECK_NULL_RETURN_VALUE_FUNC, linkerOption);
    }

    private static MethodHandle downcallHandleCheck(String funcName, String funcDescStr,
                                                    MethodHandle checkReturnValueFunc, LinkerOption linkerOption) {
        MethodHandle target = downcallHandle(funcName, funcDescStr, linkerOption);
        MethodHandle filter = MethodHandles.insertArguments(checkReturnValueFunc, 1, funcName);
        return MethodHandles.filterReturnValue(target, filter);
    }


    // The lifecycle hooks must be enabled by setting the java.testing.lifecycleHooks.enable
    // System property to true prior to Jipher being initialized in order for lifecycle events
    // to be delivered to the callback.
    //
    // Each event includes the operation type (NEW/UP_REF/FREE), the name of the OpenSSL function
    // and the pointer to the native object.  These events can be used for leak testing.
    //
    // The lifecycle hooks are implemented by instrumenting downcall MethodHandles for all OpenSSL
    // functions that are involved with OpenSSL object creation, up-ref-ing and freeing, including
    // the case where the pointer to the new object is returned via an out parameter.  There is no
    // performance overhead when the hooks have not been enabled.
    @Override
    public void setNativeObjectLifecycleCallback(NativeObjectLifecycleCallback callback) {
        lifecycleCallback = Objects.requireNonNull(callback);
    }

    @Override
    public void clearNativeObjectLifecycleCallback() {
        lifecycleCallback = null;
    }

    @Override
    public void clearObjectPools() {
        EvpCipherCtx.CIPHER_CTX_OBJECT_POOL.clear();
        EvpMdCtx.MD_CTX_OBJECT_POOL.clear();
        EvpMacCtx.HMAC_MAC_CTX_OBJECT_POOL.clear();
    }

    @Override
    public void initCrypto(InitOption... opts) {
        long optsMask = Stream.of(opts).mapToLong(opt -> 1L << opt.ordinal()).reduce(0L, (a, b) -> a | b);
        try {
            OPENSSL_INIT_CRYPTO_FUNC.invokeExact(optsMask, MemorySegment.NULL);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int versionMajor() {
        try {
            return (int) OPENSSL_VERSION_MAJOR_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int versionMinor() {
        try {
            return (int) OPENSSL_VERSION_MINOR_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int versionPatch() {
        try {
            return (int) OPENSSL_VERSION_PATCH_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String versionString(VersionStringSelector selector) {
        try {
            return ((MemorySegment) OPENSSL_VERSION_FUNC.invokeExact(selector.ordinal())).getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String infoString(InfoStringSelector selector) {
        try {
            return ((MemorySegment) OPENSSL_INFO_FUNC.invokeExact(selector.ordinal() + INFO_SELECTOR_OFFSET)).getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String versionBuildMetadataString() {
        try {
            return ((MemorySegment) OPENSSL_VERSION_BUILD_METADATA_FUNC.invokeExact()).getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int getError() {
        try {
            // The invokeExact method is signature polymorphic, so the cast to long is required despite the value immediately being cast to int.
            return (int) (long) ERR_GET_ERROR_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int peekError() {
        return peekErrorInternal();
    }

    static int peekErrorInternal() {
        try {
            // The invokeExact method is signature polymorphic, so the cast to long is required despite the value immediately being cast to int.
            return (int) (long) ERR_PEEK_ERROR_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int peekLastError() {
        return peekLastErrorInternal();
    }

    static int peekLastErrorInternal() {
        try {
            // The invokeExact method is signature polymorphic, so the cast to long is required despite the value immediately being cast to int.
            return (int) (long) ERR_PEEK_LAST_ERROR_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void forEachError(Consumer<String> consumer) {
        forEachErrorInternal(consumer);
    }

    static void forEachErrorInternal(Consumer<String> consumer) {
        if (peekErrorInternal() != 0) {
            CallbackContext context = new CallbackContext(str -> {
                consumer.accept(str.getString(0L).trim());
                return true;
            });
            ScopedValue.where(CALLBACK_CONTEXT, context).run(() -> {
                try {
                    ERR_PRINT_ERRORS_CB_FUNC.invokeExact(ERROR_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            context.rethrowException();
        }
    }

    @Override
    public void clearErrorQueue() {
        clearErrorQueueInternal();
    }

    static void clearErrorQueueInternal() {
        try {
            ERR_CLEAR_ERROR_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static final ConcurrentMap<String,MemorySegment> CONST_STRINGS = new ConcurrentHashMap<>();

    static MemorySegment constString(String str) {
        Objects.requireNonNull(str, "str must not be null");
        return CONST_STRINGS.computeIfAbsent(str, s -> Arena.global().allocateFrom(s).asReadOnly());
    }

    static MemorySegment allocateFromNullable(byte[] bytes, int requiredLen, String name, SegmentAllocator allocator) {
        if (bytes != null && bytes.length != requiredLen) {
            throw new IllegalArgumentException("%s is not of required length (was %d, required %d)".formatted(name, bytes.length, requiredLen));
        }
        return allocateFromNullable(bytes, allocator);
    }

    static MemorySegment allocateFromNullable(byte[] bytes, SegmentAllocator allocator) {
        if (bytes == null) {
            return MemorySegment.NULL;
        }
        return allocator.allocateFrom(JAVA_BYTE, bytes);
    }

    /*
     * Returns buf, if buf is native, or a new off-heap buffer (MemorySegment) of the same size as buf, otherwise.
     * This is used to ensure an output buffer that will receive non-sensitive output data is off-heap.
     * The application-supplied buffer, buf, is assumed to not contain any valid data and is only intended to
     * receive new output data, so if a new buffer is allocated then no data is copied from buf to the new buffer.
     * In the case where application-supplied buffer, buf, is not native (i.e. not off-heap) then the caller is
     * responsible for copying any output data to the application-supplied buffer after the output buffer has been
     * populated.
     */
    static MemorySegment toOffHeapSegment(MemorySegment buf, SegmentAllocator allocator) {
        MemorySegment seg;
        if (buf.isNative()) {
            seg = buf;
        } else {
            seg = allocator.allocate(buf.byteSize());
        }
        return seg;
    }

    /*
     * Returns buf, if buf is native, or a new off-heap buffer (MemorySegment) of the same size as buf that
     * will be zeroized when freed, otherwise.
     * This is used to ensure an output buffer that will receive sensitive output data is off-heap.
     * The new off-heap buffer will be automatically zeroized when freed, clearing any sensitive data it contains.
     * The application-supplied buffer, buf, is assumed to not contain any valid data and is only intended to
     * receive new output data, so if a new buffer is allocated then no data is copied from buf to the new buffer.
     * In the case where application-supplied buffer, buf, is not native (i.e. not off-heap) then the caller is
     * responsible for copying any output data to the application-supplied buffer after the output buffer has been
     * populated.
     */
    static MemorySegment toOffHeapSegmentZeroize(MemorySegment buf, Arena arena) {
        MemorySegment seg;
        if (buf.isNative()) {
            seg = buf;
        } else {
            seg = OpenSslAllocators.mallocClearFree(buf.byteSize(), arena);
        }
        return seg;
    }

    /*
     * Returns buf, if buf is native, or a new off-heap buffer (MemorySegment) of the same size and content as buf, otherwise.
     * If a new off-heap buffer is allocated then the content of the application-supplied buffer, buf, will
     * be copied to the new buffer.
     * This is used to ensure a buffer that provides non-sensitive input data is off-heap.
     */
    static MemorySegment toOffHeapSegmentCopy(MemorySegment buf, SegmentAllocator allocator) {
        MemorySegment seg;
        if (buf.isNative()) {
            seg = buf;
        } else {
            seg = allocator.allocateFrom(JAVA_BYTE, buf, JAVA_BYTE, 0L, buf.byteSize());
        }
        return seg;
    }

    /*
     * Returns buf, if buf is native, or a new off-heap buffer (MemorySegment) of the same size and content
     * as buf that will be zeroized when freed, otherwise.
     * If a new off-heap buffer is allocated then the content of the application-supplied buffer, buf, will
     * be copied to the new buffer.
     * This is used to ensure a buffer that provides sensitive input data is off-heap.
     * The new off-heap buffer will be automatically zeroized when freed, clearing any sensitive data it contains.
     */
    static MemorySegment toOffHeapSegmentCopyZeroize(MemorySegment buf, Arena arena) {
        MemorySegment seg;
        if (buf.isNative()) {
            seg = buf;
        } else {
            long len = buf.byteSize();
            seg = OpenSslAllocators.mallocClearFree(len, arena);
            seg.copyFrom(buf);
        }
        return seg;
    }

    @Override
    public OsslArena arenaGlobal() {
        return ArenaImpl.global();
    }

    @Override
    public OsslArena arenaOfAuto() {
        return ArenaImpl.ofAuto();
    }

    @Override
    public OsslArena arenaOfConfined() {
        return ArenaImpl.ofConfined();
    }

    @Override
    public OsslParamBuffer emptyParamBuffer() {
        return OsslParamBufferImpl.EMPTY_PARAM_BUFFER;
    }

    @Override
    public OsslParamBuffer templateParamBuffer(OSSL_PARAM... params) {
        return templateParamBufferInternal(params, null);
    }

    @Override
    public OsslParamBuffer templateParamBuffer(OsslArena osslArena, OSSL_PARAM... params) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return templateParamBufferInternal(params, arena);
    }

    static OsslParamBuffer templateParamBufferInternal(OSSL_PARAM[] params, Arena arena) {
        if (params.length == 0) {
            return OsslParamBufferImpl.EMPTY_PARAM_BUFFER;
        }
        for (OSSL_PARAM param : params) {
            if (param.hasData()) {
                throw new IllegalArgumentException("Non-template OSSL_PARAM supplied");
            }
        }
        return OsslParamBufferImpl.newParamBuffer(params.clone(), true, arena);
    }

    @Override
    public OsslParamBuffer dataParamBuffer(OSSL_PARAM... params) {
        return dataParamBufferInternal(params, null);
    }

    @Override
    public OsslParamBuffer dataParamBuffer(OsslArena osslArena, OSSL_PARAM... params) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return dataParamBufferInternal(params, arena);
    }

    static OsslParamBuffer dataParamBufferInternal(OSSL_PARAM[] params, Arena arena) {
        OSSL_PARAM[] packedParams = new OSSL_PARAM[params.length];
        int paramCount = 0;
        for (OSSL_PARAM param : params) {
            // Param elements can be null to allow for conditional params.
            if (param != null) {
                if (!param.hasData()) {
                    throw new IllegalArgumentException("Non-data OSSL_PARAM supplied");
                }
                packedParams[paramCount] = param;
                ++paramCount;
            }
        }
        if (paramCount == 0) {
            return OsslParamBufferImpl.EMPTY_PARAM_BUFFER;
        }
        if (paramCount < params.length) {
            packedParams = Arrays.copyOf(packedParams, paramCount);
        }
        return OsslParamBufferImpl.newParamBuffer(packedParams, false, arena);
    }

    @Override
    public OSSL_LIB_CTX newOsslLibCtx(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new OsslLibCtx(arena);
    }

    @Override
    public EVP_CIPHER_CTX newEvpCipherCtx(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new EvpCipherCtx(false, arena);
    }

    @Override
    public EVP_CIPHER_CTX newEvpCipherCtx() {
        return EvpCipherCtx.getEvpCipherCtxAutoArena();
    }

    @Override
    public EVP_KDF_CTX newEvpKdfCtx(EVP_KDF type, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new EvpKdfCtx((EvpKdf) type, arena);
    }

    @Override
    public EVP_MAC_CTX newEvpMacCtx(EVP_MAC type, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new EvpMacCtx((EvpMac) type, false, arena);
    }

    @Override
    public EVP_MAC_CTX newEvpMacCtx(EVP_MAC type) {
        return getEvpMacCtxAutoArena((EvpMac) type);
    }

    @Override
    public EVP_MD_CTX newEvpMdCtx(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new EvpMdCtx(false, arena);
    }

    @Override
    public EVP_MD_CTX newEvpMdCtx() {
        return EvpMdCtx.getEvpMdCtxAutoArena();
    }

    @Override
    public EVP_RAND_CTX newEvpRandCtx(EVP_RAND type, EVP_RAND_CTX parent, OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new EvpRandCtx((EvpRand) type, (EvpRandCtx) parent, arena);
    }

    @Override
    public EVP_PKEY newEvpPkey(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        return new EvpPkey(arena);
    }

    /**
     * The default OSSL_LIB_CTX singleton.
     */
    static final OSSL_LIB_CTX DEFAULT_OSSL_LIB_CTX = new OsslLibCtx();

    @Override
    public OSSL_LIB_CTX getDefaultOsslLibCtx() {
        return DEFAULT_OSSL_LIB_CTX;
    }

}
