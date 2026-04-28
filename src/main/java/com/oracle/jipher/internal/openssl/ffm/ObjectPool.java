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

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicStampedReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class ObjectPool<T extends PoolableObjectBase<T>> {

    static final int NR_STACKS = 64;
    static final int MAX_STACK_DEPTH = 10;
    static final int MAX_OVERFLOW_STACK_DEPTH = 1000;

    // An AtomicStampedReference is used here instead of an AtomicReference so that a stamp
    // can be used in order to avoid a potential race condition that could otherwise occur in
    // pop() when other threads pop() and then push() ctx objects such that the top-of-stack
    // object remains the same but the next-to-top changes.
    final AtomicStampedReference<T> overflowStackHeadRef = new AtomicStampedReference<>(null, 0);
    final List<AtomicStampedReference<T>> stackHeadRefsList = Collections.unmodifiableList(
            Stream.generate(() -> new AtomicStampedReference<T>(null, 0))
                    .limit(NR_STACKS)
                    .collect(Collectors.toList()));

    void push(T poolableObject) {
        int index = (((int) Thread.currentThread().threadId()) & Integer.MAX_VALUE) % NR_STACKS;
        AtomicStampedReference<T> stackHeadRef = this.stackHeadRefsList.get(index);
        if (!push(stackHeadRef, MAX_STACK_DEPTH, poolableObject)) {
            push(overflowStackHeadRef, MAX_OVERFLOW_STACK_DEPTH, poolableObject);
        }
    }

    boolean push(AtomicStampedReference<T> stackHeadRef, int maxStackSize, T poolableObject) {
        T stackHead;
        int[] stampHolder = new int[1];
        int stamp;
        do {
            stackHead = stackHeadRef.get(stampHolder);
            int newStackDepth = stackHead != null ? stackHead.stackDepth + 1 : 1;
            if (newStackDepth > maxStackSize) {
                return false;
            }
            poolableObject.next = stackHead;
            poolableObject.stackDepth = newStackDepth;
            stamp = stampHolder[0];
        } while (!stackHeadRef.compareAndSet(stackHead, poolableObject, stamp, stamp + 1));
        return true;
    }

    Optional<T> pop() {
        int index = (((int) Thread.currentThread().threadId()) & Integer.MAX_VALUE) % NR_STACKS;
        AtomicStampedReference<T> stackHeadRef = this.stackHeadRefsList.get(index);
        return pop(stackHeadRef).or(() -> pop(this.overflowStackHeadRef));
    }

    Optional<T> pop(AtomicStampedReference<T> stackHeadRef) {
        T stackHead;
        int[] stampHolder = new int[1];
        int stamp;
        do {
            stackHead = stackHeadRef.get(stampHolder);
            if (stackHead == null) {
                return Optional.empty();
            }
            stamp = stampHolder[0];
        } while (!stackHeadRef.compareAndSet(stackHead, stackHead.next, stamp, stamp + 1));
        stackHead.next = null;
        return Optional.of(stackHead);
    }

    // Used for leak testing.
    void clear() {
        for (AtomicStampedReference<T> ref : this.stackHeadRefsList) {
            ref.set(null, 0);
        }
        this.overflowStackHeadRef.set(null, 0);
    }

}
