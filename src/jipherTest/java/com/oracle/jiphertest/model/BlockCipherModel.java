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

package com.oracle.jiphertest.model;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class BlockCipherModel extends AbstractCipherModel {
    protected int blockSize;
    protected boolean paddingEnabled;

    public BlockCipherModel(int blockSize, boolean paddingEnabled) {
        super();
        this.blockSize = blockSize;
        this.paddingEnabled = paddingEnabled;
    }

    @Override
    protected int getOutputSize(int inputSize, boolean doFinal) {
        int dataSize = this.bufferedSize + inputSize;
        int partialBlockSize = dataSize % this.blockSize;

        if (this.decrypt) {
            if (doFinal) {
                if (partialBlockSize != 0) {
                    // For a genuine doFinal() call we would throw IllegalBlockSizeException.
                    // As an exception would be thrown the required size of the output buffer is zero.
                    return 0;
                } else {
                    if (this.paddingEnabled) {
                        // The output can be anything from 'dataSize - blockSize' to 'dataSize - 1'
                        // Return the worst case figure
                        return Math.max(0, dataSize - 1);
                    } else {
                        return dataSize;
                    }
                }
            } else { // update
                if (this.paddingEnabled) {
                    // Buffer between 1 and blockSize bytes.
                    if (partialBlockSize == 0) {
                        return Math.max(0, dataSize - this.blockSize);
                    } else {
                        return dataSize - partialBlockSize;
                    }
                } else {
                    // Only return full blocks
                    return dataSize - partialBlockSize;
                }
            }
        } else { // encrypt
            if (doFinal) {
                if (this.paddingEnabled) {
                    if (partialBlockSize == 0) {
                        // Add a padding block
                        return dataSize + this.blockSize;
                    } else {
                        // Fill the final block with padding bytes
                        return dataSize - partialBlockSize + this.blockSize;
                    }
                } else {
                    if (partialBlockSize != 0) {
                        // For a genuine doFinal() call we would throw IllegalBlockSizeException
                        // As an exception would be thrown the required size of the output buffer is zero.
                        return 0;
                    } else {
                        return dataSize;
                    }
                }
            } else { // update
                return dataSize - partialBlockSize;
            }
        }
    }

    @Override
    public int doFinal(int inputSize) throws IllegalBlockSizeException, BadPaddingException {
        if (((this.bufferedSize + inputSize) % this.blockSize) != 0) {
            if (!this.paddingEnabled || this.decrypt) {
                throw new IllegalBlockSizeException();
            }
        }
        if (this.decrypt && this.paddingEnabled) {
            throw new RuntimeException("Padding cannot be determined");
        }
        return super.doFinal(inputSize);
    }
}

