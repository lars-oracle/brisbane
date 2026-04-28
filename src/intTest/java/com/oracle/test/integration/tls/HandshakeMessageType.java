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

package com.oracle.test.integration.tls;

public enum HandshakeMessageType {
    CLIENT_HELLO((byte)0x01, "client_hello"),
    SERVER_HELLO((byte)0x02, "server_hello"),
    NEW_SESSION_TICKET((byte)0x04, "new_session_ticket"),
    END_OF_EARLY_DATA((byte)0x05, "end_of_early_data"),
    CERTIFICATE((byte)0x0B, "certificate"),
    SERVER_KEY_EXCHANGE((byte)0x0C, "server_key_exchange"),
    CERTIFICATE_REQUEST((byte)0x0D, "certificate_request"),
    SERVER_HELLO_DONE((byte)0x0E, "server_hello_done"),
    CERTIFICATE_VERIFY((byte)0x0F, "certificate_verify"),
    CLIENT_KEY_EXCHANGE((byte)0x10, "client_key_exchange"),
    FINISHED((byte)0x14, "finished"),
    CERTIFICATE_STATUS((byte)0x16, "certificate_status"),
    KEY_UPDATE((byte)0x18, "key_update");

    final byte value;
    final String name;

    HandshakeMessageType(byte value, String name) {
        this.value = value;
        this.name = name;
    }

    public static HandshakeMessageType byValue(byte value) {
        for (HandshakeMessageType messageType : HandshakeMessageType.values()) {
            if (messageType.value == value) {
                return messageType;
            }
        }
        return null;
    }
}
