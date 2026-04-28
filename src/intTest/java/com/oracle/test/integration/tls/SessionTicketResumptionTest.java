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

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import com.oracle.jiphertest.helpers.ProviderSetup;
import com.oracle.jiphertest.helpers.TlsSetup;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.test.integration.tls.HandshakeMessageType.CLIENT_HELLO;
import static com.oracle.test.integration.tls.HandshakeMessageType.NEW_SESSION_TICKET;
import static com.oracle.test.integration.tls.HandshakeMessageType.SERVER_HELLO;
import static com.oracle.test.integration.tls.RecordType.HANDSHAKE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * Based largely on the JDK TLS regression tests
 */
public class SessionTicketResumptionTest {

    private static final boolean IS_TLS13_SUPPORTED;
    private static final Provider[] ORIGINAL_PROVIDERS = Security.getProviders();

    static {
        String[] protocols;
        try {
            protocols = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
        } catch (NoSuchAlgorithmException e) {
            protocols = new String[0];
        }
        IS_TLS13_SUPPORTED = Arrays.asList(protocols).contains("TLSv1.3");
    }

    private static final int TLS_RECORD_HEADER_LENGTH = 5;
    private static final short TLS_VERSION_1_2 = (short) 0x0303;
    private static final int SERVER_RANDOM_LENGTH = 32;
    private static final short PRE_SHARED_KEY_EXT_ID = (short) 0x0029;

    private SSLEngine clientEngine;     // client Engine
    private ByteBuffer clientOut;       // write side of clientEngine
    private ByteBuffer clientIn;        // read side of clientEngine

    private SSLEngine serverEngine;     // server Engine
    private ByteBuffer serverOut;       // write side of serverEngine
    private ByteBuffer serverIn;        // read side of serverEngine

    /*
     * For data transport
     */
    private ByteBuffer cTOs;            // "reliable" transport client->server
    private ByteBuffer sTOc;            // "reliable" transport server->client

    final private SSLContext clientSllCtx = TlsSetup.getSSLContext("client");
    final private SSLContext serverSllCtx = TlsSetup.getSSLContext("server");

    public SessionTicketResumptionTest() throws Exception {
    }

    /*
     * Using the SSLContext created during object creation, create/configure the SSLEngines we'll use for this test.
     */
    private void createSSLEngines(String protocolVersion, String cipherSuite) throws Exception {
        /*
         * Configure the serverEngine to act as a server in the SSL/TLS handshake.
         */
        serverEngine = serverSllCtx.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setEnabledCipherSuites(new String[] {cipherSuite});

        /*
         * Similar to above, but using client mode instead.
         */
        clientEngine = clientSllCtx.createSSLEngine("client", 80);
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[] {protocolVersion});
        clientEngine.setEnabledCipherSuites(new String[] {cipherSuite});
    }

    /*
     * Create and size the buffers appropriately.
     */
    private void createBuffers() {
        /*
         * We'll assume the buffer sizes are the same between client and server.
         */
        SSLSession session = clientEngine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();

        /*
         * We'll make the input buffers a bit bigger than the max needed size, so that unwrap()s following a successful
         * data transfer won't generate BUFFER_OVERFLOWS.
         */
        clientIn = ByteBuffer.allocate(appBufferMax + 50);
        serverIn = ByteBuffer.allocate(appBufferMax + 50);

        cTOs = ByteBuffer.allocate(netBufferMax);
        sTOc = ByteBuffer.allocate(netBufferMax);

        clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
    }

    @After
    public void tearDown()  {
        Security.removeProvider(ProviderUtil.get().getName());
        for (int i = 0; i < ORIGINAL_PROVIDERS.length; i++) {
            Security.removeProvider(ORIGINAL_PROVIDERS[i].getName());
            Security.insertProviderAt(ORIGINAL_PROVIDERS[i], i + 1); // position is 1-based
        }
    }

    @Test
    public void testTLSV12() throws Exception {
        Security.insertProviderAt(ProviderUtil.get(), 1);
        // Limit the list of registered security providers to those required to support a TLS stack
        ProviderSetup.limitProviders(Arrays.asList("JipherJCE", "SUN", "SunJSSE"));
        doTest("TLSv1.2",  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    }

    @Test
    public void testTLSV13() throws Exception {
        Security.insertProviderAt(ProviderUtil.get(), 1);
        // Limit the list of registered security providers to those required to support a TLS stack
        ProviderSetup.limitProviders(Arrays.asList("JipherJCE", "SUN", "SunJSSE"));
        doTest("TLSv1.3",  "TLS_AES_256_GCM_SHA384");
    }

    public void doTest(String protocolVersion, String cipherSuite) throws Exception {

        if (protocolVersion.equalsIgnoreCase("TLSv1.3")) {
            assumeTrue("TLSv1.3 not supported by JDK", IS_TLS13_SUPPORTED);
        } else if (protocolVersion.equalsIgnoreCase("TLSv1.2")) {
            assumeTrue("TLSv1.2 SessionTicketExtension support was added in JDK 13",
                    EnvUtil.getJavaRuntimeMajorVersion() >= 13);
        }

        // Create initial state
        createSSLEngines(protocolVersion, cipherSuite);
        createBuffers();

        // Perform an initial handshake (to establish a session ticket)
        initialHandshake();

        // Reset state
        createSSLEngines(protocolVersion, cipherSuite);
        createBuffers();

        // Perform an abbreviated handshake that resumes the session using the ticket established in the initial handshake
        abbreviatedHandshake(protocolVersion);
    }

    /*
     * Performs a handshake to establish a SessionTicket
     */
    private void initialHandshake() throws Exception {
        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean dataDone = false;
        while (!dataDone) {
            clientResult = clientEngine.wrap(clientOut, cTOs);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.wrap(serverOut, sTOc);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.flip();
            sTOc.flip();

            if (!clientEngine.isInboundDone()) {
                clientResult = clientEngine.unwrap(sTOc, clientIn);
                runDelegatedTasks(clientResult, clientEngine);
                sTOc.compact();
            } else {
                sTOc.clear();
            }

            if (!serverEngine.isInboundDone()) {
                serverResult = serverEngine.unwrap(cTOs, serverIn);
                runDelegatedTasks(serverResult, serverEngine);
                cTOs.compact();
            } else {
                cTOs.clear();
            }

            /*
             * Continue until we've transferred all application data between the client and the server
             */
            if ((clientOut.limit() == serverIn.position()) && (serverOut.limit() == clientIn.position())) {
                /*
                 * A sanity check to ensure we got what was sent.
                 */
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                dataDone = true;
            }
        }
    }


    /*
     * Performs an abbreviated handshake using a Session Ticket as diagrammed in RFC-5077,
     * https://www.rfc-editor.org/rfc/rfc5077.html#section-3.1, Figure 2, reproduced below:
     *
     *    Client                                                Server
     *
     *    ClientHello
     *    (SessionTicket extension)      -------->
     *                                                     ServerHello
     *                                 (empty SessionTicket extension)
     *                                                NewSessionTicket
     *                                              [ChangeCipherSpec]
     *                                  <--------             Finished
     *    [ChangeCipherSpec]
     *    Finished                      -------->
     *    Application Data              <------->     Application Data
     *
     *  For TLS 1.3 the client uses the SessionTicket as a PSK.
     *  See RFC-8446 Section 4.6.1, https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.1:
     *
     *    Client                                                Server
     *
     *    ClientHello
     *    (PreSharedKey using SessionTicket) --->
     *                                                     ServerHello
     *                                                  (PreSharedKey)
     *                                              [ChangeCipherSpec]
     *                                              EncryptedExtensions
     *                                  <--------             Finished
     *    [ChangeCipherSpec]
     *    Finished                      -------->
     *                                  <--------     NewSessionTicket
     *    Application Data              <------->     Application Data
     *
     *
     *  The test examines the (cleartext) handshake messages types exchanged to confirm that a full handshake
     *  is NOT performed (because the server does/can not validate the session ticket).
     *  For TLSv1.3 we cannot observe enough of the (cleartext) handshake message types to determine if
     *  an abbreviated or full handshake is taking place. We therefore check that the ServerHello message carries
     *  a PreSharedKey extension (indicating that the server is resuming the session).
     *
     *  The expected (cleartext) handshake messages type sequence is:
     *      ClientHello, ServerHello, [Case TLSv1.2: NewSessionTicket].
     */
    private void abbreviatedHandshake(String protocolVersion) throws Exception {
        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean clientEncrypting = false;
        boolean serverEncrypting = false;

        Queue<HandshakeMessageType> observedMessageTypes;
        Queue<HandshakeMessageType> expectedMessageTypes = new LinkedList<>();
        expectedMessageTypes.add(CLIENT_HELLO);
        expectedMessageTypes.add(SERVER_HELLO);
        if (!protocolVersion.equalsIgnoreCase("TLSv1.3")) {
            expectedMessageTypes.add(NEW_SESSION_TICKET);
        }

        boolean dataDone = false;
        while (!dataDone) {
            clientResult = clientEngine.wrap(clientOut, cTOs);
            runDelegatedTasks(clientResult, clientEngine);

            if (clientResult.bytesProduced() > 0) {
                switch (getRecordType(cTOs)) {
                    case CHANGE_CIPHER_SPEC:
                    case APPLICATION_DATA:
                        clientEncrypting = true;
                        break;
                    case HANDSHAKE:
                        if (!clientEncrypting) {
                            observedMessageTypes = parseMessageTypes(cTOs);
                            validateMessageTypes(observedMessageTypes, expectedMessageTypes);
                        }
                        break;
                    default:
                        Assert.fail("Unsupported TLS RecordType");
                }
            }

            serverResult = serverEngine.wrap(serverOut, sTOc);
            runDelegatedTasks(serverResult, serverEngine);

            if (serverResult.bytesProduced() > 0) {
                switch (getRecordType(sTOc)) {
                    case CHANGE_CIPHER_SPEC:
                    case APPLICATION_DATA:
                        serverEncrypting = true;
                        break;
                    case HANDSHAKE:
                        if (!serverEncrypting) {
                            observedMessageTypes = parseMessageTypes(sTOc);
                            if (protocolVersion.equalsIgnoreCase("TLSv1.3")) {
                                if (observedMessageTypes.peek() == SERVER_HELLO) {
                                    assertTrue("ServerHello message does not contain PreSharedKey extension", serverHelloContainsPreSharedKeyExtension(sTOc));
                                }
                            }
                            validateMessageTypes(observedMessageTypes, expectedMessageTypes);
                        }
                        break;
                    default:
                        Assert.fail("Unsupported TLS RecordType");
                }
            }

            cTOs.flip();
            sTOc.flip();

            if (!clientEngine.isInboundDone()) {
                clientResult = clientEngine.unwrap(sTOc, clientIn);
                runDelegatedTasks(clientResult, clientEngine);
                sTOc.compact();
            } else {
                sTOc.clear();
            }

            if (!serverEngine.isInboundDone()) {
                serverResult = serverEngine.unwrap(cTOs, serverIn);
                runDelegatedTasks(serverResult, serverEngine);
                cTOs.compact();
            } else {
                cTOs.clear();
            }

            /*
             * Continue until we've transferred all application data between the client and the server
             */
            if ((clientOut.limit() == serverIn.position()) && (serverOut.limit() == clientIn.position())) {

                /*
                 * A sanity check to ensure we got what was sent.
                 */
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                dataDone = true;
            }
        }

        assertTrue("Not all of the expected handshake messages were observed", expectedMessageTypes.isEmpty());
    }

    /*
     * If the result indicates that we have outstanding tasks to do, go ahead and run them in this thread.
     */
    private static void runDelegatedTasks(SSLEngineResult result,
                                          SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();
            assertNotEquals("Handshake shouldn't need additional tasks", hsStatus, SSLEngineResult.HandshakeStatus.NEED_TASK);
        }
    }

    /*
     * Simple check to make sure everything came across as expected.
     */
    private static void checkTransfer(ByteBuffer a, ByteBuffer b) throws Exception {
        a.flip();
        b.flip();

        assertEquals("Data didn't transfer cleanly", a, b);

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    /*
     * Extracts the TLS record type from the TLS record in the provided byte buffer
     */
    private static RecordType getRecordType(ByteBuffer input)
    {
        ByteBuffer byteBuffer = input.duplicate();
        byteBuffer.flip();
        assertTrue(byteBuffer.hasRemaining());
        return RecordType.byValue(byteBuffer.get());
    }

    /*
     * Extracts the sequence of handshake message types (if any) present in the provided byte buffer
     */
    private static Queue<HandshakeMessageType> parseMessageTypes(ByteBuffer input)
    {
        Queue<HandshakeMessageType> messagesTypes = new LinkedList<>();
        ByteBuffer byteBuffer = input.duplicate();
        byteBuffer.flip();

        if (byteBuffer.hasRemaining()) {
            assertEquals("Unexpected TLS record type", HANDSHAKE, RecordType.byValue(byteBuffer.get()));
            // Advance past the remaining bytes of the TLS Record header
            byteBuffer.position(byteBuffer.position() + TLS_RECORD_HEADER_LENGTH - 1);
        }

        while (byteBuffer.hasRemaining()) {
            // Extract the handshake message type
            HandshakeMessageType messageType = HandshakeMessageType.byValue(byteBuffer.get());
            assertNotNull("Unrecognised Handshake Message type", messageType);
            messagesTypes.add(messageType);

            // Extract the length of the handshake message (3 bytes)
            int length = 0;
            for (int i = 0; i < 3; i++) {
                length = (length << 8) + Byte.toUnsignedInt(byteBuffer.get());
            }

            // Advance to the next handshake message
            byteBuffer.position(byteBuffer.position() + length);
        }

        return messagesTypes;
    }

    private static boolean serverHelloContainsPreSharedKeyExtension(ByteBuffer input) {
        boolean foundPSK = false;
        ByteBuffer byteBuffer = input.duplicate();
        byteBuffer.flip();

        if (byteBuffer.hasRemaining()) {
            assertEquals("Unexpected TLS record type", HANDSHAKE, RecordType.byValue(byteBuffer.get()));
            // Advance past the remaining bytes of the TLS Record header
            byteBuffer.position(byteBuffer.position() + TLS_RECORD_HEADER_LENGTH - 1);
        }

        // Get the next byte and make sure it is a Server Hello message
        assertEquals(SERVER_HELLO, HandshakeMessageType.byValue(byteBuffer.get()));

        // Skip past the length (3 bytes)
        byteBuffer.position(byteBuffer.position() + 3);

        // Protocol version should be TLSv1.2
        assertEquals(TLS_VERSION_1_2, byteBuffer.getShort());

        // Skip server random
        byteBuffer.position(byteBuffer.position() + SERVER_RANDOM_LENGTH);

        // Get the legacy session length and skip that many bytes
        int sessIdLen = Byte.toUnsignedInt(byteBuffer.get());
        //assertNotEquals("SessionID field empty", sessIdLen, 0);  <!--- Commented out because JDK 8 uses a 0 length session
        byteBuffer.position(byteBuffer.position() + sessIdLen);

        // Skip over the cipher suite
        byteBuffer.getShort();

        // Skip compression method
        byteBuffer.get();

        // Parse the extensions.
        // Get length first, then walk the extensions list looking for the presence of th PSK extension.
        int extListLen = Short.toUnsignedInt(byteBuffer.getShort());
        while (extListLen > 0) {
            // Get the Extension type and length
            int extType = Short.toUnsignedInt(byteBuffer.getShort());
            int extLen = Short.toUnsignedInt(byteBuffer.getShort());

            if (extType == PRE_SHARED_KEY_EXT_ID) {
                // We're not going to bother checking the value.  The presence of the extension in the context
                // of this test is good enough to tell us this is a resuming ServerHello.
                foundPSK = true;
            }

            byteBuffer.position(byteBuffer.position() + extLen);
            extListLen -= extLen + 4;   // Ext type(2), length(2), data(var.)
        }

        return foundPSK;
    }

    /*
     * Compares the observed sequence of handshake messages to the expected sequence of handshake messages
     */
    void validateMessageTypes(Queue<HandshakeMessageType> messageTypes, Queue<HandshakeMessageType> expectedMessageTypes)
    {
        HandshakeMessageType messageType;
        while ((messageType = messageTypes.poll()) != null) {
            assertEquals("Unexpected message type: " + messageType.name, expectedMessageTypes.poll(), messageType);
        }
    }
}
