
const net = require('net');
const crypto = require("crypto");
let isFinal = Boolean;
// Simple HTTP server responds with a simple WebSocket client test
const httpServer = net.createServer((connection) => {
    connection.on('data', () => {
        let content = `<!DOCTYPE html>
                            <html lang="es">
                              <head>
                                <meta charset="UTF-8" /><title>gr8 title</title>
                              </head>
                              <body>
                                You have reached the WebSocket test page
                                <script>
                                  let webSocket = new WebSocket('ws://localhost:3001');
                                  webSocket.onmessage = event => alert('Message from server: ' + event.data);
                                  webSocket.onopen = () => webSocket.send('hello');
                                </script>
                              </body>
                            </html>
                            `;
        connection.write('HTTP/1.1 200 OK\r\nContent-Length: ' + content.length + '\r\n\r\n' + content);
    });
});
httpServer.listen(3000, () => {
    console.log('HTTP server listening on port 3000\n');
});


// createServer creates a new TCP or IPC server, depending on what it listen()s to.
/**
 * If handshake initialized:
 * Retrieve the |Sec-WebSocket-Key|, which contains base64-encoded random bytes
 * Append the string '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' to the random bytes
 * Use sha1 to hash the key
 * Base64 encode the hash
 *
 * @type {Server}
 */
const server = net.createServer((connection) => {
    console.log('Client connected');

    // Connection is a socket!
    connection.on('data', (data) => {
        //const response = Buffer.alloc(20) //todo good size?
        let response = ""

        console.log('Data received from client: ', data.toString());
        console.log("\n")

        // First, we check if there has been a request to update
        if (getHeaderValue(data, 'Upgrade') === 'websocket') {
            // If there has been a request to update, the handshake has begun
            console.log('\nUpgrade header received --> starting handshake!\n')

            // To respond to the handshake, we must gather the Sec-WebSocket-key value
            const secWebSocketKey = getHeaderValue(data, 'Sec-WebSocket-Key')
            console.log('\n\nSec-WebSocket-key: ' + secWebSocketKey + "\n")

            // The key must be appended (UUID), hashed (sha1) and base64 encoded
            const secWebSocketAccept = generateAcceptValue(secWebSocketKey)
            // Logging it to make sure it worked
            console.log("The generated Sec-WebSocket-accept: " + secWebSocketAccept)

            // This is the server-side handshake to be returned to the client if everything went well!
            const responseHeaders =
                ['HTTP/1.1 101 Web Socket Protocol Handshake', // Or perhaps Switching Protocols?
                    'Upgrade: WebSocket',
                    'Connection: Upgrade',
                    `Sec-WebSocket-Accept: ${secWebSocketAccept}`];

            // Writing the response-headers to the socket (connection)
            connection.write(responseHeaders.join('\r\n') + '\r\n\r\n');
        }

        // This method (connection.on data event) will also be used for other data, such as messages!
        else{
            const message = parseMessage(data)
            // Logging to see what was received
            console.log("message from client: " + message);
            response += message;
            if(isFinal) {
                const buffer = constructReply(response)
                connection.write(buffer)
            }
        }
    });

    connection.on('end', () => {
        console.log('Client disconnected');
    });
});


server.on('error', (error) => {
    console.error('Error: ', error);
    if (error.code === 'EADDRINUSE') {
        console.log('Address in use, retrying...');
        setTimeout(function () {
            server.close();
            server.listen(3000, "localhost");
        }, 1000);
    }
});
server.listen(3001, () => {
    console.log('WebSocket server listening on port 3001');
})

/**
 * @param data = buffer
 * @param headerName = name to search for in header-lines
 */
function getHeaderValue(data, headerName) {
    let array = data.toString().split("\r\n");
    for (let line of array) {
        let header = line.split(":")
        if(header[0].trim() === headerName) {
            return header[1].trim(); // <-- headerValue
        }
    }
}
/**
 * Hashing algorithm
 * 1. Appends string
 * 2. Hashes using sha1 algortim
 * 3. base-64 encodes
 *
 * @param key is the key we get from the client during the handshake
 * @returns {string} the newly generated key to return to the client in the server-side handshake
 */
function generateAcceptValue (key) {
    return crypto
        .createHash('sha1')
        .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', 'binary')
        .digest('base64');
}

/**
 * Method decodes the frames sent by the client
 * %x1 = text frame
 * %x8 = closing connection
 * This server will only deal with text, and closing connection,
 * although binary frames (%x2) would be a good implementation for
 * images, audio and such (bit-stream)
 *
 * @param buffer consist of the (encoded) frames sent from the client
 * @return null if connection termination frame, and a decoded message if text frame
 */
function parseMessage(buffer) {
    // The first 8 bits consist of FIN-bit (1-bit), RSV1, RSV2, RSV3 (1-bit each) and the opcode (4 bit)
    const firstByte = buffer.readUInt8(0);

    const isFinalFrame = Boolean((firstByte >>> 7) & 0x1);
    if(isFinalFrame) {
        console.log("final frame!")
        isFinal = true;
    }

    // & = AND operation (mask); OxF == 0000 1111
    const opCode = firstByte & 0xF;

    // We return null if this is a connection termination frame
    if (opCode === 0x8) {
        return null;
    }

    // Except for the closing frame, no opCodes except text frames will be handled by this server
    if (opCode !== 0x1){
        return;
    }

    // The second 8 bits contain MASK-bit (1-bit) and Payload len (7-bits)
    // MASK-bit denotes whether the message is encrypted (1) or not (0) --> it should be 1 if from client
    const secondByte = buffer.readUInt8(1);

    // true = 1; false = 0
    const isMasked = Boolean((secondByte >>> 7) & 0x1);

    // Keep track of our current position as we advance through the buffer
    let currentOffset = 2;


    // The length of the "Payload data", in bytes
    // if 0-125 bytes, that is the actual payload length
    let payloadLength = secondByte & 0x7F; //Decimal -> 127, Binary -> 1111111

    // If 126, the following 2 bytes interpreted as a
    // 16-bit unsigned integer are the payload length.
    if (payloadLength > 125) {
        if (payloadLength === 126) {
            payloadLength = buffer.readUInt16BE(currentOffset);
            currentOffset += 2;
        }
        else {
            // If 127, the following 8 bytes interpreted as a 64-bit unsigned integer
            throw new Error('Payloads of this size are not not currently supported by the server');
        }
    }

    // If isMasked === true, the masking key will occupy the four bytes following payload len
    // (including the extended payload length, if present)
    let maskingKey;
    if (isMasked) {
        maskingKey = buffer.readUInt32BE(currentOffset)
        //maskingKey = buffer.readUInt32BE(currentOffset);
        console.log("masking key: " + maskingKey);
        currentOffset += 4;
    }
    // Creates a buffer with enough space to hold payloadLength.length bytes
    const data = Buffer.alloc(payloadLength);

    // If the masking bit was set to 1, we must decode the encoded payload
    if (isMasked) {
        // Loop through the buffer holding the encoded payload one byte at a time,
        // keeping track of which byte in the masking key to use in the next XOR calculation (modulo)
        for (let i = 0, j = 0; i < payloadLength; ++i, j = i % 4) {
            // Extract the correct byte mask from the masking key
            const shift = j == 3 ? 0 : (3 - j) << 3;
            console.log("shift: " + shift)
            const mask = (shift == 0 ? maskingKey : (maskingKey >>> shift)) & 0xFF;
            // Read a byte from the data buffer
            const source = buffer.readUInt8(currentOffset++);
            // XOR the source byte and write the result to the data
            data.writeUInt8(mask^source, i); // the actual code...
        }
    } else {
        // If not masked (not from browser), we can read the JSON data as-is
        buffer.copy(data, 0, currentOffset++);
    }
    // Now, we have our decoded JSON message
    return data.toString('utf8');
}

function constructReply(data) {
    // Retrieving the byte-length of data
    const byteLength = Buffer.byteLength(data);
    // Note: byte-length > 65535 are not supported (by me)
    // Explanation:
    // condition jsonByteLength < 126
    // if true: lengthByteCount = 0
    // if false: lengthByteCount = 2
    const lengthByteCount = byteLength < 126 ? 0 : 2;

    // Explanation:
    // condition lengthByteCount === 0
    // if true: lengthByteCount = jsonByteLength
    // if false: lengthByteCount = 126
    const payloadLength = lengthByteCount === 0 ? byteLength : 126;

    // We must allocate enough space in our buffer for payload, payload length AND
    // the two first bytes w/ FIN-bit, RSV's, MASK-bit etc.
    const buffer = Buffer.alloc(2 + lengthByteCount + byteLength);

    // Write out the first byte, using opcode `1` to indicate
    // that the message frame payload contains text data
    buffer.writeUInt8(0b10000001, 0); // 0b = binary; FIN-bit = 1; OPCODE = 1

    // Write the length of the JSON payload to the second byte
    buffer.writeUInt8(payloadLength, 1);

    let payloadOffset = 2;
    if (lengthByteCount > 0) {
        buffer.writeUInt16BE(byteLength, 2); payloadOffset += lengthByteCount;
    }
    // Write the JSON data to the data buffer
    buffer.write(data, payloadOffset);
    return buffer;
}
