# WebSocket server  - created using HTTP server and custom handshake

The websocket protocol (RFC 6465) is largely used to create the server script of this project. 
From the protocol, the frame diagram is of great help to understand the rules and regulations of 
the methods to implement in order for the self-made websocket server to be able to communicate 
properly with the client. While the server is made using a self-made WebSocket server library, 
the client script was created using the browser's built-in WebSocket class. 
### RFC frame diagram:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
### Purpose of the diagram
The diagram has been used to construct the Server script. 
There are two primary types of frames; message frames and control frames.
Message frames carry message data (the “payload”). Control frames are used for other purposes, 
such as sending a ping or pong, indicating that the connection is about to close, and so forth.
WebSocket frames consist of a header, followed by the message payload, unless it is a control frame. 
The header always starts with two bytes (16 bits). 
Below follows an explanation of each part of the diagram:

FIN:  1 bit

      Indicates that this is the final fragment in a message.  The first
      fragment MAY also be the final fragment.

RSV1, RSV2, RSV3:  1 bit each

      Not relevant for this project. 

Opcode:  4 bits

      Defines the interpretation of the "Payload data".  If an unknown
      opcode is received, the receiving endpoint MUST _Fail the
      WebSocket Connection_.  The following values are defined.

      *  %x0 denotes a continuation frame

      *  %x1 denotes a text frame

      *  %x2 denotes a binary frame

      *  %x3-7 are reserved for further non-control frames

      *  %x8 denotes a connection close

      *  %x9 denotes a ping

      *  %xA denotes a pong

      *  %xB-F are reserved for further control frames

Mask:  1 bit

      Defines whether the "Payload data" is masked.  If set to 1, a
      masking key is present in masking-key, and this is used to unmask
      the "Payload data" as per Section 5.3.  All frames sent from
      client to server have this bit set to 1.

Payload length:  7 bits, 7+16 bits, or 7+64 bits

      The length of the "Payload data", in bytes: if 0-125, that is the
      payload length.  If 126, the following 2 bytes interpreted as a
      16-bit unsigned integer are the payload length.  If 127, the
      following 8 bytes interpreted as a 64-bit unsigned integer (the
      most significant bit MUST be 0) are the payload length.  Multibyte
      length quantities are expressed in network byte order.  Note that
      in all cases, the minimal number of bytes MUST be used to encode
      the length, for example, the length of a 124-byte-long string
      can't be encoded as the sequence 126, 0, 124.  The payload length
      is the length of the "Extension data" + the length of the
      "Application data".  The length of the "Extension data" may be
      zero, in which case the payload length is the length of the
      "Application data".

Masking-key:  0 or 4 bytes

      All frames sent from the client to the server are masked by a
      32-bit value that is contained within the frame.  This field is
      present if the mask bit is set to 1 and is absent if the mask bit
      is set to 0.  See Section 5.3 for further information on client-
      to-server masking.

Payload data:  (x+y) bytes

      The "Payload data" is defined as "Extension data" concatenated
      with "Application data".

Extension data:  x bytes

      Not relevant for this project.

Application data:  y bytes

      Not relevant for this project.
