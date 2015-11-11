# kineticlib -- JavaScript Kinetic library

Node.js library for using the [Kinetic open storage
protocol](https://github.com/Kinetic/kinetic-protocol).

## Requirements

This project's code is written in ES6. If you need to include it from older
JavaScript versions, use babel or an equivalent.

Install npm dependencies using `npm install`.

## Examples

Create a PDU for a PUT at key "mykey" and send it to localhost on port 1234:

```js
import net from 'net';

import kinetic from 'kineticlib';

const pdu = new kinetic.PutPDU(
    new Buffer("mykey"),                 // key
    1,                                   // incrementTCP
    new Buffer('44'), new Buffer('45'),  // dbVersion, newVersion
    1989                                 // clusterVersion
);
pdu.setChunk(new Buffer("D4T4d4t4D4T4d4t4D4T4d4t4D4T4d4t4D4T4d4t4"));

const sock = net.connect(1234, 'localhost');
sock.on("end", () => {
    process.stdout.write("PDU sent through the network.\n");
});

pdu.pipe(sock, { end: false });
```

Decode a PDU message from a buffer:

```js
import kinetic from 'kineticlib';

const rawData = new Buffer('\x46\x00\x00\x00\x32\x00' ... );

const pdu = new kinetic.PDU(rawData);

const type = pdu.getMessageType();
process.stdout.write("Received " + kinetic.getOpName(type) + " PDU.\n");

if (type === kinetic.ops.GET) {
    process.stdout.write("Peer is trying to GET key " + pdu.getKey() + ".\n");
}
```

Handle a decoding error:

```js
import kinetic from 'kineticlib';

const badBuffer = new Buffer('\x46\x00\x00\x00\x32\x00');

try {
    const pdu = new kinetic.PDU(badBuffer);
} catch (e) {
    if (e.badLength)
        process.stdout.write("Message is either truncated or too long.\n");
    else if (e.hmacFail)
        process.stdout.write("Message is corrupted.\n");
    // ...
}
```
