# kineticlib -- JavaScript Kinetic library

Node.js library for using the [Kinetic open storage
protocol](https://github.com/Kinetic/kinetic-protocol).

## Requirements

This project's code is written in ES6. If you need to include it from older
JavaScript versions, use babel or an equivalent.

Install npm dependencies using `npm install`.

## Usage

Sample code for using the Kinetic library:

```js
import kinetic from 'kineticlib';

const rawData = new Buffer('\x46\x00\x00\x00\x32\x00');
const kineticPDU = new kinetic.PDU(rawData);

if (kineticPDU.getMessageType() === kinetic.ops.GET) {
    const response = new kinetic.PutPDU(new Buffer('key'), 1, new Buffer(0),
        new  Buffer('1'), 0);
    response.setChunk(new Buffer('value'));

    const sock = net.connect(1234, 'localhost');
    const ret = response.send(sock);
    if (ret !== kinetic.errors.SUCCESS)
        throw new Error("argh: " + kinetic.getErrorName(ret) + "!");
}
```
