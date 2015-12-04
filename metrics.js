import kinetic from "./index.js";

import net from 'net';
import crypto from "crypto";
import fs from 'fs';

const chunk = crypto.randomBytes(256);
const ITERATIONS = 10000;
const HEADER_SZ = 9;
const sock = new net.Socket();

let d = new Buffer(0);
let data = new Buffer(0);
let time1 = [];
let strEnd = '';
let counter = 1;

const task = function (i){
    const pdu = new kinetic.PutPDU(i, crypto.randomBytes(40), chunk.length);
    sock.write(pdu.read());
    sock.write(chunk);
}

const treatment = function (sock, callback) {
    sock.on('readable', function () {
        d = sock.read();
        if (d !== null && data !== null && data.length > 0){
            d = Buffer.concat([data, d]);
            data = new Buffer(0);
        }
        if (d === null || d.length < HEADER_SZ){
            data = d;   
            return;  // need to wait for more data
        }

        const protobufSize = d.readInt32BE(1, 5);
        const chunkSize = d.readInt32BE(5);
        if (d.length < HEADER_SZ + protobufSize + chunkSize){
            data = d;
            return;  // need to wait for more data
        }
        const pdu = new kinetic.PDU(d);

        callback(null, pdu);

        if (d.length > HEADER_SZ + protobufSize + chunkSize){
            sock.unshift(d.slice(HEADER_SZ + protobufSize + chunkSize));
        }
    });
}

if (process.argv[2] === undefined){
    process.stdout.write(
        "Usage: node metrics.js 'path/to/file'\n");
    process.exit();
}

sock.connect(8124, '127.0.0.1', function() {
    const time0 = process.hrtime();
    treatment(sock, (err, pdu) => {
        time1 = process.hrtime(time0);
        strEnd += `[ ${time1[0]} , ${time1[1]} ]\n`;
        counter++;
        if (counter === ITERATIONS){
            fs.writeFileSync(process.argv[2], strEnd);
            process.stdout.write("Closing the socket.\n");
            sock.end();
         }
    });
    for(let i = 1; i <= ITERATIONS; i++){
        task(i);
    }
});
