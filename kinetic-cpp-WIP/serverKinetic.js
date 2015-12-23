'use strict';

const kinetic = require('./index.js');

const net = require('net');

const VERSION = 0x46;
const HEADER_SZ = 9;
const HEADER_VERSION_OFFSET = 0;
const HEADER_PBUFSZ_OFFSET = 1;
const HEADER_CHUNKSZ_OFFSET = 5;

let res;
let d = new Buffer(0);
let data = new Buffer(0);

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

        kinetic.read(d.slice(HEADER_SZ), (err, pdu) => {
            callback(null, pdu);
        })
        
        sock.unshift(d.slice(HEADER_SZ + protobufSize + chunkSize));
    });
}

const server = net.createServer((sock) => {
    treatment(sock, (err, pduReq) => {
        if (!err){
            if (pduReq.messageType === 30){
                kinetic.write(29, pduReq.sequence ,(err, pduRes) => {
                    const header = new Buffer(HEADER_SZ);
                    header.writeInt8(VERSION, HEADER_VERSION_OFFSET);
                    header.writeInt32BE(pduRes.length, HEADER_PBUFSZ_OFFSET);
                    header.writeInt32BE(0, HEADER_CHUNKSZ_OFFSET);
                    sock.write(header);
                    sock.write(pduRes);
                })
            }
        } else {
            console.log(err);
        }
    });
});

server.listen(8124);

