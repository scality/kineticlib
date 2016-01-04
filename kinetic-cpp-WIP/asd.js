'use strict';
const kinetic = require('./index');
const crypto = require("crypto");
const net = require("net");

const VERSION = 0x46;
const HEADER_SZ = 9;
const HEADER_VERSION_OFFSET = 0;
const HEADER_PBUFSZ_OFFSET = 1;
const HEADER_CHUNKSZ_OFFSET = 5;

const sock = new net.Socket();
let data = new Buffer(0);
let d = new Buffer(0);
const chunk = crypto.randomBytes(256);
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
 //       console.log(d);
        kinetic.read(d.slice(HEADER_SZ), (err, pdu) => {
            callback(err, pdu);
        })

        if (d.length > HEADER_SZ + protobufSize + chunkSize){
            sock.unshift(d.slice(HEADER_SZ + protobufSize + chunkSize));
        }
    });
}



sock.connect(8123, '127.0.0.1', function() {
    const time0 = process.hrtime();
/*    for (let i = 0; i < 1000; i++){
        try {
            kinetic.write(30, i, function(err, data){
                if (err) {
                    console.log(err);
                } else {
                    const header = new Buffer(HEADER_SZ);
                    header.writeInt8(VERSION, HEADER_VERSION_OFFSET);
                    header.writeInt32BE(data.length, HEADER_PBUFSZ_OFFSET);
                    header.writeInt32BE(0, HEADER_CHUNKSZ_OFFSET);
                    sock.write(header);
                    sock.write(data);
                }
            });
        } catch (err) {
            console.log(err);
        }
    } */
    let key = new Buffer("qwerty");

    let i = 1;
    const interval = setInterval(() => {
        try {
            kinetic.write(4, i, key, function(err, data){
                if (err) {
                    console.log(err);
                } else {
                    const header = new Buffer(HEADER_SZ);
                    header.writeInt8(VERSION, HEADER_VERSION_OFFSET);
                    header.writeInt32BE(data.length, HEADER_PBUFSZ_OFFSET);
                    header.writeInt32BE(chunk.length, HEADER_CHUNKSZ_OFFSET);
                    sock.write(header);
                    sock.write(data);
                    sock.write(chunk);
                }
            });
        } catch (err) {
            console.log(err);
        }
        if (i === 10){
            clearInterval(interval);
        }
        i++;
    }, 1);
/*
    try {
        kinetic.write(30, 1, function(err, data){
            if (err) {
                console.log(err);
            } else {
                const header = new Buffer(HEADER_SZ);
                header.writeInt8(VERSION, HEADER_VERSION_OFFSET);
                header.writeInt32BE(data.length, HEADER_PBUFSZ_OFFSET);
                header.writeInt32BE(0, HEADER_CHUNKSZ_OFFSET);
                sock.write(header);
                sock.write(data);
            }
        });
    } catch (err) {
        console.log(err);
    }
    */
    treatment(sock, (err, pdu) => {
        if (pdu.messageType !== "null")
            console.log(pdu);
        if (pdu.sequence === 10)
            sock.end();
    });  
});            
