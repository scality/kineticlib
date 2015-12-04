import json from './indexjson';

import http from 'http';
import crypto from 'crypto';
import fs from 'fs';

const HEADER_SZ = 4;
const chunk = crypto.randomBytes(256);
const ITERATIONS = 10000;
const options = {
    host: '127.0.0.1',
    path: '/',
    port: '8125',
    method: 'POST',
    headers: {
	'content-type': 'application/json'
    }
};

let i = 1;
let endStr = '';
let time1 = [];
let counter = 1;

const callback = function(response) {
    let data = new Buffer(0);

    response.on('data', function (chunk) {
	data = Buffer.concat([data, chunk]);
    });
    
    response.on('end', function () {
	const PDUSize = data.readInt32BE(0);
	const pload = data.slice(HEADER_SZ, HEADER_SZ + PDUSize);
	const resPDU = new json.PDU(pload);
        time1 = process.hrtime(time0);
        endStr += `[ ${time1[0]} , ${time1[1]} ]\n`;
        counter++;
        if (counter === ITERATIONS)
            fs.writeFileSync(process.argv[2], endStr);
    });
};

if (process.argv[2] === undefined){
    process.stdout.write(
        "Usage: node metrics.js 'path/to/file'\n");
    process.exit();
}

const time0 = process.hrtime();
const interval = setInterval(() => {
    i++;
    const req = http.request(options, callback);
    const pdu = new json.PutPDU(i, crypto.randomBytes(40), chunk.length);    
    const writablePDU = pdu.read();
    let buf = new Buffer(HEADER_SZ);
    buf.writeUInt32BE(writablePDU.length);
    req.write(buf);
    req.write(writablePDU);
    req.write(chunk);
    req.end();

    if (i === ITERATIONS)
        clearInterval(interval);
}, 1);
	    
