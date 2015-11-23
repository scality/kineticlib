import fs from 'fs';
import os from 'os';

import kinetic from './indexjson.js';

let time0 = [];
let time1 = [];

let a;
let pda;
const sequence = 1;
const detailedMessage = new Buffer('OK');
const key = new Buffer('qwer');
const dbVersion = new Buffer('1');
let timer = '';
const requestNumber = 100000;

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    a = new kinetic.GetPDU(sequence, key).read();
    pda = new kinetic.PDU(a);
}

time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' get : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the getPDU : ' + pda.getProtobufSize() + ' bytes' + os.EOL;

time0 = [];
time1 = [];

let b;
let pdb;
time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b = new kinetic.GetResponsePDU(
        sequence, sequence, detailedMessage, key, 256, dbVersion).read();
    pdb = new kinetic.PDU(b);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' getResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the getResponsePDU : ' + pdb.getProtobufSize() + ' bytes' +
    os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'getJSON');
wstream.write(timer);
wstream.end();
