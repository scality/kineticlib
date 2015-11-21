import fs from 'fs';

import kinetic from './index.js';

import os from 'os';

let time0 = [];
let time1 = [];

let a;
let pda;
const sequence = 1;
const detailedMessage = new Buffer('OK');
let timer = '';
const requestNumber = 100000;

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    a = new kinetic.FlushPDU(sequence).read();
    pda = new kinetic.PDU(a);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' flush : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the flushPDU : ' + pda.getProtobufSize() + ' bytes' + os.EOL;

time0 = [];
time1 = [];

let b;
let pdb;
time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b = new kinetic.FlushResponsePDU(sequence, sequence, detailedMessage)
        .read();
    pdb = new kinetic.PDU(b);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' flushResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the flushResponsePDU : ' + pdb.getProtobufSize() + ' bytes' +
    os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'flush');
wstream.write(timer);
wstream.end();
