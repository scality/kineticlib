import fs from 'fs';
import os from 'os';

import kinetic from '../../index.js';

let time0 = [];
let time1 = [];

let a;
let b;
let pda;
let pdb;

const sequence = 1;
const detailedMessage = new Buffer('OK');
const key = new Buffer('qwer');
let timer = '';
const requestNumber = 100000;

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    a = new kinetic.PutPDU(sequence, key, 256).read();
    pda = new kinetic.PDU(a);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' put : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the putResponsePDU : ' + pda.getProtobufSize() + ' bytes' +
    os.EOL;

time0 = [];
time1 = [];

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b = new kinetic.PutResponsePDU(sequence, sequence, detailedMessage).read();
    pdb = new kinetic.PDU(b);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' putResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the putResponsePDU : ' + pdb.getProtobufSize() + ' bytes' +
    os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'put');
wstream.write(timer);
wstream.end();
