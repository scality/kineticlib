import fs from 'fs';

import kinetic from './index.js';

import os from 'os';

let time0 = [];
let time1 = [];

let a;
let pda;
const sequence = 1;
const detailedMessage = new Buffer('OK');
const key = new Buffer('qwer');
let timer = '';
const requestNumber = 100000;
const dbVersion = new Buffer('1234');

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    a[i] = new kinetic.GetPDU(sequence, key).read();
    pda[i] = new kinetic.PDU(a[i]);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' put : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the getPDU : ' + pda.getProtobufSize() + ' bytes' + os.EOL;

time0 = [];
time1 = [];

let b;
let pdb;

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b[i] = new kinetic.GetResponsePDU(sequence, sequence, detailedMessage, key,
                                      256, dbVersion).read();
    pdb[i] = new kinetic.PDU(b[i]);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' putResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the getPDU : ' + pdb.getProtobufSize() + ' bytes' + os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'get');
wstream.write(timer);
wstream.end();
