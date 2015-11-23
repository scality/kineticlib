import fs from 'fs';
import os from 'os';

import kinetic from './indexjson.js';

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
    a = new kinetic.NoOpPDU(sequence).read();
    pda = new kinetic.PDU(a);
}

time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' noop : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the noopPDU : ' + pda.getProtobufSize() + ' bytes' + os.EOL;

time0 = [];
time1 = [];

let b;
let pdb;
time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b = new kinetic.NoOpResponsePDU(sequence, sequence, detailedMessage)
        .read();
    pdb = new kinetic.PDU(b);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' noopResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the noopResponsePDU : ' + pdb.getProtobufSize() + ' bytes' +
    os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'noopJSON');
wstream.write(timer);
wstream.end();