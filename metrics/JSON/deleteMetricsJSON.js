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
let timer = '';
const requestNumber = 100000;

time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    a = new kinetic.DeletePDU(sequence, key).read();
    pda = new kinetic.PDU(a);
}

time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' delete : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the deletePDU : ' + pda.getProtobufSize() + ' bytes' + os.EOL;

time0 = [];
time1 = [];

let b;
let pdb;
time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b = new kinetic.DeleteResponsePDU(sequence, sequence, detailedMessage)
        .read();
    pdb = new kinetic.PDU(b);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' deleteResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the deleteResponsePDU : ' + pdb.getProtobufSize() + ' bytes' +
    os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'deleteJSON');
wstream.write(timer);
wstream.end();
