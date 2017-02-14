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

const logs =  {
    types: [],
    utilizations: [],
    temperatures: [],
    capacity: null,
    configuration: {
        vendor: 'Seagate',
        model: 'Simulator',
        serialNumber: new Buffer('qwerty1234'),
        worldWideName: new Buffer('kinetic'),
        version: '0.8.0.4-SNAPSHOT',
        compilationDate: 'Wed Nov 18 20:08:27 CET 2015',
        sourceHash: '4026da95012a74f137005362a419466dbcb2ae5a',
        protocolVersion: '3.0.6',
        protocolCompilationDate: 'Wed Nov 18 20:08:27 CET 2015',
        protocolSourceHash: 'a5e192b2a42e2919ba3bba5916de8a2435f81243',
        interface: [{
            name: 'wlan0',
            MAC: '28:b2:bd:94:e3:28',
            ipv4Address: '127.0.0.1',
            ipv6Address: '::1:'
        }, {
            name: 'lo',
            MAC: null,
            ipv4Address: '127.0.0.1',
            ipv6Address: '::1:'
        }],
        port: 8123,
        tlsPort: 8443
    },
    statistics: [],
    messages: null,
    limits: {
        maxKeySize: 4096,
        maxValueSize: 1048576,
        maxVersionSize: 2048,
        maxTagSize: 4294967295,
        maxConnections: 4294967295,
        maxOutstandingReadRequests: 4294967295,
        maxOutstandingWriteRequests: 4294967295,
        maxMessageSize: 4294967295,
        maxKeyRangeCount: 200,
        maxIdentityCount: 4294967295,
        maxPinSize: null,
        maxOperationCountPerBatch: 15,
        maxBatchCountPerDevice: 5},
    device: null
};


time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    a = new kinetic.GetLogPDU(sequence).read();
    pda = new kinetic.PDU(a);
}

time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' getlog : ' +
    (time1[0] + 'seconds ' + time1[1]) + ' nanosecondes' + os.EOL;

timer += 'size of the getlogPDU : ' + pda.getProtobufSize() + ' bytes' + os.EOL;

time0 = [];
time1 = [];

let b;
let pdb;
time0 = process.hrtime();
for (let i = 0; i < requestNumber; i++) {
    b = new kinetic.GetLogResponsePDU(sequence, sequence, detailedMessage, logs)
        .read();
    pdb = new kinetic.PDU(b);
}
time1 = process.hrtime(time0);
timer += 'Time for creating ' + requestNumber + ' getlogResponse : ' +
    time1[0] + 'seconds ' + time1[1] + ' nanosecondes' + os.EOL;

timer += 'size of the getlogResponsePDU : ' + pdb.getProtobufSize() + ' bytes' +
    os.EOL;

const wstream = fs.createWriteStream(requestNumber + 'getlogJSON');
wstream.write(timer);
wstream.end();
