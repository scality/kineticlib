import kinetic from './index.js';

import net from 'net';

let res;
let d = new Buffer(0);
let data = new Buffer(0);

const HEADER_SZ = 9;

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
        const pdu = new kinetic.PDU(d);
        
        callback(null, pdu);
        sock.unshift(d.slice(HEADER_SZ + protobufSize + chunkSize));
    });
}



const server = net.createServer({pauseOnConnect: true}, function (sock) {
    treatment(sock, (err, pduReq) => {
        if (pduReq.getMessageType() === kinetic.ops.PUT){
            const pduResponse = new kinetic.PutResponsePDU(
                pduReq.getSequence(), 1, new Buffer('OK'));
            sock.write(pduResponse.read());
        }
    });
});

server.listen(8124);

