import http from 'http';
import winston from 'winston';
import json from './indexjson';
import os from 'os';

const HEADER_SZ = 4;

exports.createServer = function (port) {
    const server = http.createServer(function (request, response) {
	let data = new Buffer(0);

	request.on('data', function (chunk){
	    data = Buffer.concat([data, chunk]);
	}).on('end', function() {
	    const PDUSize = data.readInt32BE(0);
	    const pload = data.slice(HEADER_SZ, HEADER_SZ + PDUSize);
	    const pdu = new json.PDU(pload);
            if (pdu.getMessageType() === 'PUT'){
		const resPDU = new json.
		    PutResponsePDU(pdu.getSequence(),
				   1, new Buffer('OK'));
		const writableResponse = resPDU.read();
		const buf = new Buffer(HEADER_SZ);
		buf.writeUInt32BE(writableResponse.length);
	        response.writeHead(200, {'Content-Type': 'application/json',
                                         'Content-length':
                                         writableResponse.length + HEADER_SZ});
                response.write(buf);
                response.end(writableResponse);
	    }
	});
    });
    
    if (port) {
	server.listen(port);
    }
    
    return server;
};
