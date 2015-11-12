import assert from 'assert';
import net from 'net';
import util from 'util';

import winston from 'winston';

import kinetic from '../../index';

const HOST = '127.0.0.1';
const PORT = 8123;
let sequence = 0;

const logger = new (winston.Logger)({
    transports: [new (winston.transports.Console)({ level: 'error' })]
});

const requestsArr = [
    ['put', 'PUT_RESPONSE'],
    ['get', 'GET_RESPONSE'],
    ['delete', 'DELETE_RESPONSE'],
    ['noop', 'NOOP_RESPONSE'],
    ['flush', 'FLUSH_RESPONSE'],
    ['getLog', 'GETLOG_RESPONSE'],
    ['setClusterVersion', 'SETUP_RESPONSE'],
    ['setClusterVersionTo0', 'SETUP_RESPONSE']
];

function requestsLauncher(request, client) {
    let pdu;

    if (request === 'noop') {
        pdu = new kinetic.NoOpPDU(sequence, 0);
    } else if (request === 'put') {
        pdu = new kinetic.PutPDU(sequence, 0, new Buffer('qwer'),
            new Buffer(0), new Buffer('1'));
        pdu.setChunk(new Buffer("ON DIT BONJOUR TOUT LE MONDE"));
    } else if (request === 'get') {
        pdu = new kinetic.GetPDU(sequence, 0, new Buffer('qwer'));
    } else if (request === 'delete') {
        pdu = new kinetic.DeletePDU( sequence, 0, new Buffer('qwer'),
                                    new Buffer('1'));
    } else if (request === 'flush') {
        pdu = new kinetic.FlushPDU(sequence, 0);
    } else if (request === 'getLog') {
        pdu = new kinetic.GetLogPDU(sequence, 0, [0, 1, 2, 4, 5, 6]);
    } else if (request === 'setClusterVersion') {
        pdu = new kinetic.SetClusterVersionPDU(sequence, 1234, 0);
    } else if (request === 'setClusterVersionTo0') {
        pdu = new kinetic.SetClusterVersionPDU(sequence, 0, 1234);
    }

    pdu.pipe(client, { end: false });
    sequence++;
}

function checkTest(request, requestResponse, done) {
    const client = net.connect(PORT, HOST);

    client.on('data', function heandleData(data) {
        let pdu;
        try {
            pdu = new kinetic.PDU(data);
        } catch (e) {
            return done(e);
        }
        if (pdu.getMessageType() === null ||
            kinetic.getOpName(pdu.getMessageType()) !== requestResponse) {
            requestsLauncher(request, client);
        } else {
            logger.info(util.inspect(pdu.getProtobuf(),
                {showHidden: false, depth: null}));
            logger.info(util.inspect(pdu.getChunk().toString(),
                {showHidden: false, depth: null}));

            assert.deepEqual(pdu.getProtobuf().status.code,
                kinetic.errors.SUCCESS);
            assert.deepEqual(kinetic.getOpName(pdu.getMessageType()),
                requestResponse);

            if (request === 'get') {
                assert.deepEqual(pdu.getChunk(),
                    new Buffer("ON DIT BONJOUR TOUT LE MONDE"));
                assert.equal(pdu.getKey(), "qwer");
                assert.equal(pdu.getDbVersion(), '1');
            }

            client.end();

            done();
        }
    });
}

function checkIntegrity(requestArr) {
    const request = requestArr[0];
    const response = requestArr[1];
    describe(`Assess ${request} and its response ${response}`, () => {
        it(`Chunk and ${request} protobufMessage should be preserved`,
        (done) => { checkTest(request, response, done); });
    });
}

requestsArr.forEach(checkIntegrity);
