import assert from 'assert';
import net from 'net';
import util from 'util';

import posixRead from 'posix-read';
import winston from 'winston';

import kinetic from '../../index';

const logger = new (winston.Logger)({
    transports: [new (winston.transports.Console)({ level: 'error' })]
});

describe('kinetic.PDU decoding()', () => {
    function checkDecoding(data, checkFunction, done) {
        try {
            const pdu = new kinetic.PDU(data);
            checkFunction(pdu);
            done();
        } catch (err) {
            done(err);
        }
    }

    it('should parse valid Initial PDU', (done) => {
        /*
         * Note: expected buffers formatted using:
         *   hexdump -C FILE | cut -b10-33,35-58 | sed 's/\s\+$//g;s/ /\\x/g'
         */
        const rawData = new Buffer(
            "\x46\x00\x00\x01\x5a\x00\x00\x00\x00\x20\x03\x3a\xd5\x02\x0a\x09" +
            "\x08\x00\x18\xc2\xea\x9d\xe4\x91\x2a\x12\xc3\x02\x32\xc0\x02\x2a" +
            "\x86\x02\x2a\x07\x53\x65\x61\x67\x61\x74\x65\x32\x09\x53\x69\x6d" +
            "\x75\x6c\x61\x74\x6f\x72\x3a\x0a\x71\x77\x65\x72\x74\x79\x31\x32" +
            "\x33\x34\x72\x07\x6b\x69\x6e\x65\x74\x69\x63\x42\x10\x30\x2e\x38" +
            "\x2e\x30\x2e\x34\x2d\x53\x4e\x41\x50\x53\x48\x4f\x54\x62\x1c\x57" +
            "\x65\x64\x20\x4e\x6f\x76\x20\x31\x38\x20\x32\x30\x3a\x30\x38\x3a" +
            "\x32\x37\x20\x43\x45\x54\x20\x32\x30\x31\x35\x6a\x28\x34\x30\x32" +
            "\x36\x64\x61\x39\x35\x30\x31\x32\x61\x37\x34\x66\x31\x33\x37\x30" +
            "\x30\x35\x33\x36\x32\x61\x34\x31\x39\x34\x36\x36\x64\x62\x63\x62" +
            "\x32\x61\x65\x35\x61\x7a\x05\x33\x2e\x30\x2e\x36\x82\x01\x1c\x57" +
            "\x65\x64\x20\x4e\x6f\x76\x20\x31\x38\x20\x32\x30\x3a\x30\x38\x3a" +
            "\x32\x37\x20\x43\x45\x54\x20\x32\x30\x31\x35\x8a\x01\x28\x61\x35" +
            "\x65\x31\x39\x32\x62\x32\x61\x34\x32\x65\x32\x39\x31\x39\x62\x61" +
            "\x33\x62\x62\x61\x35\x39\x31\x36\x64\x65\x38\x61\x32\x34\x33\x35" +
            "\x66\x38\x31\x32\x34\x33\x4a\x1b\x0a\x05\x77\x6c\x61\x6e\x30\x12" +
            "\x09\xdb\xc6\xf6\x6d\xdf\x78\x7b\x7d\xbc\x1a\x04\xd7\x6e\xf4\xd3" +
            "\x22\x01\xd7\x4a\x0d\x0a\x02\x6c\x6f\x1a\x04\xd7\x6e\xf4\xd3\x22" +
            "\x01\xd7\x50\xbb\x3f\x58\xfb\x41\x42\x35\x08\x80\x20\x10\x80\x80" +
            "\x40\x18\x80\x10\x20\xff\xff\xff\xff\x0f\x28\xff\xff\xff\xff\x0f" +
            "\x30\xff\xff\xff\xff\x0f\x38\xff\xff\xff\xff\x0f\x40\xff\xff\xff" +
            "\xff\x0f\x48\xc8\x01\x50\xff\xff\xff\xff\x0f\x60\x0f\x68\x05\x1a" +
            "\x02\x08\x01", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 341);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(), null);
            assert.deepStrictEqual(pdu.getClusterVersion(), 0);
            assert.deepStrictEqual(pdu.getSequence(), undefined);
            assert.deepStrictEqual(pdu.getKey(), undefined);
            assert.deepStrictEqual(pdu.getDbVersion(), undefined);
            assert.deepStrictEqual(pdu.getNewVersion(), undefined);
            assert.deepStrictEqual(pdu._command.status.code,
                kinetic.errors.SUCCESS);
            assert.deepStrictEqual(typeof pdu.getLogObject(), 'object');
        }, done);
    });

    it('should parse valid NOOP', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x70\x14\x62\x07\x0b\x41\xf4\xb0\x21\xd1\x93\xfa\x53\xb4\x15" +
            "\xf0\x4b\xb6\xba\xa2\x3a\x14\x0a\x10\x08\xbe\xea\xda\x04\x18\xcd" +
            "\xa0\x85\xc4\x8c\x2a\x20\x7b\x38\x1e\x12\x00", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 20);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.NOOP);
            assert.deepStrictEqual(pdu.getClusterVersion(), 9876798);
            assert.deepStrictEqual(pdu.getSequence(), 123);
            assert.deepStrictEqual(pdu.getKey(), undefined);
            assert.deepStrictEqual(pdu.getDbVersion(), undefined);
            assert.deepStrictEqual(pdu.getNewVersion(), undefined);
            assert.deepStrictEqual(pdu.getForce(), false);
        }, done);
    });

    it('should parse valid NOOP_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x2f\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x62\x0c\xb9\x95\xa8\x03\x38\xe4\x79\x5f\xac\xe0\x21\x8c\xbd" +
            "\x11\xaf\x14\x74\x83\x3a\x11\x0a\x0b\x18\xa9\xc4\xd2\x92\x8d\x2a" +
            "\x30\x02\x38\x1d\x1a\x02\x08\x01", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 17);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.NOOP_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 2);
        }, done);
    });

    it('should parse valid PUT', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x41\x00\x00\x00\x28\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x3b\xad\xea\x16\x6f\x8b\x37\xff\xf6\xd6\x0d\x03\x24\xf1\xb5" +
            "\x53\xa9\x14\xbb\xc6\x3a\x23\x0a\x0e\x08\xc5\x0f\x18\xf8\x87\xcd" +
            "\xf4\x8c\x2a\x20\x01\x38\x04\x12\x11\x0a\x0f\x12\x01\xe3\x1a\x05" +
            "mykey\x22\x01\xe3\x48\x01D4T4d4t4D4T4d4t4D4T4d4t4D4T4d4t4D4T4d4t4",
            "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 35);
            assert.deepStrictEqual(pdu.getChunkSize(), 40);
            assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.PUT);
            assert.deepStrictEqual(pdu.getClusterVersion(), 1989);
            assert.deepStrictEqual(pdu.getSequence(), 1);
            assert.deepStrictEqual(pdu.getKey(), new Buffer("mykey"));
            assert.deepStrictEqual(pdu.getDbVersion(),
                new Buffer('ã', 'ascii'));
            assert.deepStrictEqual(pdu.getNewVersion(),
                new Buffer('ã', 'ascii'));
            assert.deepStrictEqual(pdu.getForce(), false);
        }, done);
    });

    it('should parse valid PUT_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x33\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x01\x6d\x91\xa7\x8c\x67\xdf\x96\x1f\xca\x53\xa5\xa5\x0b\xdf" +
            "\xa5\xe6\x4f\x0a\xe2\x3a\x15\x0a\x0b\x18\x8d\xc4\xd2\x92\x8d\x2a" +
            "\x30\x00\x38\x03\x12\x02\x0a\x00\x1a\x02\x08\x01", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 21);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.PUT_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 0);
            assert.deepStrictEqual(pdu.getDbVersion(), undefined);
        }, done);
    });

    it('should parse valid GET', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x37\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xb6\x8a\x74\x54\x51\xf1\xcb\x4a\x99\xe2\x78\x3c\x29\x15\x45" +
            "\x21\x42\x45\xc0\x33\x3a\x19\x0a\x0d\x08\x00\x18\xd6\xec\xde\x95" +
            "\x8d\x2a\x20\x01\x38\x02\x12\x08\x0a\x06\x1a\x04\x71\x77\x65\x72",
            "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 25);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.GET);
            assert.deepStrictEqual(pdu.getClusterVersion(), 0);
            assert.deepStrictEqual(pdu.getSequence(), 1);
            assert.deepStrictEqual(pdu.getKey(), new Buffer("qwer"));
            assert.deepStrictEqual(pdu.getDbVersion(), undefined);
            assert.deepStrictEqual(pdu.getNewVersion(), undefined);
            assert.deepStrictEqual(pdu.getForce(), false);
        }, done);
    });

    it('should parse valid GET_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x3d\x00\x00\x00\x1c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x40\x97\x7d\x14\xc5\xb3\xd4\x17\x87\x27\x23\xcf\xb7\x25\x8d" +
            "\x6a\x36\xbe\x54\xe2\x3a\x1f\x0a\x0b\x18\xab\xdf\x96\xf5\x8c\x2a" +
            "\x30\x01\x38\x01\x12\x0c\x0a\x0a\x1a\x04qwer\x22\x00" +
            "\x2a\x00\x1a\x02\x08\x01ON DIT BONJOUR TOUT LE MONDE", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 31);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getChunkSize(), 28);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.GET_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 1);
            assert.deepStrictEqual(pdu.getKey(), new Buffer("qwer"));
            assert.deepStrictEqual(pdu.getDbVersion(), new Buffer(''));
            assert.deepStrictEqual(pdu.getNewVersion(), undefined);
            assert.deepStrictEqual(pdu.getForce(), false);
        }, done);
    });

    it('should parse valid DELETE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x41\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xf7\x12\xbb\xff\x62\x2b\x2b\xa3\x1a\xab\x42\xdd\x3d\x61\x83" +
            "\x92\xa6\xe0\x07\x34\x3a\x23\x0a\x0d\x08\x00\x18\x83\xd1\x9b\xb8" +
            "\x91\x2a\x20\x00\x38\x06\x12\x12\x0a\x10\x1a\x06\x73\x74\x72\x69" +
            "\x6e\x67\x22\x04\x31\x32\x33\x34\x48\x01", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 35);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.DELETE);
            assert.deepStrictEqual(pdu.getClusterVersion(), 0);
            assert.deepStrictEqual(pdu.getSequence(), 0);
            assert.deepStrictEqual(pdu.getKey(), new Buffer("string"));
        }, done);
    });

    it('should parse valid DELETE_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x35\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x1b\x4b\xa0\xe1\x25\xdb\xd0\x90\xbd\x1b\x96\xcd\xf6\x97\x14" +
            "\x23\x12\xfe\xb8\x2c\x3a\x17\x0a\x04\x30\x00\x38\x05\x12\x02\x0a" +
            "\x00\x1a\x0b\x08\x01\x1a\x07\x53\x55\x43\x43\x45\x53\x53",
            "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 23);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.DELETE_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 0);
        }, done);
    });

    it('should parse valid FLUSH', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x2f\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x51\xb0\x2c\x5f\xad\x9e\x5a\x59\x85\x9c\xa2\x91\x53\xd4\x47" +
            "\xe1\x1f\x6b\x73\x8e\x3a\x11\x0a\x0d\x08\x00\x18\xe3\xec\xde\x95" +
            "\x8d\x2a\x20\x03\x38\x20\x12\x00", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 17);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.FLUSH);
            assert.deepStrictEqual(pdu.getClusterVersion(), 0);
            assert.deepStrictEqual(pdu.getSequence(), 3);
        }, done);
    });


    it('should parse valid FLUSH_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x2f\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x54\x1a\xc5\x91\x49\xdf\xf4\x1d\x5d\xdd\x73\xac\x23\xce\xeb" +
            "\xe0\x10\x74\xf8\x1a\x3a\x11\x0a\x0b\x18\xad\xc4\xd2\x92\x8d\x2a" +
            "\x30\x03\x38\x1f\x1a\x02\x08\x01", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 17);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.FLUSH_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 3);
        }, done);
    });

    it('should parse valid SetClusterVersion', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x34\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xde\xb2\xcf\xf8\x3b\x95\x83\x83\x72\xf0\xb3\xbb\xd6\xcd\xa0" +
            "\x70\x21\x07\xe1\xf0\x3a\x16\x0a\x0d\x08\x00\x18\xed\x95\xcb\xb9" +
            "\x91\x2a\x20\x00\x38\x16\x12\x05\x1a\x03\x08\xd2\x09", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 22);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.SET_CLUSTER_VERSION);
            assert.deepStrictEqual(pdu.getClusterVersion(), 0);
            assert.deepStrictEqual(pdu.getNewClusterVersion(), 1234);
            assert.deepStrictEqual(pdu.getSequence(), 0);
        }, done);
    });

    it('should parse valid SETUP_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x31\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x6e\xe5\xc4\x5e\xa6\x02\x42\xa9\x55\x33\x68\xf0\x5e\x3b\xc9" +
            "\xb9\x89\x96\x7d\xa7\x3a\x13\x0a\x04\x30\x00\x38\x15\x1a\x0b\x08" +
            "\x01\x1a\x07\x53\x55\x43\x43\x45\x53\x53", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 19);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.SETUP_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 0);
        }, done);
    });

    it('should parse valid GETLOG', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x3f\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xcf\xa0\xb4\xec\xc7\x18\xd6\x1f\x55\x6f\xd8\xde\xd4\x91\x3b" +
            "\x5a\xaf\x7d\x91\x19\x3a\x21\x0a\x0d\x08\x00\x18\xec\xec\xde\x95" +
            "\x8d\x2a\x20\x04\x38\x18\x12\x10\x32\x0e\x08\x00\x08\x01\x08\x02" +
            "\x08\x03\x08\x04\x08\x05\x08\x06", "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 33);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.GETLOG);
            assert.deepStrictEqual(pdu.getClusterVersion(), 0);
            assert.deepStrictEqual(pdu.getSequence(), 4);
        }, done);
    });

        /*
         *  GETLOG_RESPONSE - Little problem for the HMAC integrity verification
         *  with the log type 3 (configuration)
         *  issue #29 : https://github.com/scality/IronMan-Arsenal/issues/29
         */
    it('should parse valid GETLOG_RESPONSE', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x01\x7f\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xc3\x10\xd3\x89\xce\xf8\x78\xb0\x3d\x30\x1b\x33\xb7\xbf\xa1" +
            "\x55\xc9\x5e\x40\x15\x3a\xe0\x02\x0a\x0b\x18\xff\xdc\xe3\xba\x8d" +
            "\x2a\x30\x04\x38\x17\x12\xcc\x02\x32\xc9\x02\x08\x00\x08\x01\x08" +
            "\x02\x08\x04\x08\x05\x08\x06\x12\x0a\x0a\x03\x48\x44\x41\x15\x85" +
            "\xeb\x11\x3f\x12\x0a\x0a\x03\x45\x4e\x30\x15\xae\x47\xe1\x3e\x12" +
            "\x0a\x0a\x03\x45\x4e\x31\x15\x8f\xc2\xf5\x3d\x12\x0a\x0a\x03\x43" +
            "\x50\x55\x15\xec\x51\x38\x3f\x1a\x19\x0a\x03\x48\x44\x41\x15\x00" +
            "\x00\x1c\x42\x1d\x00\x00\xa0\x40\x25\x00\x00\xc8\x42\x2d\x00\x00" +
            "\xc8\x41\x1a\x19\x0a\x03\x43\x50\x55\x15\x00\x00\x50\x42\x1d\x00" +
            "\x00\xa0\x40\x25\x00\x00\xc8\x42\x2d\x00\x00\xc8\x41\x22\x0c\x20" +
            "\x80\xa0\xcd\xec\xeb\x06\x2d\x79\x62\x26\x3d\x32\x0b\x08\x04\x20" +
            "\xb0\xb0\x01\x28\xee\xfc\xb3\x0a\x32\x0a\x08\x02\x20\xf4\x6e\x28" +
            "\xd6\xe9\xb7\x05\x32\x0b\x08\x06\x20\xd0\xfd\x01\x28\x99\xac\xea" +
            "\x01\x32\x09\x08\x0a\x20\xfa\x01\x28\xc9\x84\x02\x32\x09\x08\x08" +
            "\x20\xfe\x01\x28\xd4\x87\x02\x32\x09\x08\x0c\x20\xe4\x0c\x28\xa0" +
            "\xd6\x17\x32\x06\x08\x10\x20\x00\x28\x00\x32\x09\x08\x1a\x20\x8b" +
            "\x06\x28\x99\xc7\x05\x32\x09\x08\x16\x20\xb9\x02\x28\xe4\x94\x02" +
            "\x32\x0a\x08\x18\x20\xa2\x02\x28\xe6\xcf\x88\x04\x32\x07\x08\x1c" +
            "\x20\x1c\x28\xef\x27\x3a\x16\x4d\x65\x73\x73\x61\x67\x65\x20\x66" +
            "\x72\x6f\x6d\x20\x73\x69\x6d\x75\x6c\x61\x74\x6f\x72\x42\x35\x08" +
            "\x80\x20\x10\x80\x80\x40\x18\x80\x10\x20\xff\xff\xff\xff\x0f\x28" +
            "\xff\xff\xff\xff\x0f\x30\xff\xff\xff\xff\x0f\x38\xff\xff\xff\xff" +
            "\x0f\x40\xff\xff\xff\xff\x0f\x48\xc8\x01\x50\xff\xff\xff\xff\x0f" +
            "\x60\x0f\x68\x05\x1a\x02\x08\x01",  "ascii");

        checkDecoding(rawData, (pdu) => {
            assert.deepStrictEqual(pdu.getCommandSize(), 352);
            assert.deepStrictEqual(pdu.getStatusCode(), kinetic.errors.SUCCESS);
            assert.deepStrictEqual(pdu.getChunkSize(), 0);
            assert.deepStrictEqual(pdu.getMessageType(),
                kinetic.ops.GETLOG_RESPONSE);
            assert.deepStrictEqual(pdu.getSequence(), 4);
            assert.deepStrictEqual(pdu.getLogObject().types,
                [0, 1, 2, 4, 5, 6]);
        }, done);
    });

    it('should detect PDU with invalid version', (done) => {
        const rawData = new Buffer(
            "\x47\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x70\x14\x62\x07\x0b\x41\xf4\xb0\x21\xd1\x93\xfa\x53\xb4\x15" +
            "\xf0\x4b\xb6\xba\xa2\x3a\x14\x0a\x10\x08\xbe\xea\xda\x04\x18\xcd" +
            "\xa0\x85\xc4\x8c\x2a\x20\x7b\x38\x1e\x12\x00", "ascii");

        try {
            const pdu = new kinetic.PDU(rawData);
            logger.info(util.inspect(pdu.getProtobuf(),
                {showHidden: false, depth: null}));

            done(new Error('Bad error throwing in _parse/constructor()'));
        } catch (e) {
            if (e.badVersion)
                done();
            else
                done(e);
        }
    });

    it('should detect PDU with truncated header', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x01\x7f\x00\x00\x00\x00", "ascii");

        try {
            const pdu = new kinetic.PDU(rawData);
            pdu;
            done(new Error("No error thrown"));
        } catch (e) {
            if (e.badLength)
                done();
            else
                done(e);
        }
    });

    it('should detect PDU with truncated message', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x70\x14\x62\x07\x0b\x41\xf4\xb0\x21\xd1\x93\xfa\x53\xb4\x15" +
            "\xf0\x4b\xb6\xba\xa2\x3a\x14\x0a\x10\x08\xbe\xea\xda\x04\x18\xcd" +
            "\xa0\x85\xc4\x8c\x2a\x20\x7b\x38\x1e\x12", "ascii");

        try {
            const pdu = new kinetic.PDU(rawData);
            pdu;
            done(new Error("No error thrown"));
        } catch (e) {
            if (e.badLength)
                done();
            else
                done(e);
        }
    });

    it('should detect PDU with bad HMAC', (done) => {
        const rawData = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x71\x14\x62\x07\x0b\x41\xf4\xb0\x22\xd1\x93\xfa\x53\xb4\x15" +
            "\xf0\x4b\xb6\xba\xa2\x3a\x14\x0a\x10\x08\xbe\xea\xda\x04\x18\xcd" +
            "\xa0\x85\xc4\x8c\x2a\x20\x7b\x38\x1e\x12\x00", "ascii");

        try {
            const pdu = new kinetic.PDU(rawData);
            logger.info(util.inspect(pdu.getProtobuf(),
                {showHidden: false, depth: null}));

            done(new Error('Bad error throwing in _parse/constructor()'));
        } catch (e) {
            if (e.hmacFail)
                done();
            else
                done(e);
        }
    });
});

describe('kinetic.streamToPDU()', () => {
    function getNewSocket(callback) {
        const otherEnd = new net.Socket();

        const server = net.createServer(
            { pauseOnConnect: true },
            function onConnection(socket) {
                server.close();
                callback(socket, otherEnd);
            });

        server.listen(function onListening() {
            otherEnd.connect(server.address().port);
        });
    }

    it('should parse one-block stream', (done) => {
        const input = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x70\x14\x62\x07\x0b\x41\xf4\xb0\x21\xd1\x93\xfa\x53\xb4\x15" +
            "\xf0\x4b\xb6\xba\xa2\x3a\x14\x0a\x10\x08\xbe\xea\xda\x04\x18\xcd" +
            "\xa0\x85\xc4\x8c\x2a\x20\x7b\x38\x1e\x12\x00", "ascii");

        getNewSocket((socket, otherEnd) => {
            kinetic.streamToPDU(socket, (err, pdu) => {
                if (err)
                    return done(err);

                assert.deepStrictEqual(pdu.getCommandSize(), 20);
                assert.deepStrictEqual(pdu.getChunkSize(), 0);
                assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.NOOP);
                assert.deepStrictEqual(pdu.getClusterVersion(), 9876798);
                assert.deepStrictEqual(pdu.getSequence(), 123);
                done();
            });

            otherEnd.write(input);
        });
    });

    it('should parse multi-part stream', (done) => {
        const part1 = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x70\x14\x62\x07\x0b\x41\xf4\xb0\x21\xd1\x93\xfa", "ascii");
        const part2 = new Buffer(
            "\x53\xb4\x15\xf0\x4b\xb6\xba\xa2\x3a\x14\x0a\x10\x08\xbe\xea\xda" +
            "\x04\x18\xcd\xa0\x85\xc4\x8c\x2a\x20\x7b\x38", "ascii");
        const part3 = new Buffer("\x1e\x12\x00", "ascii");

        getNewSocket((socket, otherEnd) => {
            kinetic.streamToPDU(socket, (err, pdu) => {
                if (err)
                    return done(err);

                assert.deepStrictEqual(pdu.getCommandSize(), 20);
                assert.deepStrictEqual(pdu.getChunkSize(), 0);
                assert.deepStrictEqual(pdu.getMessageType(), kinetic.ops.NOOP);
                assert.deepStrictEqual(pdu.getClusterVersion(), 9876798);
                assert.deepStrictEqual(pdu.getSequence(), 123);
                done();
            });

            otherEnd.write(part1);
            setTimeout(() => {
                otherEnd.write(part2);
            }, 10);
            setTimeout(() => {
                otherEnd.write(part3);
            }, 40);
        });
    });

    it('should detect truncated stream', (done) => {
        const input = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x70\x14\x62\x07\x0b\x41\xf4\xb0\x21\xd1\x93\xfa", "ascii");

        getNewSocket((socket, otherEnd) => {
            kinetic.streamToPDU(socket, (err) => {
                if (err) {
                    if (err.endOfFile)
                        done();
                    else
                        done(err);
                } else {
                    done(new Error("No error thrown"));
                }
            });

            otherEnd.end(input);
        });
    });

    it("should not consume chunk data (with on('data'))", (done) => {
        const input = new Buffer(
            "\x46\x00\x00\x00\x3e\x00\x00\x00\x1c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x7d\x41\xc3\xd7\x37\xb9\x69\x82\xef\xb5\x2d\x7b\xc3\x9f\x47" +
            "\x35\x82\x92\x29\x6d\x3a\x20\x0a\x0d\x08\x00\x18\xdb\x9e\xcc\xc0" +
            "\x8d\x2a\x20\x00\x38\x04\x12\x0f\x0a\x0d\x12\x01\x31\x1a\x04qwer" +
            "\x22\x00\x48\x01ON DIT BONJOUR TOUT LE MONDE", "ascii");

        getNewSocket((socket, otherEnd) => {
            kinetic.streamToPDU(socket, (err) => {
                if (err)
                    return done(err);

                socket.on('data', (chunk) => {
                    assert.deepStrictEqual(
                        chunk, new Buffer("ON DIT BONJOUR TOUT LE MONDE"));
                    done();
                });
                socket.resume();
            });

            otherEnd.write(input);
        });
    });

    it('should not consume chunk data (with read())', (done) => {
        const input = new Buffer(
            "\x46\x00\x00\x00\x3e\x00\x00\x00\x1c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x7d\x41\xc3\xd7\x37\xb9\x69\x82\xef\xb5\x2d\x7b\xc3\x9f\x47" +
            "\x35\x82\x92\x29\x6d\x3a\x20\x0a\x0d\x08\x00\x18\xdb\x9e\xcc\xc0" +
            "\x8d\x2a\x20\x00\x38\x04\x12\x0f\x0a\x0d\x12\x01\x31\x1a\x04qwer" +
            "\x22\x00\x48\x01ON DIT BONJOUR TOUT LE MONDE", "ascii");

        getNewSocket((socket, otherEnd) => {
            kinetic.streamToPDU(socket, (err) => {
                if (err)
                    return done(err);

                posixRead(socket, 14, (err, chunk) => {
                    if (err)
                        return done(err);

                    assert.deepStrictEqual(chunk, new Buffer("ON DIT BONJOUR"));
                    done();
                });
                socket.resume();
            });

            otherEnd.write(input);
        });
    });

    it('should accept 50 transactions in the same TCP session', (done) => {
        const input = new Buffer(
            "\x46\x00\x00\x00\x3e\x00\x00\x00\x1c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x7d\x41\xc3\xd7\x37\xb9\x69\x82\xef\xb5\x2d\x7b\xc3\x9f\x47" +
            "\x35\x82\x92\x29\x6d\x3a\x20\x0a\x0d\x08\x00\x18\xdb\x9e\xcc\xc0" +
            "\x8d\x2a\x20\x00\x38\x04\x12\x0f\x0a\x0d\x12\x01\x31\x1a\x04qwer" +
            "\x22\x00\x48\x01ON DIT BONJOUR TOUT LE MONDE", "ascii");

        getNewSocket((socket, otherEnd) => {
            function newTransaction(n) {
                kinetic.streamToPDU(socket, (err, pdu) => {
                    if (err)
                        return done(err);

                    posixRead(socket, pdu.getChunkSize(), (err, chunk) => {
                        if (err)
                            return done(err);

                        assert.deepStrictEqual(
                            chunk, new Buffer("ON DIT BONJOUR TOUT LE MONDE"));

                        if (n > 0)
                            newTransaction(n - 1);
                        else
                            done();
                    });
                });

                otherEnd.write(input);
            }

            newTransaction(50);
        });
    });
});

describe('kinetic.PDU encoding()', () => {
    it('should write valid Initial PDU', (done) => {
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
                maxBatchCountPerDevice: 5 },
            device: null
        };

        const result = new kinetic.InitPDU(logs).read();

        const expected = new Buffer(
            "\x46\x00\x00\x01\x5a\x00\x00\x00\x00\x20\x03\x3a\xd5\x02\x0a\x09" +
            "\x08\x00\x18\xc2\xea\x9d\xe4\x91\x2a\x12\xc3\x02\x32\xc0\x02\x2a" +
            "\x86\x02\x2a\x07\x53\x65\x61\x67\x61\x74\x65\x32\x09\x53\x69\x6d" +
            "\x75\x6c\x61\x74\x6f\x72\x3a\x0a\x71\x77\x65\x72\x74\x79\x31\x32" +
            "\x33\x34\x72\x07\x6b\x69\x6e\x65\x74\x69\x63\x42\x10\x30\x2e\x38" +
            "\x2e\x30\x2e\x34\x2d\x53\x4e\x41\x50\x53\x48\x4f\x54\x62\x1c\x57" +
            "\x65\x64\x20\x4e\x6f\x76\x20\x31\x38\x20\x32\x30\x3a\x30\x38\x3a" +
            "\x32\x37\x20\x43\x45\x54\x20\x32\x30\x31\x35\x6a\x28\x34\x30\x32" +
            "\x36\x64\x61\x39\x35\x30\x31\x32\x61\x37\x34\x66\x31\x33\x37\x30" +
            "\x30\x35\x33\x36\x32\x61\x34\x31\x39\x34\x36\x36\x64\x62\x63\x62" +
            "\x32\x61\x65\x35\x61\x7a\x05\x33\x2e\x30\x2e\x36\x82\x01\x1c\x57" +
            "\x65\x64\x20\x4e\x6f\x76\x20\x31\x38\x20\x32\x30\x3a\x30\x38\x3a" +
            "\x32\x37\x20\x43\x45\x54\x20\x32\x30\x31\x35\x8a\x01\x28\x61\x35" +
            "\x65\x31\x39\x32\x62\x32\x61\x34\x32\x65\x32\x39\x31\x39\x62\x61" +
            "\x33\x62\x62\x61\x35\x39\x31\x36\x64\x65\x38\x61\x32\x34\x33\x35" +
            "\x66\x38\x31\x32\x34\x33\x4a\x1b\x0a\x05\x77\x6c\x61\x6e\x30\x12" +
            "\x09\xdb\xc6\xf6\x6d\xdf\x78\x7b\x7d\xbc\x1a\x04\xd7\x6e\xf4\xd3" +
            "\x22\x01\xd7\x4a\x0d\x0a\x02\x6c\x6f\x1a\x04\xd7\x6e\xf4\xd3\x22" +
            "\x01\xd7\x50\xbb\x3f\x58\xfb\x41\x42\x35\x08\x80\x20\x10\x80\x80" +
            "\x40\x18\x80\x10\x20\xff\xff\xff\xff\x0f\x28\xff\xff\xff\xff\x0f" +
            "\x30\xff\xff\xff\xff\x0f\x38\xff\xff\xff\xff\x0f\x40\xff\xff\xff" +
            "\xff\x0f\x48\xc8\x01\x50\xff\xff\xff\xff\x0f\x60\x0f\x68\x05\x1a" +
            "\x02\x08\x01", "ascii");

        // Ignore the timestamp bytes (17 -> 24)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(24).equals(expected.slice(24)));
        done();
    });

    it('should write valid Initial PDU with UNSOLICITEDSTATUS', (done) => {
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
                maxBatchCountPerDevice: 5 },
            device: null
        };

        const pdu = new kinetic.InitPDU(logs);
        pdu._buildProtobuf();

        // the authType 3 is the UNSOLICITEDSTATUS authType
        assert.deepStrictEqual(pdu._protobuf.authType, 3);
        done();
    });

    it('should write valid NOOP', (done) => {
        const result = new kinetic.NoOpPDU(123, {clusterVersion: 9876798})
            .read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x32\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xde\x57\x30\x36\x5a\x4a\x6f\xb7\x88\x02\x0b\xc4\x38\x0f\x76" +
            "\xd9\xf1\xae\x57\x3b\x3a\x14\x0a\x10\x08\xbe\xea\xda\x04\x18\x82" +
            "\xf9\xdb\x8f\x8d\x2a\x20\x7b\x38\x1e\x12\x00", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 47 -> 51)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 47).equals(expected.slice(37, 47)));
        assert(result.slice(52).equals(expected.slice(52)));

        done();
    });

    it('should write valid NOOP_RESPONSE', (done) => {
        const result = new kinetic.NoOpResponsePDU(1, 1, new Buffer(0)).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x2a\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x5f\x85\x18\x00\x1c\x3b\x1a\xa8\x3c\x9b\xfd\xfe\x32\x9f\x0f" +
            "\x13\xc4\xba\x1a\xcb\x3a\x0c\x0a\x04\x30\x01\x38\x1d\x1a\x04\x08" +
            "\x01\x1a\x00", "ascii");

        assert(result.equals(expected));

        done();
    });

    it('should write valid PUT (option force missing)', (done) => {
        const chunk = new Buffer("HI EVERYBODY");

        const options = {
            dbVersion: new Buffer('2'),
            newVersion: new Buffer('3'),
        };

        const k = new kinetic.PutPDU(1, 'string', chunk.length, options);

        const result = Buffer.concat([k.read(), chunk]);

        const expected = new Buffer(
            "\x46\x00\x00\x00\x41\x00\x00\x00\x0c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x49\x32\xeb\x78\xae\x2d\x7f\x48\x97\x7e\x76\x58\x15\x07\xd0" +
            "\xcf\xd5\xdc\x6d\x8c\x3a\x23\x0a\x0d\x08\x00\x18\xbd\x96\x89\x96" +
            "\x91\x2a\x20\x01\x38\x04\x12\x12\x0a\x10\x12\x01\x33\x1a\x06\x73" +
            "\x74\x72\x69\x6e\x67\x22\x01\x32\x48\x01\x48\x49\x20\x45\x56\x45" +
            "\x52\x59\x42\x4f\x44\x59", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid PUT (force: true)', (done) => {
        const chunk = new Buffer("HI EVERYBODY");
        const options = {
            dbVersion: new Buffer('2'),
            newVersion: new Buffer('3'),
            force: true,
        };

        const k = new kinetic.PutPDU(1, 'string', chunk.length, options);

        const result = Buffer.concat([k.read(), chunk]);

        const expected = new Buffer(
            "\x46\x00\x00\x00\x43\x00\x00\x00\x0c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x33\x55\x10\x85\x03\x2d\xaf\x1c\xd3\x20\x40\xe0\x92\xfa\xb6" +
            "\xbe\xb2\x9b\x2c\xd1\x3a\x25\x0a\x0d\x08\x00\x18\xa1\xc3\x8e\x96" +
            "\x91\x2a\x20\x01\x38\x04\x12\x14\x0a\x12\x12\x01\x33\x40\x01\x1a" +
            "\x06\x73\x74\x72\x69\x6e\x67\x22\x01\x32\x48\x01\x48\x49\x20\x45" +
            "\x56\x45\x52\x59\x42\x4f\x44\x59", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid PUT (force: false)', (done) => {
        const chunk = new Buffer("HI EVERYBODY");
        const options = {
            dbVersion: new Buffer('2'),
            newVersion: new Buffer('3'),
            force: false,
        };

        const k = new kinetic.PutPDU(1, 'string', chunk.length, options);

        const result = Buffer.concat([k.read(), chunk]);

        const expected = new Buffer(
            "\x46\x00\x00\x00\x43\x00\x00\x00\x0c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xff\x74\x10\xbb\xab\x1b\x56\xdf\x2c\xf6\xf6\x1f\x93\x38\xfa" +
            "\xf1\xc5\xef\xd6\x92\x3a\x25\x0a\x0d\x08\x00\x18\xbb\x97\x83\x96" +
            "\x91\x2a\x20\x01\x38\x04\x12\x14\x0a\x12\x12\x01\x33\x40\x00\x1a" +
            "\x06\x73\x74\x72\x69\x6e\x67\x22\x01\x32\x48\x01\x48\x49\x20\x45" +
            "\x56\x45\x52\x59\x42\x4f\x44\x59", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid PUT_RESPONSE', (done) => {
        const result = new kinetic.PutResponsePDU(1, 1, new Buffer(0)).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x2e\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x5f\xe8\x1f\xf4\xa6\xb1\xbd\x33\x3d\xc2\x00\xcc\xb0\xeb\xae" +
            "\x1d\x3f\xff\xc9\x02\x3a\x10\x0a\x04\x30\x01\x38\x03\x12\x02\x0a" +
            "\x00\x1a\x04\x08\x01\x1a\x00", "ascii");

        assert(result.equals(expected));

        done();
    });

    it('should write valid GET(options missing)', (done) => {
        const result = new kinetic.GetPDU(0, new Buffer('qwer')).read();
        const expected = new Buffer(
            "\x46\x00\x00\x00\x37\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x71\x45\xcf\xea\xa2\x7c\x91\xc9\x90\xfb\x3e\x09\xa1\xe0\x92" +
            "\xd4\x5a\xb6\x17\xfd\x3a\x19\x0a\x0d\x08\x00\x18\x95\xd3\xeb\xc2" +
            "\x8d\x2a\x20\x00\x38\x02\x12\x08\x0a\x06\x1a\x04\x71\x77\x65\x72",
            "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid GET (metadataOnly: false)', (done) => {
        const options = {
            metadataOnly: false,
        };
        const result = new kinetic.GetPDU(0, new Buffer('qwer'), options)
            .read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x39\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x87\x3a\xda\x04\xe1\x0b\x7d\x5e\x34\xd0\xc4\x3a\x89\x16\x0f" +
            "\x2c\xdf\xf0\x05\x52\x3a\x1b\x0a\x0d\x08\x00\x18\xfc\xc6\x98\x95" +
            "\x91\x2a\x20\x00\x38\x02\x12\x0a\x0a\x08\x1a\x04\x71\x77\x65\x72" +
            "\x38\x00", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid GET (metadataOnly : true)', (done) => {
        const options = {
            metadataOnly: true,
        };
        const result = new kinetic.GetPDU(0, new Buffer('qwer'), options)
            .read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x39\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x22\xcd\x40\xbb\x1d\xc8\xa6\x34\xb3\x75\x27\xaa\x43\x5f\x1c" +
            "\xd3\xbc\x88\xb3\x0c\x3a\x1b\x0a\x0d\x08\x00\x18\x8f\xf0\x9f\x95" +
            "\x91\x2a\x20\x00\x38\x02\x12\x0a\x0a\x08\x1a\x04\x71\x77\x65\x72" +
            "\x38\x01", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid GET_RESPONSE', (done) => {
        const chunk = new Buffer("HI EVERYBODY");
        const pdu = new kinetic.GetResponsePDU(
                1, 1, new Buffer(0), new Buffer('qwer'), chunk.length,
                new Buffer('1'));

        const result = Buffer.concat([pdu.read(), chunk]);

        const expected = new Buffer(
            "\x46\x00\x00\x00\x37\x00\x00\x00\x0c\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xb2\x95\x7f\x58\x5e\x25\x0f\xda\x99\x0e\x84\x2f\xaa\x18\xf3" +
            "\x9c\x74\x7b\x7b\x40\x3a\x19\x0a\x04\x30\x01\x38\x01\x12\x0b\x0a" +
            "\x09\x1a\x04\x71\x77\x65\x72\x22\x01\x31\x1a\x04\x08\x01\x1a\x00" +
            "\x48\x49\x20\x45\x56\x45\x52\x59\x42\x4f\x44\x59", "ascii");

        assert(result.equals(expected));

        done();
    });

    it('should write valid DELETE (options missing)', (done) => {
        const options = {
            dbVersion: new Buffer('1234'),
        };

        const result = new kinetic.DeletePDU(0, 'string', options).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x41\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x80\xd0\x16\xe1\x33\x2f\x52\xc3\xce\x47\x23\x50\xea\xd7\xb7" +
            "\x7d\x68\x02\xe5\xbe\x3a\x23\x0a\x0d\x08\x00\x18\xd8\xeb\xa1\x96" +
            "\x91\x2a\x20\x00\x38\x06\x12\x12\x0a\x10\x1a\x06\x73\x74\x72\x69" +
            "\x6e\x67\x22\x04\x31\x32\x33\x34\x48\x01", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid DELETE (force: true)', (done) => {
        const options = {
            dbVersion: new Buffer('1234'),
            force: true,
        };

        const result = new kinetic.DeletePDU(0, 'string', options).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x43\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xb4\x0a\x35\xbe\x7c\x79\xcc\x26\x82\xe5\x7c\x7a\x7f\x2e\x13" +
            "\x6d\xfb\xea\x51\x68\x3a\x25\x0a\x0d\x08\x00\x18\xcb\xb0\xaa\x96" +
            "\x91\x2a\x20\x00\x38\x06\x12\x14\x0a\x12\x40\x01\x1a\x06\x73\x74" +
            "\x72\x69\x6e\x67\x22\x04\x31\x32\x33\x34\x48\x01", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid DELETE (force: false)', (done) => {
        const options = {
            dbVersion: new Buffer('1234'),
            force: false,
        };

        const result = new kinetic.DeletePDU(0, 'string', options).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x43\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x2b\x4d\xbf\xd5\xe1\x7d\xd6\xa3\xff\x62\xc0\xae\x71\xa6\x79" +
            "\x95\xd6\xd6\x80\x52\x3a\x25\x0a\x0d\x08\x00\x18\x86\xf4\xae\x96" +
            "\x91\x2a\x20\x00\x38\x06\x12\x14\x0a\x12\x40\x00\x1a\x06\x73\x74" +
            "\x72\x69\x6e\x67\x22\x04\x31\x32\x33\x34\x48\x01", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid DELETE_RESPONSE', (done) => {
        const result = new kinetic.DeleteResponsePDU(1, 1, new Buffer(0))
            .read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x2e\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xd2\x5e\x45\xf0\x20\xe3\xe4\xbf\xc2\xc1\x52\xe7\x67\xd0\xdf" +
            "\x65\x1b\x8e\x98\x9e\x3a\x10\x0a\x04\x30\x01\x38\x05\x12\x02\x0a" +
            "\x00\x1a\x04\x08\x01\x1a\x00", "ascii");

        assert(result.equals(expected));

        done();
    });

    it('should write valid FLUSH', (done) => {
        const result = new kinetic.FlushPDU(0).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x2f\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x1b\xb1\x4c\x9d\x7c\x95\xe6\xbc\x7b\xb0\x0f\x65\x1d\x5e\x24" +
            "\xaa\x6a\xb5\xf0\x0a\x3a\x11\x0a\x0d\x08\x00\x18\xa8\x99\xee\xc3" +
            "\x8d\x2a\x20\x00\x38\x20\x12\x00", "ascii");


        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid FLUSH_RESPONSE', (done) => {
        const result = new kinetic.FlushResponsePDU(1, 1, new Buffer(0)).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x2a\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x11\x71\xfb\xeb\x34\x02\x4d\x6e\x22\xe7\xed\xd8\x1d\xab\x1d" +
            "\x87\xfe\x3b\x96\xb5\x3a\x0c\x0a\x04\x30\x01\x38\x1f\x1a\x04\x08" +
            "\x01\x1a\x00", "ascii");

        assert(result.equals(expected));

        done();
    });


    it('should write valid GETLOG', (done) => {
        const result = new kinetic.GetLogPDU(0).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x3d\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\xa6\x25\x09\x88\xca\x6f\xbf\x42\x80\xc7\x87\x77\x47\xc4\x78" +
            "\x97\x88\xd9\x2b\xd7\x3a\x1f\x0a\x0d\x08\x00\x18\xb1\xea\xa7\xc4" +
            "\x8d\x2a\x20\x00\x38\x18\x12\x0e\x32\x0c\x08\x00\x08\x01\x08\x02" +
            "\x08\x04\x08\x05\x08\x06", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid GETLOG_RESPONSE', (done) => {
        const logResponse = {
            types: [ 0, 1, 2, 4, 5, 6 ],
            utilizations:
                [ { name: 'HDA', value: 0.550000011920929 },
                    { name: 'EN0', value: 0.7900000214576721 },
                    { name: 'EN1', value: 0.8500000238418579 },
                    { name: 'CPU', value: 0.1599999964237213 } ],
            temperatures:
                [ { name: 'HDA', current: 51, minimum: 5, maximum: 100,
                    target: 25 },
                  { name: 'CPU', current: 40, minimum: 5, maximum: 100,
                    target: 25 } ],
            capacity:
            { nominalCapacityInBytes: -1114419200,
            portionFull: 0.05364461988210678 },
            configuration: null,
            statistics:
                [ { messageType: 4,
                    count: 1,
                    bytes: 141, },
                { messageType: 2,
                    count: 1,
                    bytes: 145, },
                { messageType: 6,
                    count: 1,
                    bytes: 111, },
                { messageType: 10,
                    count: 0,
                    bytes: 0, },
                { messageType: 8,
                    count: 0,
                    bytes: 0, },
                { messageType: 12,
                    count: 0,
                    bytes: 0, },
                { messageType: 16,
                    count: 0,
                    bytes: 0, },
                { messageType: 26,
                    count: 0,
                    bytes: 0, },
                { messageType: 22,
                    count: 0,
                    bytes: 0, },
                { messageType: 24,
                    count: 0,
                    bytes: 0, },
                { messageType: 28,
                    count: 0,
                    bytes: 0, } ],
            messages: new Buffer('Holla'),
            limits:
            { maxKeySize: 4096,
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
                maxBatchCountPerDevice: 5 },
            device: null
        };
        const result = new kinetic.GetLogResponsePDU(1,  1, new Buffer(0),
            logResponse).read();

        const expected = new Buffer(
            "\x46\x00\x00\x01\x4d\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x64\x67\x71\x29\xe3\x98\x7e\xf1\xd1\xc3\x3b\xfb\x65\x2b\x48" +
            "\xb4\x7c\x16\xf3\x10\x3a\xae\x02\x0a\x04\x30\x01\x38\x17\x12\x9f" +
            "\x02\x32\x9c\x02\x08\x00\x08\x01\x08\x02\x08\x04\x08\x05\x08\x06" +
            "\x12\x0a\x0a\x03\x48\x44\x41\x15\xcd\xcc\x0c\x3f\x12\x0a\x0a\x03" +
            "\x45\x4e\x30\x15\x71\x3d\x4a\x3f\x12\x0a\x0a\x03\x45\x4e\x31\x15" +
            "\x9a\x99\x59\x3f\x12\x0a\x0a\x03\x43\x50\x55\x15\x0a\xd7\x23\x3e" +
            "\x1a\x19\x0a\x03\x48\x44\x41\x15\x00\x00\x4c\x42\x1d\x00\x00\xa0" +
            "\x40\x25\x00\x00\xc8\x42\x2d\x00\x00\xc8\x41\x1a\x19\x0a\x03\x43" +
            "\x50\x55\x15\x00\x00\x20\x42\x1d\x00\x00\xa0\x40\x25\x00\x00\xc8" +
            "\x42\x2d\x00\x00\xc8\x41\x22\x10\x20\x80\xa0\xcd\xec\xfb\xff\xff" +
            "\xff\xff\x01\x2d\x76\xba\x5b\x3d\x32\x07\x08\x04\x20\x01\x28\x8d" +
            "\x01\x32\x07\x08\x02\x20\x01\x28\x91\x01\x32\x06\x08\x06\x20\x01" +
            "\x28\x6f\x32\x06\x08\x0a\x20\x00\x28\x00\x32\x06\x08\x08\x20\x00" +
            "\x28\x00\x32\x06\x08\x0c\x20\x00\x28\x00\x32\x06\x08\x10\x20\x00" +
            "\x28\x00\x32\x06\x08\x1a\x20\x00\x28\x00\x32\x06\x08\x16\x20\x00" +
            "\x28\x00\x32\x06\x08\x18\x20\x00\x28\x00\x32\x06\x08\x1c\x20\x00" +
            "\x28\x00\x3a\x05\x48\x6f\x6c\x6c\x61\x42\x35\x08\x80\x20\x10\x80" +
            "\x80\x40\x18\x80\x10\x20\xff\xff\xff\xff\x0f\x28\xff\xff\xff\xff" +
            "\x0f\x30\xff\xff\xff\xff\x0f\x38\xff\xff\xff\xff\x0f\x40\xff\xff" +
            "\xff\xff\x0f\x48\xc8\x01\x50\xff\xff\xff\xff\x0f\x60\x0f\x68\x05" +
            "\x1a\x04\x08\x01\x1a\x00", "ascii");

        assert(result.equals(expected));

        done();
    });

    it('should write valid SetClusterVersion', (done) => {
        const result = new kinetic.SetClusterVersionPDU(1, 1234, 0).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x34\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x2c\xf2\x65\xde\x71\x74\x7c\x91\x23\x8a\xa8\xbd\x38\x6a\xab" +
            "\x40\x5d\x5e\x64\xd1\x3a\x16\x0a\x0d\x08\x00\x18\x98\xed\xdf\xd5" +
            "\x8f\x2a\x20\x01\x38\x16\x12\x05\x1a\x03\x08\xd2\x09", "ascii");

        // Ignore the timestamp bytes (17 -> 37 & 44 -> 48)
        assert(result.slice(0, 17).equals(expected.slice(0, 17)));
        assert(result.slice(37, 44).equals(expected.slice(37, 44)));
        assert(result.slice(49).equals(expected.slice(49)));

        done();
    });

    it('should write valid SETUP_RESPONSE', (done) => {
        const result = new kinetic.SetupResponsePDU(1, 1, new Buffer(0)).read();

        const expected = new Buffer(
            "\x46\x00\x00\x00\x2a\x00\x00\x00\x00\x20\x01\x2a\x18\x08\x01\x12" +
            "\x14\x21\xd9\xc6\x5c\x25\x51\x7f\x8d\xd1\xcc\xb9\x40\x17\xb8\xab" +
            "\xed\x11\xcb\x63\xe5\x3a\x0c\x0a\x04\x30\x01\x38\x15\x1a\x04\x08" +
            "\x01\x1a\x00", "ascii");

        assert(result.equals(expected));

        done();
    });
});

describe('kinetic.PutPDU()', () => {
    it('should accept string key', (done) => {
        try {
            const k = new kinetic.PutPDU(1, "string", 12);
            k;
            done();
        } catch (e) {
            done(e);
        }
    });

    it('should not accept non-string non-buffer key', (done) => {
        try {
            const k = new kinetic.PutPDU(
                1, 1, 77777, 12, new Buffer('2'), new Buffer('3'));
            k;
            done(new Error("constructor accepted invalid key type"));
        } catch (e) {
            if (e.badArg)
                done();
            else
                done(e);
        }
    });

    it('should accept numeric dbVersion', (done) => {
        try {
            const k = new kinetic.PutPDU(1, "string", 12, { dbVersion: 345 });
            k;
            done();
        } catch (e) {
            done(e);
        }
    });

    it('should not accept badly-typed dbVersion', (done) => {
        try {
            const k = new kinetic.PutPDU(1, "string", 12,
                                         { dbVersion: { a: 1 },
                                           newVersion: new Buffer('3') });
            k;
            done(new Error("constructor accepted object-typed key"));
        } catch (e) {
            if (e.badArg)
                done();
            else
                done(e);
        }
    });

    it('should accept numeric newVersion', (done) => {
        try {
            const k = new kinetic.PutPDU(1, "string", 12, { newVersion: 346 });
            k;
            done();
        } catch (e) {
            done(e);
        }
    });

    it('should not accept non-buffer newVersion', (done) => {
        try {
            const k = new kinetic.PutPDU(1, 'string', 12,
                                         { dbVersion: new Buffer('2'),
                                           newVersion: { s: 'abc' } });
            k;
            done(new Error("constructor accepted string-typed key"));
        } catch (e) {
            if (e.badArg)
                done();
            else
                done(e);
        }
    });

    it('should set sequence', (done) => {
        try {
            const k = new kinetic.PutPDU(345, "sequence", 12);
            assert.strictEqual(k.getSequence(), 345);
            done();
        } catch (e) {
            done(e);
        }
    });
});

describe('kinetic.GetPDU()', () => {
    it('should accept string key', (done) => {
        try {
            const k = new kinetic.GetPDU(1, "string");
            k;
            done();
        } catch (e) {
            done(e);
        }
    });

    it('should not accept non-string non-buffer key', (done) => {
        try {
            const k = new kinetic.GetPDU(1, 2);
            k;
            done(new Error("constructor accepted string-typed key"));
        } catch (e) {
            if (e.badArg)
                done();
            else
                done(e);
        }
    });

    it('should set sequence', (done) => {
        try {
            const k = new kinetic.GetPDU(987, "sequence");
            assert.strictEqual(k.getSequence(), 987);
            done();
        } catch (e) {
            done(e);
        }
    });
});

describe('kinetic.DeletePDU()', () => {
    it('should accept string key', (done) => {
        try {
            const k = new kinetic.DeletePDU(1, "string");
            k;
            done();
        } catch (e) {
            done(e);
        }
    });

    it('should not accept non-string non-buffer key', (done) => {
        try {
            const k = new kinetic.DeletePDU(1, 777777);
            k;
            done(new Error("constructor accepted string-typed key"));
        } catch (e) {
            if (e.badArg)
                done();
            else
                done(e);
        }
    });

    it('should accept numeric dbVersion', (done) => {
        try {
            const k = new kinetic.DeletePDU(1, "string", { dbVersion: 345 });
            k;
            done();
        } catch (e) {
            done(e);
        }
    });

    it('should not accept badly-typed dbVersion', (done) => {
        try {
            const k = new kinetic.DeletePDU(1, "string",
                                            { dbVersion: { a: 1 } });
            k;
            done(new Error("constructor accepted object-typed key"));
        } catch (e) {
            if (e.badArg)
                done();
            else
                done(e);
        }
    });
});

describe('kinetic LONG number getters ', () => {
    it('should decode Long sequence to number max:922337203685477600',
        (done) => {
            const rawData = new kinetic.NoOpPDU(9223372036854776001).read();
            const k = new kinetic.PDU(rawData);

            assert.strictEqual(k.getSequence(), 9223372036854776000);

            done();
        });

    it('should decode LONG ackSequence to number max:9223372036854776000',
        (done) => {
            const rawData = new kinetic.NoOpResponsePDU(9223372036854776000, 1,
                new Buffer(0)).read();
            const k = new kinetic.PDU(rawData);

            assert.strictEqual(k.getSequence(), 9223372036854776000);

            done();
        });

    it('should decode LONG clusterVersion to number max:9223372036854776000',
        (done) => {
            const rawData = new kinetic.NoOpPDU(1,
                {clusterVersion: 9223372036854776000}).read();
            const k = new kinetic.PDU(rawData);

            assert.strictEqual(k.getClusterVersion(), 9223372036854776000);

            done();
        });
});
