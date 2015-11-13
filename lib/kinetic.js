import crypto from 'crypto';
import stream from 'stream';

import protobuf from 'protobufjs';

const VERSION = 0x46;
const PROTOFILEPATH = __dirname + '/kinetic.proto';
const PROTOBUILDCLASS = 'com.seagate.kinetic.proto';

const HEADER_SZ = 9;
const HEADER_VERSION_OFFSET = 0;
const HEADER_PBUFSZ_OFFSET = 1;
const HEADER_CHUNKSZ_OFFSET = 5;

/**
 * Gets the actual version of the kinetic protocol.
 * @returns {number} - the current version of the kinetic
 * protocol.
 */
export function getVersion() {
    return VERSION;
}

export const logs = {
    UTILIZATIONS: 0,
    TEMPERATURES: 1,
    CAPACITIES: 2,
    CONFIGURATION: 3,
    STATISTICS: 4,
    MESSAGES: 5,
    LIMITS: 6,
    DEVICE: 7,
};

export const ops = {
    PUT: 4,
    PUT_RESPONSE: 3,
    GET: 2,
    GET_RESPONSE: 1,
    NOOP: 30,
    NOOP_RESPONSE: 29,
    DELETE: 6,
    DELETE_RESPONSE: 5,
    SET_CLUSTER_VERSION: 22,
    SETUP_RESPONSE: 21,
    FLUSH: 32,
    FLUSH_RESPONSE: 31,
    GETLOG: 24,
    GETLOG_RESPONSE: 23,
};

export const errors = {
    INVALID_STATUS_CODE: -1,
    NOT_ATTEMPTED: 0,
    SUCCESS: 1,
    HMAC_FAILURE: 2,
    NOT_AUTHORIZED: 3,
    VERSION_FAILURE: 4,
    INTERNAL_ERROR: 5,
    HEADER_REQUIRED: 6,
    NOT_FOUND: 7,
    VERSION_MISMATCH: 8,
    SERVICE_BUSY: 9,
    EXPIRED: 10,
    DATA_ERROR: 11,
    PERM_DATA_ERROR: 12,
    REMOTE_CONNECTION_ERROR: 13,
    NO_SPACE: 14,
    NO_SUCH_HMAC_ALGORITHM: 15,
    INVALID_REQUEST: 16,
    NESTED_OPERATION_ERRORS: 17,
    DEVICE_LOCKED: 18,
    DEVICE_ALREADY_UNLOCKED: 19,
    CONNECTION_TERMINATED: 20,
    INVALID_BATCH: 21,
};

/**
 * Like Error, but with a property set to true.
 *
 * Example: instead of:
 *     const err = new Error("input is not a buffer");
 *     err.badTypeInput = true;
 *     throw err;
 * use:
 *     throw propError("badTypeInput", "input is not a buffer");
 *
 * @param {String} propName - the property name.
 * @param {String} message - the Error message.
 * @returns {Error} the Error object.
 */
function propError(propName, message) {
    const err = new Error(message);
    err[propName] = true;
    return err;
}

/**
 * Gets the key of an object with its value.
 * @param {Object} object - the corresponding object.
 * @param {String} value - the corresponding value.
 * @returns {Buffer} - object key.
 */
function getKeyByValue(object, value) {
    return Object.keys(object).find(key => object[key] === value);
}

/**
 * Gets the operation name with its code.
 * @param {number} opCode - the operation code.
 * @returns {String} - operation name.
 */
export function getOpName(opCode) {
    return getKeyByValue(ops, opCode);
}

/**
 * Gets the error name with its code.
 * @param {number} errorCode - the error code.
 * @returns {String} - error name.
 */
export function getErrorName(errorCode) {
    return getKeyByValue(errors, errorCode);
}

/**
 * Gets the log type name with its code.
 * @param {number} logCode - the log type code.
 * @returns {String} - log type name.
 */
export function getLogType(logCode) {
    return getKeyByValue(logs, logCode);
}

export const protoBuild = protobuf.loadProtoFile(PROTOFILEPATH)
    .build(PROTOBUILDCLASS);

/**
 * Represents the Kinetic Protocol Data Structure.
 */
export class PDU extends stream.Readable {
    /**
     * @constructor
     * @param {Buffer} input - An optional input buffer to parse the Kinetic
     *                         message from
     * @throws {Error} - err.badVersion is set the version is incompatible,
     *                 - err.badLength is set if the buffer size is incoherent,
     *                 - err.decodingError is the protobuf is not decodable,
     *                 - err.hmacFail is set if the HMAC does not match,
     *                 - err.badTypeInput is set if the input is not a Buffer.
     * @returns {Kinetic} - to allow for a functional style.
     */
    constructor(input) {
        super();

        /*
         * From Kinetic official documentation, a Kinetic Protocol Data Unit
         * (PDU) is composed of:
         * - message -- a Protocol Buffer (protobuf) message, containing
         *              operation metadata & key-value metadata,
         * - chunk   -- the value to store/read.
         */
        this._message = undefined;
        this._chunk = undefined;

        if (input !== undefined) {
            if (!Buffer.isBuffer(input))
                throw new PropError("badTypeInput", "input is not a buffer");
            this._parse(input);
        }
        return this;
    }

    /**
     * Sets the actual protobuf message for the Kinetic Protocol Data Unit.
     * @param {Object} pbMessage - the well formated kinetic protobuf structure.
     * @returns {Kinetic} - to allow for a functional style.
     */
    setProtobuf(pbMessage) {
        this._message = pbMessage;
        return this;
    }

    setMessage(command) {
        this._message = new protoBuild.Command(command);
        this.computeHMAC();
        return this.setProtobuf(new protoBuild.Message({
            "authType": 1,
            "hmacAuth": {
                "identity": 1,
                "hmac": this.getHMAC(),
            },
            "commandBytes": this._message.toBuffer(),
        }));
    }

    /**
     * Slice the buffer with the offset and the limit.
     * @param {Object} obj - an object buffer with offset and limit.
     * @returns {Buffer} - sliced buffer from the buffer structure with the
     * offset and the limit.
     */
    getSlice(obj) {
        return obj.buffer.slice(obj.offset, obj.limit);
    }

    /**
     * Gets the actual protobuf message.
     * @returns {Object} - Kinetic protobuf message.
     */
    getProtobuf() {
        return this._message;
    }

    /**
     * Gets the actual protobuf message size.
     * @returns {number} - Size of the kinetic protobuf message.
     */
    getProtobufSize() {
        return this._message.calculate();
    }

    /**
     * Sets the chunk for the Kinetic Protocol Data Unit.
     * @param {Buffer} chunk - the data .
     * @returns {Kinetic} - to allow for a functional style.
     */
    setChunk(chunk) {
        this._chunk = chunk;
        return this;
    }

    /**
     * Gets the actual chunk.
     * @returns {Buffer} - Chunk.
     */
    getChunk() {
        return this._chunk;
    }

    /**
     * Gets the actual chunk size.
     * @returns {number} - Chunk size.
     */
    getChunkSize() {
        if (this._chunk === undefined)
            return 0;
        return this._chunk.length;
    }

    /**
     * Sets the HMAC for the Kinetic Protocol Data Unit integrity.
     * @returns {Kinetic} - to allow for a functional style.
     */
    computeHMAC() {
        const buf = new Buffer(4);
        buf.writeInt32BE(this.getProtobufSize());
        this._hmac = crypto.createHmac('sha1', 'asdfasdf');
        this._hmac.update(buf);
        this._hmac.update(this._message.toBuffer());
        this._hmac = this._hmac.digest();
        return this;
    }

    /**
     * Gets the actual HMAC.
     * @returns {Buffer} - HMAC.
     */
    getHMAC() {
        return this._hmac;
    }

    /**
     * Gets the actual request messageType.
     * @returns {number} - The code number of the request.
     */
    getMessageType() {
        return this._message.header.messageType;
    }

    /**
     * Gets sequence (monotonically increasing number for each request in a TCP
     * connection) or ackSequence in case of a response message.
     * @returns {number} - The sequence number.
     */
    getSequence() {
        if (this._message.header.sequence !== null)
            return this._message.header.sequence.toNumber();
        else if (this._message.header.ackSequence !== null)
            return this._message.header.ackSequence.toNumber();
    }

    /**
     * Gets the actual clusterVersion.
     * @returns {number} - The clusterVersion.
     */
    getClusterVersion() {
        return this._message.header.clusterVersion.toNumber();
    }

    /**
     * Gets the actual key.
     * @returns {Buffer} - Key.
     */
    getKey() {
        return this.getSlice(this._message.body.keyValue.key);
    }

    /**
     * Gets the version of the data unit in the database.
     * @returns {Buffer} - Version of the data unit in the database.
     */
    getDbVersion() {
        return this.getSlice(this._message.body.keyValue.dbVersion);
    }

    /**
     * Gets the new version of the data unit.
     * @returns {Buffer} - New version of the data unit.
     */
    getNewVersion() {
        return this.getSlice(this._message.body.keyValue.newVersion);
    }

    /**
     * Gets the detailed error message.
     * @returns {Buffer} - Detailed error message.
     */
    getErrorMessage() {
        return this.getSlice(this._message.status.detailedMessage);
    }

    /**
     * Gets the logs message.
     * @returns {Buffer} - Logs message.
     */
    getGetLogMessage() {
        return this.getSlice(this._message.body.getLog.messages);
    }

    /**
     * Test the HMAC integrity between the actual instance and the given HMAC
     * @param {Buffer} hmac - the non instance hmac to compare
     * @returns {Boolean} - whether HMAC matches or not
     */
    checkHmacIntegrity(hmac) {
        this.computeHMAC();

        return this.getHMAC().equals(hmac);
    }

    /*
     * Internal implementation of the `stream.Readable` class.
     */
    _read() {
        const header = new Buffer(HEADER_SZ);
        header.writeInt8(getVersion(), HEADER_VERSION_OFFSET);
        header.writeInt32BE(this.getProtobufSize(), HEADER_PBUFSZ_OFFSET);
        header.writeInt32BE(this.getChunkSize(), HEADER_CHUNKSZ_OFFSET);
        this.push(header);

        this.push(this._message.toBuffer());

        if (this.getChunk() !== undefined)
            this.push(this.getChunk());

        this.push(null);
    }

    /**
     * Creates the Kinetic Protocol Data Structure from a buffer.
     * @param {Buffer} data - The data received by the socket.
     * @throws {Error} - err.badVersion is set the version is incompatible,
     *                 - err.badLength is set if the buffer size is incoherent,
     *                 - err.decodingError is the protobuf is not decodable,
     *                 - err.hmacFail is set if the HMAC does not match.
     * @returns {number} - an error code
     */
    _parse(data) {
        if (data.length < HEADER_SZ)
            throw new PropError("badLength", "PDU message is truncated");

        const version = data.readInt8(HEADER_VERSION_OFFSET);
        const pbMsgLen = data.readInt32BE(HEADER_PBUFSZ_OFFSET);
        const chunkLen = data.readInt32BE(HEADER_CHUNKSZ_OFFSET);

        if (version !== getVersion())
            throw new PropError("badVersion", "version failure");
        else if (data.length !== HEADER_SZ + pbMsgLen + chunkLen)
            throw new PropError("badLength",
                                "PDU message is truncated or too long");

        try {
            const protobuf = data.slice(HEADER_SZ, HEADER_SZ + pbMsgLen);
            this._cmd = protoBuild.Message.decode(protobuf);
            this.setProtobuf(protoBuild.Command.decode(this._cmd.commandBytes));
        } catch (e) {
            if (e.decoded) {
                this.setProtobuf(e.decoded);
            } else {
                throw new PropError("decodingError",
                                    "cannot decode protobuf message: " + e);
            }
        }
        this.setChunk(data.slice(pbMsgLen + HEADER_SZ, chunkLen + pbMsgLen + HEADER_SZ));

        if (this._cmd.authType === 1 && !this.checkHmacIntegrity(
                    this.getSlice(this._cmd.hmacAuth.hmac)))
            throw new PropError("hmacFail", "HMAC does not match");
    }
}

/**
 * Reads from a stream (e.g. a socket) to decode a PDU asynchronously.
 *
 * Once enough data to decode a message has been received, a PDU is built and
 * the callback function is called. If extra bytes are received (the beggining
 * of the chunk payload), they are put back into the stream so another reader
 * can fetch and process them.
 *
 * @param {stream} s - The stream to read from.
 * @param {function} callback - The callback function (err, pdu) => { ... }.
 * @throws {Error} Only when callback is omitted. Otherwise, callback will be
 *                 called with the Error as first argument.
 * @returns {undefined} undefined
 */
export function streamToPDU(s, callback) {
    let recvBuffer = new Buffer(0);
    let pdu = null;

    function handleError(err) {
        recvBuffer = null;  // abort
        if (typeof callback === 'function')
            callback(err);
        else
            throw err;
    }

    s.on("error", handleError);

    s.on("readable", () => {
        if (pdu !== null)
            return;

        const data = s.read();
        if (data === null)
            return;

        recvBuffer = Buffer.concat([recvBuffer, data]);

        if (recvBuffer.length < HEADER_SZ)
            return;  // need to wait for more data

        const protobufSize = recvBuffer.readInt32BE(1);
        if (recvBuffer.length < HEADER_SZ + protobufSize)
            return;  // need to wait for more data

        if (pdu === null) {
            pdu = new PDU(recvBuffer);

            // In case we read to much (and starting reading the chunk payload),
            // unshift the buffer to put bytes ready to be read again.
            if (recvBuffer.length > HEADER_SZ + protobufSize)
                s.unshift(recvBuffer.slice(HEADER_SZ + protobufSize));

            if (typeof callback === 'function')
                callback(null, pdu);
        }
    });

    s.on("end", () => {
        if (pdu === null)
            handleError(new PropError("badLength",
                                      "PDU message is truncated."));
    });
}

/**
 * Getting logs and stats request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection.
 * @param {number} clusterVersion - version of the cluster
 * @param {Array} types - array filled by logs types needed.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetLogPDU extends PDU {
    constructor(sequence, clusterVersion, types) {
        super();
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "GETLOG",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": clusterVersion,
            },
            "body": {
                "getLog": {
                    "types": types,
                },
            },
        });
        return this;
    }
}

/**
 * Getting logs and stats response following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - detailed error message.
 * @param {object} responseLogs - object filled by logs needed.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetLogResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage, responseLogs) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        this.setMessage({
            "header": {
                "ackSequence": ackSequence,
                "messageType": "GETLOG_RESPONSE",
            },
            "body": {
                "getLog": responseLogs,
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}

/**
 * Flush all data request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection.
 * @param {number} clusterVersion - version of the cluster
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class FlushPDU extends PDU {
    constructor(sequence, clusterVersion) {
        super();
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "FLUSHALLDATA",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": clusterVersion,
            },
            "body": {
            },
        });
        return this;
    }
}

/**
 * Flush all data response following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class FlushResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        this.setMessage({
            "header": {
                "messageType": "FLUSHALLDATA_RESPONSE",
                "ackSequence": ackSequence,
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}

/**
 * set clusterVersion request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection.
 * @param {number} clusterVersion - The version number of this cluster
 *                                  definition
 * @param {number} oldClusterVersion - The old version number of this cluster
 *                                     definition
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class SetClusterVersionPDU extends PDU {
    constructor(sequence, clusterVersion, oldClusterVersion) {
        super();
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "SETUP",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": oldClusterVersion,
            },
            "body": {
                "setup": {
                    "newClusterVersion": clusterVersion,
                },
            },
        });
        return this;
    }
}

/**
 * Setup response request following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class SetupResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        this.setMessage({
            "header": {
                "messageType": "SETUP_RESPONSE",
                "ackSequence": ackSequence,
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}

/**
 * NOOP request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection
 * @param {number} clusterVersion - The version number of this cluster
 *                                  definition
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class NoOpPDU extends PDU {
    constructor(sequence, clusterVersion) {
        super();
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "NOOP",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": clusterVersion,
            },
            "body": {
            },
        });
        return this;
    }
}

/**
 * Response for the NOOP request following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class NoOpResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        this.setMessage({
            "header": {
                "messageType": "NOOP_RESPONSE",
                "ackSequence": ackSequence,
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}

/**
 * PUT request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection
 * @param {number} clusterVersion - The version number of this cluster
 *                                  definition
 * @param {Buffer} key - key of the item to put.
 * @param {Buffer} dbVersion - version of the item in the database.
 * @param {Buffer} newVersion - new version of the item to put.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class PutPDU extends PDU {
    constructor(sequence, clusterVersion, key, dbVersion, newVersion) {
        super();
        if (!Buffer.isBuffer(key))
            throw new Error("key is not a buffer");
        if (!Buffer.isBuffer(dbVersion))
            throw new Error("old dbversion is not a buffer");
        if (!Buffer.isBuffer(newVersion))
            throw new Error("new dbversion is not a buffer");
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "PUT",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": clusterVersion,
            },
            "body": {
                "keyValue": {
                    "key": key,
                    "newVersion": newVersion,
                    "dbVersion": dbVersion,
                    "synchronization": 'WRITETHROUGH',
                },
            },
        });
        return this;
    }
}

/**
 * Response for the PUT request following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class PutResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        this.setMessage({
            "header": {
                "messageType": "PUT_RESPONSE",
                "ackSequence": ackSequence,
            },
            "body": {
                "keyValue": { },
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}

/**
 * GET request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection
 * @param {number} clusterVersion - The version number of this cluster
 *                                  definition
 * @param {Buffer} key - key of the item to get.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetPDU extends PDU {
    constructor(sequence, clusterVersion, key) {
        super();
        if (!Buffer.isBuffer(key))
            throw new Error("key is not a buffer");
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "GET",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": clusterVersion,
            },
            "body": {
                "keyValue": {
                    "key": key,
                },
            },
        });
        return this;
    }
}

/**
 * Response for the GET request following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - Detailed error message.
 * @param {Buffer} key - key of the item to gotten item.
 * @param {Buffer} dbVersion - The version of the item in the database.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage, key, dbVersion) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        if (!Buffer.isBuffer(dbVersion))
            throw new Error("dbVersion is not a buffer");

        this.setMessage({
            "header": {
                "messageType": "GET_RESPONSE",
                "ackSequence": ackSequence,
            },
            "body": {
                "keyValue": {
                    "key": key,
                    "dbVersion": dbVersion,
                },
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}

/**
 * DELETE request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection
 * @param {number} clusterVersion - The version number of this cluster
 *                                  definition
 * @param {Buffer} key - key of the item to delete.
 * @param {Buffer} dbVersion - version of the item in the database.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class DeletePDU extends PDU {
    constructor(sequence, clusterVersion, key, dbVersion) {
        super();
        if (!Buffer.isBuffer(key))
            throw new Error("key is not a buffer");
        if (!Buffer.isBuffer(dbVersion))
            throw new Error("dbVersion is not a buffer");
        const connectionID = (new Date).getTime();
        this.setMessage({
            "header": {
                "messageType": "DELETE",
                "connectionID": connectionID,
                "sequence": sequence,
                "clusterVersion": clusterVersion,
            },
            "body": {
                "keyValue": {
                    "key": key,
                    "dbVersion": dbVersion,
                    "synchronization": 'WRITETHROUGH',
                },
            },
        });
        return this;
    }
}

/**
 * Response for the DELETE request following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} response - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessage - Detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class DeleteResponsePDU extends PDU {
    constructor(ackSequence, response, errorMessage) {
        super();
        if (!Buffer.isBuffer(errorMessage))
            throw new Error("the error message is not a buffer");
        this.setMessage({
            "header": {
                "messageType": "DELETE_RESPONSE",
                "ackSequence": ackSequence,
            },
            "body": {
                "keyValue": { },
            },
            "status": {
                "code": response,
                "detailedMessage": errorMessage,
            },
        });
        return this;
    }
}
