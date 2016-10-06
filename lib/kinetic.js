import crypto from 'crypto';
import stream from 'stream';

import posixRead from 'posix-read';
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
         * - header   -- A 9-byte-long header.
         * - protobuf -- A Protocol Buffer message, containing operation
         *               metadata & key-value metadata.
         * - chunk    -- The value to store/read. For performance reasons, the
         *               chunk is not copied into the PDU object; the client is
         *               responsible for reading or writing it.
         */
        this._command = undefined;  // the object-typed command that gets
                                    // converted into the protobuf (made of
                                    // bytes)
        this._chunkSize = 0;


        if (input !== undefined) {
            if (!Buffer.isBuffer(input))
                throw propError("badTypeInput", "input is not a buffer");
            this._parse(input);
        }
        return this;
    }

    _buildProtobuf() {
        this.computeHMAC();

        if (this._authType !== undefined) {
            this._protobuf = new protoBuild.Message({
                authType: this._authType,
                commandBytes: this._command.toBuffer(),
            });
        } else {
            this._protobuf = new protoBuild.Message({
                authType: 1,
                hmacAuth: {
                    identity: 1,
                    hmac: this.getHMAC(),
                },
                commandBytes: this._command.toBuffer(),
            });
        }

        return this;
    }

    /**
     * Sets the protobuf command for the Kinetic Protocol Data Unit.
     *
     * @param {Object} command - the well formated kinetic protobuf structure.
     * @returns {Kinetic} - this
     */
    setCommand(command) {
        this._command = new protoBuild.Command(command);
    }

    /**
     * Gets the protobuf command.
     *
     * @returns {Object} - the object-typed command
     */
    getCommand() {
        return this._command;
    }

    /**
     * Gets the protobuf command size.
     *
     * @returns {number} - the size in bytes
     */
    getCommandSize() {
        return this._command.calculate();
    }

    /**
     * Get the actual Kinetic protobuf, encoded as a buffer ready to be sent
     * over the network.
     *
     * @returns {Buffer} - the encoded protobuf message
     */
    getProtobuf() {
        return this._protobuf;
    }

    /**
     * Gets the actual protobuf message size.
     * @returns {number} - Size of the kinetic protobuf message.
     */
    getProtobufSize() {
        return this._protobuf.calculate();
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
     * Sets the size of the chunk following the protobuf message in the PDU.
     * @param {number} size - Size of the chunk.
     * @returns {Kinetic} - To allow for a functional style.
     */
    setChunkSize(size) {
        this._chunkSize = size;
        return this;
    }

    /**
     * Gets the actual chunk size.
     * @returns {number} - Chunk size.
     */
    getChunkSize() {
        return this._chunkSize;
    }

    /**
     * Sets the HMAC for the Kinetic Protocol Data Unit integrity.
     * @returns {Kinetic} - to allow for a functional style.
     */
    computeHMAC() {
        const buf = Buffer.allocUnsafe(4);
        buf.writeInt32BE(this.getCommandSize());
        const hmac = crypto.createHmac("sha1", "asdfasdf");
        hmac.update(buf);
        hmac.update(this._command.toBuffer());
        this._hmac = hmac.digest();
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
        return this._command.header.messageType;
    }

    /**
     * Gets sequence (monotonically increasing number for each request in a TCP
     * connection) or ackSequence in case of a response message.
     * @returns {number} - The sequence number.
     */
    getSequence() {
        if (this._command.header.sequence !== null)
            return this._command.header.sequence.toNumber();
        else if (this._command.header.ackSequence !== null)
            return this._command.header.ackSequence.toNumber();
    }

    /**
     * Gets the status code for response messages.
     * @returns {number} - The status code.
     */
    getStatusCode() {
        return this._command.status.code;
    }

    /**
     * Gets the actual clusterVersion.
     *
     * @returns {number} - The clusterVersion, or 0 if missing.
     */
    getClusterVersion() {
        if (this._command.header.clusterVersion === null)
            return 0;

        return this._command.header.clusterVersion.toNumber();
    }

    /**
     * Gets the updated clusterVersion.
     * @returns {number} - The updated clusterVersion, or undefined if missing.
     */
    getNewClusterVersion() {
        if (this._command.body.setup.newClusterVersion === null)
            return undefined;

        return this._command.body.setup.newClusterVersion.toNumber();
    }

    /**
     * Gets the actual key.
     *
     * @returns {Buffer} - The key value, or `undefined` if missing.
     */
    getKey() {
        if (this._command.body.keyValue === null)
            return undefined;

        return this.getSlice(this._command.body.keyValue.key);
    }

    /**
     * Gets the version of the data unit in the database.
     *
     * @returns {Buffer} - Version of the data unit in the database, or
     *                     `undefined` if missing.
     */
    getDbVersion() {
        if (this._command.body.keyValue === null
                || this._command.body.keyValue.dbVersion === null)
            return undefined;

        return this.getSlice(this._command.body.keyValue.dbVersion);
    }

    /**
     * Gets the new version of the data unit.
     *
     * @returns {Buffer} - New version of the data unit, or `undefined` if
     *                     missing.
     */
    getNewVersion() {
        if (this._command.body.keyValue === null
                || this._command.body.keyValue.newVersion === null)
            return undefined;

        return this.getSlice(this._command.body.keyValue.newVersion);
    }

    /**
     * Gets the force value of the data unit.
     *
     * @returns {boolean} - Whether force is true or false. If missing, false is
     *                      assumed.
     */
    getForce() {
        return (this._command.body.keyValue !== null
                && this._command.body.keyValue.force === true);
    }

    /**
     * Gets the detailed error message.
     * @returns {Buffer} - Detailed error message.
     */
    getErrorMessage() {
        return this.getSlice(this._command.status.detailedMessage);
    }

    /**
     * Gets the logs object.
     *
     * @returns {Object} - Logs, or `undefined` if missing.
     */
    getLogObject() {
        if (this._command.body.getLog === null)
            return undefined;

        return this._command.body.getLog;
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
        this._buildProtobuf();

        const header = Buffer.allocUnsafe(HEADER_SZ);
        header.writeInt8(getVersion(), HEADER_VERSION_OFFSET);
        header.writeInt32BE(this.getProtobufSize(), HEADER_PBUFSZ_OFFSET);
        header.writeInt32BE(this.getChunkSize(), HEADER_CHUNKSZ_OFFSET);

        this.push(header);

        this.push(this.getProtobuf().toBuffer());

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
            throw propError("badLength", "PDU message is truncated");

        const version = data.readInt8(HEADER_VERSION_OFFSET);
        const protobufSize = data.readInt32BE(HEADER_PBUFSZ_OFFSET);
        this._chunkSize = data.readInt32BE(HEADER_CHUNKSZ_OFFSET);

        if (version !== getVersion())
            throw propError("badVersion", "version failure");
        else if (data.length < HEADER_SZ + protobufSize)
            throw propError("badLength", "PDU message is truncated");

        try {
            const buf = data.slice(HEADER_SZ, HEADER_SZ + protobufSize);
            this._protobuf = protoBuild.Message.decode(buf);
            this._command =
                protoBuild.Command.decode(this._protobuf.commandBytes);
        } catch (e) {
            if (e.decoded) {
                this._command = e.decoded;
            } else {
                throw propError("decodingError",
                                "cannot decode protobuf message: " + e);
            }
        }

        if (this._protobuf.authType === 1 && !this.checkHmacIntegrity(
                    this.getSlice(this._protobuf.hmacAuth.hmac)))
            throw propError("hmacFail", "HMAC does not match");
    }
}

/**
 * Reads from a stream (e.g. a socket) to decode a PDU asynchronously.
 *
 * Uses a POSIX read to read 9 + protobufSize bytes (exactly) from the socket.
 * Chunk bytes are not consumed from the socket. This is an asynchronous call,
 * so a callback must be provided.
 *
 * @param {net.Socket} socket - The socket to read from. This socket must be
 *                              paused, otherwise libuv will try to read from
 *                              it concurrently.
 * @param {function} callback - The callback function (err, pdu) => { ... }.
 * @throws {Error} If something bad happens. The Error object has one of these
 *                 properties set, to help handling the error:
 *                 - `err.badStream` if the socket is malformed or its file
 *                   descriptor is not available
 *                 - `err.endOfFile` if the end-of-file was reached before
 *                   having read all the bytes needed for decoding
 *                 - `err.systemError` in case of a system call error (in such
 *                   a case, `error.message` should contain more useful
 *                   information).
 * @returns {undefined}
 */
export function streamToPDU(socket, callback) {
    posixRead(socket, HEADER_SZ, (err, header) => {
        if (err)
            return callback(err);

        const protobufSize = header.readInt32BE(1);

        posixRead(socket, protobufSize, (err, protobuf) => {
            if (err)
                return callback(err);

            const pdu = new PDU(Buffer.concat([header, protobuf]));
            callback(null, pdu);
        });
    });
}

function validateVersionArgument(arg) {
    if (Buffer.isBuffer(arg)) {
        return arg;
    } else if (typeof arg === "number") {
        const buf = Buffer.allocUnsafe(4);
        buf.writeInt32BE(arg);
        return buf;
    }

    throw propError("badArg", "Version is neither a buffer nor a number");
}

function validateBufferOrStringArgument(arg) {
    if (Buffer.isBuffer(arg))
        return arg;
    else if (typeof arg === "string")
        return Buffer.from(arg, 'utf8');

    throw propError("badArg", "Argument is neither a buffer nor a string");
}

/**
 * Create the initial PDU with logs
 * @param {object} getLog - object filled by logs needed.
 * @param {Object} options - optional :
 *                  {number} [options.clusterVersion = 0] - the cluster version
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class InitPDU extends PDU {
    constructor(getLog, options = {}) {
        super();

        this._authType = 'UNSOLICITEDSTATUS';

        const connectionID = (new Date).getTime();

        this.setCommand({
            header: {
                connectionID,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
                getLog,
            },
            status: {
                code: 1,
            },
        });
        return this;
    }
}

/**
 * Getting logs and stats request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection.
 * @param {Object} options - optional :
 *                  {number} [options.clusterVersion = 0] - the cluster version
 *                  {number[]} [options.types = [0, 1, 2, 4, 5, 6]] - logs types
 *                  needed
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetLogPDU extends PDU {
    constructor(sequence, options = {}) {
        super();

        const connectionID = (new Date).getTime();

        this.setCommand({
            header: {
                messageType: "GETLOG",
                connectionID,
                sequence,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
                getLog: {
                    types: Array.isArray(options.types) ?
                        options.types : [0, 1, 2, 4, 5, 6],
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
 * @param {number} code - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessageArg - detailed error message.
 * @param {object} getLog - object filled by logs needed.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetLogResponsePDU extends PDU {
    constructor(ackSequence, code, errorMessageArg, getLog) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);

        this.setCommand({
            header: {
                ackSequence,
                messageType: "GETLOG_RESPONSE",
            },
            body: {
                getLog,
            },
            status: {
                code,
                detailedMessage,
            },
        });
        return this;
    }
}

/**
 * Flush all data request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection.
 * @param {Object} options - optional :
 *                  {number} [options.clusterVersion = 0] - the cluster version
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class FlushPDU extends PDU {
    constructor(sequence, options = {}) {
        super();

        const connectionID = (new Date).getTime();

        this.setCommand({
            header: {
                messageType: "FLUSHALLDATA",
                connectionID,
                sequence,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
            },
        });
        return this;
    }
}

/**
 * Flush all data response following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} code - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessageArg - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class FlushResponsePDU extends PDU {
    constructor(ackSequence, code, errorMessageArg) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);

        this.setCommand({
            header: {
                messageType: "FLUSHALLDATA_RESPONSE",
                ackSequence,
            },
            status: {
                code,
                detailedMessage,
            },
        });
        return this;
    }
}

/**
 * set clusterVersion request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection.
 * @param {number} newClusterVersion - The version number of this cluster
 *                                  definition
 * @param {number} clusterVersion - The old version number of this cluster
 *                                     definition
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class SetClusterVersionPDU extends PDU {
    constructor(sequence, newClusterVersion, clusterVersion) {
        super();

        const connectionID = (new Date).getTime();

        this.setCommand({
            header: {
                messageType: "SETUP",
                connectionID,
                sequence,
                clusterVersion,
            },
            body: {
                setup: {
                    newClusterVersion,
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
 * @param {number} code - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessageArg - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class SetupResponsePDU extends PDU {
    constructor(ackSequence, code, errorMessageArg) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);

        this.setCommand({
            header: {
                messageType: "SETUP_RESPONSE",
                ackSequence,
            },
            status: {
                code,
                detailedMessage,
            },
        });
        return this;
    }
}

/**
 * NOOP request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection
 * @param {Object} options - optional :
 *                  {number} [options.clusterVersion = 0] - the cluster version
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class NoOpPDU extends PDU {
    constructor(sequence, options = {}) {
        super();

        const connectionID = (new Date).getTime();

        this.setCommand({
            header: {
                messageType: "NOOP",
                connectionID,
                sequence,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
            },
        });
        return this;
    }
}

/**
 * Response for the NOOP request following the kinetic protocol.
 * @param {number} ackSequence - monotically increasing number for each request
 *                               in a TCP connection
 * @param {number} code - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessageArg - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class NoOpResponsePDU extends PDU {
    constructor(ackSequence, code, errorMessageArg) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);

        this.setCommand({
            header: {
                messageType: "NOOP_RESPONSE",
                ackSequence,
            },
            status: {
                code,
                detailedMessage,
            },
        });
        return this;
    }
}

/**
 * PUT request following the kinetic protocol.
 * @param {number} sequence - monotonically increasing number for each
 *                                request in a TCP connection
 * @param {Buffer} key - key of the item to put.
 * @param {number} chunkSize - size of the chunk to put.
 * @param {Buffer} dbVersion - version of the item in the database.
 * @param {Buffer} newVersion - new version of the item to put.
 * @param {Object} options - optional :
 *                  {String} [options.synchronization = WRITETHROUGH] - to
 *                  specify if the data must be written to disk immediately,
 *                  or can be written in the future.
 *                  {number} [options.clusterVersion = 0] - the cluster version
 *                  {boolean} [options.force = null] - optional setting force to
 *                  true ignores potential version mismatches and carries out
 *                  the operation.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class PutPDU extends PDU {
    constructor(sequence, keyArg, chunkSize, options = {}) {
        super();

        let dbVersion = null;
        let newVersion = null;

        const key = validateBufferOrStringArgument(keyArg);
        if (options.dbVersion)
            dbVersion = validateVersionArgument(options.dbVersion);
        if (options.newVersion)
            newVersion = validateVersionArgument(options.newVersion);

        const connectionID = (new Date).getTime();
        this._chunkSize = chunkSize;
        this.setCommand({
            header: {
                messageType: "PUT",
                connectionID,
                sequence,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
                keyValue: {
                    key,
                    newVersion,
                    dbVersion,
                    synchronization: options.synchronization ||
                        "WRITETHROUGH",
                    force: typeof options.force === "boolean" ?
                             options.force : null,
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
 * @param {number} code - response code (SUCCESS, FAIL)
 * @param {Buffer} errorMessageArg - detailed error message.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class PutResponsePDU extends PDU {
    constructor(ackSequence, code, errorMessageArg) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);

        this.setCommand({
            header: {
                messageType: "PUT_RESPONSE",
                ackSequence,
            },
            body: {
                keyValue: { },
            },
            status: {
                code,
                detailedMessage,
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
 * @param {Object} options - optional :
 *                  {Boolean} [options.metadataOnly = false] - If true, only
 *                  metadata (not the full value) will be returned,
 *                  If false, metadata and value will be returned.
 *                  {number} [options.clusterVersion = 0] - the cluster version
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetPDU extends PDU {
    constructor(sequence, keyArg, options = {}) {
        super();

        const key = validateBufferOrStringArgument(keyArg);
        const connectionID = (new Date).getTime();

        this.setCommand({
            header: {
                messageType: "GET",
                connectionID,
                sequence,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
                keyValue: {
                    key,
                    metadataOnly: typeof options.metadataOnly === "boolean" ?
                                    options.metadataOnly : null,
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
 * @param {Buffer} errorMessageArg - Detailed error message.
 * @param {Buffer} key - key of the item to gotten item.
 * @param {number} chunkSize - size of the got chunk.
 * @param {Buffer} dbVersion - The version of the item in the database.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class GetResponsePDU extends PDU {
    constructor(ackSequence, code, errorMessageArg, keyArg,
                chunkSize, dbVersionArg) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);
        const key = validateBufferOrStringArgument(keyArg);
        const dbVersion = validateVersionArgument(dbVersionArg);

        this._chunkSize = chunkSize;
        this.setCommand({
            header: {
                messageType: "GET_RESPONSE",
                ackSequence,
            },
            body: {
                keyValue: {
                    key,
                    dbVersion,
                },
            },
            status: {
                code,
                detailedMessage,
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
 * @param {Object} options - optional :
 *                  {String} [options.synchronization = 'WRITETHROUGH'] -
 *                  to specify if the data must be written to disk immediately,
 *                  or can be written in the future.
 *                  {number} [options.clusterVersion = 0] - the cluster version
 *                  {boolean} [options.force = null] - optional setting force to
 *                  true ignores potential version mismatches and carries out
 *                  the operation.
 * @returns {Kinetic} - message structure following the kinetic protocol
 */
export class DeletePDU extends PDU {
    constructor(sequence, keyArg, options = {}) {
        super();

        let dbVersion = null;

        const key = validateBufferOrStringArgument(keyArg);
        if (options.dbVersion)
            dbVersion = validateVersionArgument(options.dbVersion);

        const connectionID = (new Date).getTime();
        this.setCommand({
            header: {
                messageType: "DELETE",
                connectionID,
                sequence,
                clusterVersion: Number.isInteger(options.clusterVersion) ?
                    options.clusterVersion : 0,
            },
            body: {
                keyValue: {
                    key,
                    dbVersion,
                    synchronization: options.synchronization ||
                        "WRITETHROUGH",
                    force: typeof options.force === "boolean" ?
                             options.force : null,
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
    constructor(ackSequence, code, errorMessageArg) {
        super();

        const detailedMessage = validateBufferOrStringArgument(errorMessageArg);

        this.setCommand({
            header: {
                messageType: "DELETE_RESPONSE",
                ackSequence,
            },
            body: {
                keyValue: { },
            },
            status: {
                code,
                detailedMessage,
            },
        });
        return this;
    }
}
