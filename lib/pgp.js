'use strict';

import debug from 'debug';
import { EventEmitter } from 'node:events';
import * as openpgp from 'openpgp';

const DEBUG = debug('sylkrtc:PGP');

const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });

class PGP extends EventEmitter {
    constructor(options = {}, connection) {
        super();
        this._privateKey = options.privateKey || null;
        this._publicKey = options.publicKey || null;
        this._armoredPrivateKey = options.privateKey || null;
        this._armoredPublicKey = options.publicKey || null;
        this._cachedPublicKeys = new Map();
        this._connection = connection;

        if (this._privateKey) {
            (async () => {
                try {
                    let privateKey = await openpgp.readPrivateKey({ armoredKey: this._privateKey });
                    if (options.password) {
                        privateKey = await openpgp.decryptKey({ privateKey, passphrase: options.password });
                    }
                    this._privateKey = privateKey;
                } catch (error) {
                    DEBUG('Error initializing private key: %s', error);
                }
            })();
        }

        if (this._publicKey) {
            (async () => {
                try {
                    this._publicKey = await openpgp.readKey({ armoredKey: this._publicKey });
                } catch (error) {
                    DEBUG('Error initializing public key: %s', error);
                }
            })();
        }

        if (this._privateKey && this._publicKey) {
            DEBUG('PGP messaging loaded and enabled');
        }
    }

    addPublicPGPKeys(keys) {
        for (const [contact, key] of Object.entries(keys)) {
            this._cachedPublicKeys.set(contact, key);
            this.emit('publicKeyAdded', { contact, key });
        }
    }

    async generatePGPKeys() {
        DEBUG('Generating PGP key');
        return new Promise((resolve, reject) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = ({ data }) => {
                if (data.error) {
                    DEBUG("Can't generate key: %s", data.error);
                    reject(new Error(data.error));
                    return;
                }
                DEBUG('PGP key generated');
                const { publicKey, privateKey } = data.result;
                this._armoredPublicKey = publicKey;
                this._armoredPrivateKey = privateKey;

                Promise.all([
                    openpgp.readPrivateKey({ armoredKey: privateKey }).then(key => { this._privateKey = key; }),
                    openpgp.readKey({ armoredKey: publicKey }).then(key => { this._publicKey = key; })
                ]).then(() => resolve(data.result))
                  .catch(err => reject(err));
            };
            const action = 'generateKey';
            const inputData = { name: this._displayName, email: this._id };
            worker.postMessage({ action, inputData }, [channel.port2]);
        });
    }

    async exportKeys(password) {
        try {
            const message = `${this._armoredPrivateKey}`.trim();
            const pgpMessage = await openpgp.createMessage({ text: message });
            const encryptedMessage = await openpgp.encrypt({
                message: pgpMessage,
                passwords: [password],
                config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib }
            });
            const fullMessage = `${this._armoredPublicKey}\n${encryptedMessage}`;
            return { message: fullMessage, didEncrypt: true };
        } catch (error) {
            DEBUG('Error exporting keys: %s', error);
            return { message: '', didEncrypt: false };
        }
    }

    async decryptKeyImport(message, password) {
        try {
            const regexp = /(?<before>[^]*?)(?<pgpMessage>-----BEGIN PGP MESSAGE-----[^]*-----END PGP MESSAGE-----)(?<after>[^]*)/i;
            const match = regexp.exec(message.content);
            if (!match) throw new Error('No PGP message found');

            const { before, pgpMessage, after } = match.groups;
            const msg = await openpgp.readMessage({ armoredMessage: pgpMessage });
            const { data } = await openpgp.decrypt({ message: msg, passwords: [password] });
            const result = { ...message, _content: `${before}${data}${after}`, didDecrypt: true };
            return result;
        } catch (error) {
            DEBUG("Can't decrypt key: %s", error);
            return { ...message, didDecrypt: false };
        }
    }

    async encryptMessage(uri, message) {
        try {
            DEBUG("Attempt to encrypt message (%s)", message.id);
            const publicKey = await this._lookupPublicKey(uri);
            if (!publicKey) throw new Error("No public key found");

            const pgpMessage = await openpgp.createMessage({ text: message.content });
            const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
            const encryptedMessage = await openpgp.encrypt({
                message: pgpMessage,
                encryptionKeys: [this._publicKey, publicKeyObj]
            });
            DEBUG("Message encrypted (%s)", message.id);
            return { message: encryptedMessage, didEncrypt: true };
        } catch (error) {
            DEBUG("Message not encrypted (%s): %s", message.id, error);
            return { message: message.content, didEncrypt: false };
        }
    }

    async encryptFile(uri, file) {
        try {
            DEBUG("Attempt to encrypt file (%s)", file.name);
            const publicKey = await this._lookupPublicKey(uri);
            if (!publicKey) throw new Error("No public key found");

            const array = await file.arrayBuffer().then(buffer => new Uint8Array(buffer));
            const pgpMessage = await openpgp.createMessage({ binary: array, format: 'binary', filename: file.name });
            const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });
            const encryptedMessage = await openpgp.encrypt({
                message: pgpMessage,
                encryptionKeys: [this._publicKey, publicKeyObj]
            });
            DEBUG("File encrypted (%s)", file.name);
            return {
                file: new File([encryptedMessage], `${file.name}.asc`, { type: file.type, lastModified: file.lastModified }),
                didEncrypt: true
            };
        } catch (error) {
            DEBUG("File not encrypted (%s): %s", file.name, error);
            return { file, didEncrypt: false };
        }
    }

    async decryptFile(fileData, filename, filetype) {
        DEBUG("Attempt to decrypt file (%s)", filename);
        return new Promise((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = ({ data }) => {
                if (data.error) {
                    DEBUG("Can't decrypt file (%s) %s", filename, data.error);
                    resolve({ file: new File([fileData], filename, { type: filetype }), didDecrypt: false });
                    return;
                }
                DEBUG("File decrypted (%s)", filename);
                resolve({ file: new File([data.result], data.filename, { type: filetype }), didDecrypt: true });
            };
            const action = 'decrypt';
            const inputData = { privateKey: this._armoredPrivateKey, publicKey: this._publicKey, format: 'binary' };
            worker.postMessage({ action, inputData, msg: fileData }, [channel.port2]);
        });
    }

    terminateWorker() {
        worker.terminate();
    }

    async decryptMessage(message) {
        DEBUG("Attempt to decrypt message (%s)", message.message_id);
        return new Promise((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = ({ data }) => {
                if (data.error) {
                    DEBUG("Can't decrypt message (%s) %s", message.message_id, data.error);
                    resolve({ ...message, didDecrypt: false });
                    return;
                }
                DEBUG("Message decrypted (%s)", message.message_id);
                resolve({ ...message, content: data.result, didDecrypt: true });
            };
            const action = 'decrypt';
            const inputData = { privateKey: this._armoredPrivateKey, publicKey: this._publicKey };
            worker.postMessage({ action, inputData, msg: message.content }, [channel.port2]);
        });
    }

    async _lookupPublicKey(uri) {
        let key = this._cachedPublicKeys.get(uri);
        if (!key) {
            return new Promise((resolve) => {
                this._connection.once('publicKey', (message) => {
                    DEBUG("Fetched public key from server for %s", message.uri);
                    this.addPublicPGPKeys({ [message.uri]: message.publicKey });
                    resolve(message.publicKey);
                });
                this._connection.lookupPublicKey(uri);
            });
        }
        return key;
    }
}

export default PGP;
