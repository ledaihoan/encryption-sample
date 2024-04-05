window.base64ToArrayBuffer = function base64ToArrayBuffer(base64) {
	var binary_string = window.atob(base64);
	var len = binary_string.length;
	var bytes = new Uint8Array(len);
	for (var i = 0; i < len; i++) {
		bytes[i] = binary_string.charCodeAt(i);
	}
	return bytes.buffer;
};

window.arrayBufferToBase64 = function arrayBufferToBase64(buffer) {
	var binary = '';
	var bytes = new Uint8Array(buffer);
	var len = bytes.byteLength;
	for (var i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return window.btoa(binary);
};

window.importPublicKey = async function importPublicKey(spki) {
	const binaryDer = base64ToArrayBuffer(spki);
	var cryptoKey = await window.crypto.subtle
		.importKey(
			"spki",
			binaryDer, {
			name: 'RSA-OAEP',
			modulusLength: 4096,
			hash: {
				name: 'sha-256'
			}
		},
			false,
			["encrypt"]
		);
	return cryptoKey;
};

window.encryptDataWithPublicKey = async function (message, publicKey) {
	let enc = new TextEncoder();
	let encodedMessage = enc.encode(message);
	var encryptedData = await window.crypto.subtle.encrypt({
		name: "RSA-OAEP"
	},
		publicKey,
		encodedMessage
	);
	var encodedData = arrayBufferToBase64(encryptedData);
	return encodedData;
};

window.serverPublicKey = 'MIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgBehP/aVmw43tVYNx+uB/fvkzF+H+nx4kFcy4Jo5guR38ovxQ7Z22iYMtmD689n3rgpE4OXI30qfHcmbY9zDga8zxisvclbJg4v36r1deLtPFhpfXIZB/WL/EGnJEKsX4sUCncXY0yx6oL6qep1Aqu+WLgk7q/YeemnKhuUQ1AUAmf4T+Z8ttgXXKIYYQgtj0iO6U75phBbWKg4bsTWhHDX4dSVe9li8Y05mk0pSrUlryIZpIVTiLc2i7ASSiQ+NgFmLyxy78mMJ01A1Ra4XuJE/Py0G0Wf4CoxWbe4lQHRj8w++zUisskXjGogVIelD3Vkhsp01yIq1DI5N8z4vWTEt2h5wwTEtSPyYs0JPPU+gJ970FsNAkZb7lZ3AD4MxvakvbAJkb2itvuhcis1qN1xMMDTRkonakH5K7Ca8fwARoG/pl0DcASWJY7QyadbEmjyyki2AEt+lNa2C77Z3ZCEssikl5D+74wIxpO34zRmGLT1r1rb/KICdK/dO7H6vui+8FSxO1zJJzOPiiPGGVSdlPMhZgxn/aiIca4heCzIv7lIsi/U5AZdjF7+NRHmSmYA+6x1UxarkMZXXDC6WVqmFTZ7vpE1oDsyde6/PfSbpAJ/AR6bBX2FA+IStdpH/ZhDEmIYL3cC8kaP9g+djEPP5BOqNqOJtuS/XtXftMgT4wIDAQAB';

window.encryptServerPublic = async function (message) {
	var spki = window.serverPublicKey;
	var key = await importPublicKey(spki);
	var encryptedData = await encryptDataWithPublicKey(message, key);
	return encryptedData;
};

window.getCurrentClientKeyPair = async function () {
	var idb = await window.idbClient.openDb(window.idbName, window.idbVersion, window.clientKey_idbUpgradeCb);
	var clientKeyPair = await window.idbClient.readRecord(idb, window.clientKey_idbStoreName, clientKey_idbKey);
	return clientKeyPair;
};

window.storeClientKeyPair = async function (clientKeyPair) {
	var idb = await window.idbClient.openDb(window.idbName, window.idbVersion, window.clientKey_idbUpgradeCb);
	await window.idbClient.deleteRecord(idb, window.clientKey_idbStoreName, window.clientKey_idbKey);
	await window.idbClient.createRecord(idb, window.clientKey_idbStoreName, clientKeyPair, window.clientKey_idbKey);
};

window.generateClientKeyPair = async function () {
	var clientKeyPair = await window.getCurrentClientKeyPair();
	if (!clientKeyPair) {
		const key = await window.crypto.subtle.generateKey(
			{
				name: "RSA-OAEP",
				modulusLength: 4096, //can be 1024, 2048, or 4096
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				hash: {name: "sha-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
			},
			false, //whether the key is extractable (i.e. can be used in exportKey)
			["decrypt"]
		);
		await window.storeClientKeyPair(key);
		//returns a keypair object
		//console.log(key);
		//console.log(key.publicKey);
		//console.log(key.privateKey);
		
	}
};

window.exportPKey = async function () {
	var clientKeyPair = await window.getCurrentClientKeyPair();
	if (clientKeyPair && clientKeyPair.publicKey) {
		const exportedPKey = await window.crypto.subtle.exportKey("spki", clientKeyPair.publicKey);
		return arrayBufferToBase64(exportedPKey);
	}
	return "";
};

window.generateRandomBytes = function (length=16) {
    return crypto.getRandomValues(new Uint8Array(length));
};

window.generateRandomHex = async function (length) {
    const bytes = new Uint8Array(length / 2);
    await window.crypto.getRandomValues(bytes);
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
};

window.hexStringToUint8Array = function (hexString) {
    return new TextEncoder().encode(hexString);
};


// Function to pad data with PKCS7
window.pkcs7Pad = function (message) {
    const blockSize = 16;
    const paddingLength = blockSize - (message.length % blockSize);
    const padding = new Uint8Array(paddingLength).fill(paddingLength);
    const paddedMessage = new Uint8Array(message.length + paddingLength);
    paddedMessage.set(message);
    paddedMessage.set(padding, message.length);
    return paddedMessage;
};
// Function to remove PKCS7 padding
window.pkcs7Unpad = function (data) {
    const paddingLength = data[data.length - 1];
    if (paddingLength < 1 || paddingLength > 16) {
        throw new Error("Invalid PKCS7 padding length");
    }
    for (let i = 1; i <= paddingLength; i++) {
        if (data[data.length - i] !== paddingLength) {
            throw new Error("Invalid PKCS7 padding");
        }
    }
    return data.slice(0, data.length - paddingLength);
};


window.encryptAES_CBC_256 = async function (message) {
    // Generate a random IV
    const ivHex = await window.generateRandomHex(16);
	const keyHex = await window.generateRandomHex(32);
	
	const iv = window.hexStringToUint8Array(ivHex);
	const key = window.hexStringToUint8Array(keyHex);
	

    // Import the key
    const importedKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
	
	const originBytes = new TextEncoder().encode(message);

    // Pad the data with PKCS7
    const paddedData = pkcs7Pad(originBytes);

    // Perform encryption
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'AES-CBC',
            iv: iv
        },
        importedKey,
        paddedData
    );

    // Return IV and encrypted data
    return { iv: ivHex, key: keyHex, encryptedData: arrayBufferToBase64(encryptedData) };
};

window.decryptAES_CBC_256 = async function (encryptedMessage, keyHex, ivHex) {
	// Convert hexadecimal strings to Uint8Array
    const key = window.hexStringToUint8Array(keyHex);
    const iv = window.hexStringToUint8Array(ivHex);
	
	const encryptedBytes = base64ToArrayBuffer(encryptedMessage);

    // Import the key
    const importedKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    // Perform decryption
    const decryptedBytes = await crypto.subtle.decrypt(
        {
            name: 'AES-CBC',
            iv: iv
        },
        importedKey,
        encryptedBytes
    );


    // Remove PKCS7 padding
    const unpaddedBytes = window.pkcs7Unpad(new Uint8Array(decryptedBytes));
    // Return the decrypted data
    return new TextDecoder().decode(unpaddedBytes);
};

window.encryptPayload = async function (payload, publicKey = window.serverPublicKey) {
	const json = JSON.stringify(payload);
	const encrypted = await encryptAES_CBC_256(json);
	const { encryptedData, key, iv } = encrypted;
	const pKey = await window.importPublicKey(publicKey);
	const encryptedKeyIv = await window.encryptDataWithPublicKey(key + iv, pKey);
	return `${encryptedData},${encryptedKeyIv}`;
};

window.encryptClientPayload = async function (payload) {
	await window.generateClientKeyPair();
	const clientPKey = await window.exportPKey();
	const wrapPayload = {
		...payload,
		clientPublicKey: clientPKey
	};
	return window.encryptPayload(wrapPayload, window.serverPublicKey);
};

window.decryptJsonPayload = function (payload, privateKey) { return payload; };

window.decryptResponse = function (encryptedResponseString) { return encryptedResponseString; };



(async () => {
	const payload = {
		"message": "abc"
	};
	const encrypted = await window.encryptClientPayload(payload);
	console.log(encrypted);
	
})();
