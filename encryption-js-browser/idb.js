window.clientKey_idbKey = 'clientKeyIdbKey';
window.idbName = 'mpf_idb';
window.idbVersion = 1;
window.clientKey_idbStoreName= 'clientKeyIdbStoreName';
window.clientKey_idbUpgradeCb = (db) => {
    if (!db.objectStoreNames.contains(window.clientKey_idbStoreName)) {
        db.createObjectStore(window.clientKey_idbStoreName);
    }
};
window.idbClient = {
	openDb: function (dbName, version, upgradeCb) {
		return new Promise((resolve, reject) => {
			const request = indexedDB.open(dbName, version);

			request.onerror = (event) => {
				reject(`Failed to open database: ${event.target.error}`);
			};

			request.onsuccess = (event) => {
				resolve(event.target.result);
			};

			request.onupgradeneeded = (event) => {
				upgradeCb(event.target.result);
			};
		});
	},
	createRecord: function (db, storeName, data, key = null) {
		return new Promise((resolve, reject) => {
			const transaction = db.transaction(storeName, 'readwrite');
			const objectStore = transaction.objectStore(storeName);
			const request = key ? objectStore.add(data, key) : object.add(data);

			request.onsuccess = (event) => {
				resolve(event.target.result);
			};

			request.onerror = (event) => {
				reject(`Failed to create record: ${event.target.error}`);
			};
		});
	},
	readRecord: function (db, storeName, key) {
		return new Promise((resolve, reject) => {
			const transaction = db.transaction(storeName, 'readonly');
			const objectStore = transaction.objectStore(storeName);
			const request = objectStore.get(key);

			request.onsuccess = (event) => {
				resolve(event.target.result);
			};

			request.onerror = (event) => {
				reject(`Failed to read record: ${event.target.error}`);
			};
		});
	},
	updateRecord: function (db, storeName, key, newData) {
		return new Promise((resolve, reject) => {
			const transaction = db.transaction(storeName, 'readwrite');
			const objectStore = transaction.objectStore(storeName);
			const request = objectStore.put(newData, key);

			request.onsuccess = (event) => {
				resolve(event.target.result);
			};

			request.onerror = (event) => {
				reject(`Failed to update record: ${event.target.error}`);
			};
		});
	},
	deleteRecord: function (db, storeName, key) {
		return new Promise((resolve, reject) => {
			const transaction = db.transaction(storeName, 'readwrite');
			const objectStore = transaction.objectStore(storeName);
			const request = objectStore.delete(key);

			request.onsuccess = () => {
				resolve();
			};

			request.onerror = (event) => {
				reject(`Failed to delete record: ${event.target.error}`);
			};
		});
	}
};