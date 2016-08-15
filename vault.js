'use strict';

const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const fs = require('fs');

module.exports = class Vault {
  /**
   * @param  {String} masterPassword The master password of the 1password Vault
   * @param  {String} [profileName] The profile name in the Vault. Defaults to "default" 
   * @return {OnePassword} OnePassword class instance 
   */
  constructor(masterPassword, profileName) {
    if (profileName == null) {
      profileName = 'default';
    }

    // TODO: Support non-Mac environments?
    const dbFileLocation = `${process.env['HOME']}/Library/Containers/2BUA8C4S2C.com.agilebits.onepassword-osx-helper/Data/Library/Data/OnePassword.sqlite`;
    const db = new sqlite3.Database(dbFileLocation, sqlite3.OPEN_READONLY);

    this.details = [];

    // Hoisting these variables because it's easier to read versus
    // passing them in each promise call below
    let masterPasswordKeyPair;
    let masterDataKeyPair;
    let overviewDataKeyPair;
    let profileData;

    this.dbPromise = new Promise((resolve, reject) => {
      // Read the profile and gather necessary information
      db.get("SELECT id, iterations, master_key_data, overview_key_data, salt FROM profiles WHERE profile_name = ?", profileName, (err, row) => {
        if (err) {
          return reject(err);
        }

        profileData = row;

        return resolve();
      });
    }).then(() => {
      // Now that the necessary information has been gathered, generate keys from master password provided
      // This won't normally reject unless there was some OS level error, and will not reject on invalid
      // password
      return new Promise((resolve, reject) => {
        crypto.pbkdf2(masterPassword, profileData.salt, profileData.iterations, 64, 'sha512', (err, key) => {
          if (err) {
            return reject(err);
          }

          // Encryption key, MAC key
          masterPasswordKeyPair = [ key.slice(0, 32), key.slice(32) ];

          return resolve();
        });
      });
    }).then(() => {
      // Attempt to decrypt the master key data with the master password
      // Will fail if the password is incorrect
      return new Promise((resolve, reject) => {
        decryptKeyData(masterPasswordKeyPair, profileData.master_key_data, true, (err, masterDataKeyData) => {
          if (err) {
            return reject(err);
          }

          return resolve(masterDataKeyData);
        });
      });
    }).then(masterDataKeyData => {
      // Create key pair from master key data
      masterDataKeyPair = createKeyPair(masterDataKeyData, true);

      return Promise.resolve();
    }).then(() => {
      // Attempt to decrypt overview key data
      return new Promise((resolve, reject) => {
        decryptKeyData(masterPasswordKeyPair, profileData.overview_key_data, true, (err, overviewDataKeyData) => {
          if (err) {
            return reject(err);
          }

          return resolve(overviewDataKeyData);
        });
      });
    }).then(overviewDataKeyData => {
      // Create overview keypair
      overviewDataKeyPair = createKeyPair(overviewDataKeyData, true);

      return Promise.resolve();
    }).then(() => {
      // Get all overview data from the db
      return new Promise((resolve, reject) => {
        db.all('SELECT id, key_data, overview_data FROM items WHERE profile_id = ? AND trashed = 0', profileData.id, (err, items) => {
          if (err) {
            return reject(err);
          }

          return resolve(items);
        });
      });
    }).then(items => {
      const keys = [];

      // For..of doesn't work properly in Node LTS 4.4.7
      for(let i = 0; i < items.length; i++) {
        const item = items[i];

        // Decrypt each item overview datum
        decryptKeyData(overviewDataKeyPair, item.overview_data, false, (err, overviewData) => {
          if (err) {
            return Promise.reject(err);
          }

          // Decrypt each item key datum
          decryptKeyData(masterDataKeyPair, item.key_data, false, (err, keyData) => {
            if (err) {
              return Promise.reject(err);
            }

            let itemDataKeyPair;

            // If the item keydata is empty, use the overview key pair
            if (!keyData.length) {
              itemDataKeyPair = overviewDataKeyPair;
            } else {
              itemDataKeyPair = createKeyPair(keyData);
            }

            keys.push({
              overviewDataRaw: overviewData,
              overviewData: JSON.parse(overviewData.toString('utf8')),
              itemDataKeyPair,
              id: item.id
            });
          });
        });
      }

      return Promise.resolve(keys);
    }).then(keys => {
      // Retrieve all item details
      return new Promise((resolve, reject) => {
        db.all('SELECT item_id, data FROM item_details', (err, itemDetails) => {
          if (err) {
            return reject(err);
          }

          return resolve({ 
            keys,
            itemDetails
          });
        });
      });
    }).then(result => {
      const keys = result.keys;
      const itemDetails = result.itemDetails;
      const itemDetailsPromises = [];

      // Decrypt each item detail and add it to `this.details`
      itemDetails.forEach((detail, i) => {
        const itemOverview = keys.find(key => { return key.id === detail.item_id  });

        if (!itemOverview) {
          return;
        }

        itemDetailsPromises.push(new Promise((resolve, reject) => {
          decryptKeyData(itemOverview.itemDataKeyPair, detail.data, true, (err, itemDetail) => {
            // We can ignore the error here, sometimes itemDetail 
            // won't exist and we should set it to null

            if (err) {
              itemDetail = null;
            }

            this.details.push({
              itemOverview,
              itemDetailRaw: itemDetail,
              itemDetail: itemDetail ? JSON.parse(itemDetail.toString('utf8')) : null,
            });

            return resolve();
          });
        }));
      });

      // Return Promise that waits for all itemDetails promises
      return Promise.all(itemDetailsPromises);
    });
  }

  /**
   * @param  {String} title Title of the item to search for
   * @return {Promise([Object|null])} Promise with array of result
   */
  search(title) {
    return this.dbPromise.then(() => {
      const items = this.details.filter(detail => detail.itemOverview.overviewData.title === title);

      if (items.length) {
        return Promise.resolve(items);
      } else {
        return Promise.reject();
      }
    });
  }
}

/**
 * @param  {Array} keypair Encryption and MAC keypair
 * @param  {Buffer} data Raw encrypted data buffer
 * @param  {Boolean} isOpdata01 If the data is Opdata01 format, see https://support.1password.com/opvault-design/#opdata01
 * @param  {Function} callback
 * @return {String} Plaintext key data (in binary format, not hex)
 */
function decryptKeyData(keypair, data, isOpdata01, callback) {
  // `data` if in OPData1 format:
  // 8 bytes: <String> "opdata01"
  // 8 bytes: <Int> Length, unsigned 64 bit little endian
  // 16 bytes: <Binary> Initialization Vector (IV)
  // Variable: <Binary> AES Encrypted data in CBC mode
  // 32 bytes: <Binary> HMAC-SHA256 MAC

  const offset = isOpdata01 ? 16 : 0;

  const check = data.slice(0, 8).toString();
  const length = (data.readUInt32LE(12) << 8) + data.readUInt32LE(8);
  const iv = data.slice(offset, offset + 16);
  const ciphertext = data.slice(offset + 16, -32);
  const hmacData = data.slice(0, -32);
  const hmacCheck = data.slice(-32);

  // The check must be "opdata01"
  if (isOpdata01) {
    if (check !== 'opdata01') {
      return callback(new Error('Invalid OPData1 Checksum'));
    }
  }

  // Create and verify MAC
  const hmac = crypto.createHmac('sha256', keypair[1]);
  hmac.update(hmacData);
  const digest = hmac.digest('hex');

  if (digest !== hmacCheck.toString('hex')) {
    return callback(new Error('Invalid password'));
  }

  // Decipher with encryption key and IV
  const decipher = crypto.createDecipheriv('aes-256-cbc', keypair[0], iv);
  decipher.setAutoPadding(false);
  let plaintext = decipher.update(ciphertext);
  decipher.final();

  // Remove padding
  // Use absolute value when slicing, in case length is negative (JS doesn't handle big ints well)
  plaintext = plaintext.slice(-Math.abs(length));

  return callback(null, plaintext);
}

/**
 * @param  {Buffer} data Raw key data
 * @param  {Boolean} digest If the data should be hashed before slicing
 * @return {Array[String]} Array consisting of encryption and MAC keys, in binary format
 */
function createKeyPair(data, digest) {
  if (digest) {
    const hash = crypto.createHash('sha512');
    hash.update(data);
    data = hash.digest();
  }

  return [ data.slice(0, 32), data.slice(32) ];
}
