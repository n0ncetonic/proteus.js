/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

const CBOR = require('wire-webapp-cbor');
const TypeUtil = require('../util/TypeUtil');

const CipherKey = require('../derived/CipherKey');
const MacKey = require('../derived/MacKey');

/** @module session */

/**
 * @class MessageKeys
 * @param {!derived.CipherKey} cipher_key
 * @param {!derived.MacKey} mac_key
 * @param {!number} counter
 * @returns {MessageKeys} - `this`
 */
class MessageKeys {
  constructor(cipher_key, mac_key, counter) {
    if (typeof cipher_key !== 'undefined') {
      TypeUtil.assert_is_instance(CipherKey, cipher_key);
    }
    if (typeof mac_key !== 'undefined') {
      TypeUtil.assert_is_instance(MacKey, mac_key);
    }
    if (typeof counter !== 'undefined') {
      TypeUtil.assert_is_integer(counter);
    }

    this._cipher_key = cipher_key;
    this._mac_key = mac_key;
    this._counter = counter;
  }

  /** @type {derived.CipherKey} */
  get cipher_key() {
    return this._cipher_key;
  }

  set cipher_key(cipher_key) {
    this._cipher_key = cipher_key;
  }

  /** @type {derived.MacKey} */
  get mac_key() {
    return this._mac_key;
  }

  set mac_key(mac_key) {
    this._mac_key = mac_key;
  }

  /** @type {number} */
  get counter() {
    return this._counter;
  }

  set counter(counter) {
    this._counter = counter;
  }

  /**
   * @returns {Uint8Array}
   * @private
   */
  _counter_as_nonce() {
    const nonce = new ArrayBuffer(8);
    new DataView(nonce).setUint32(0, this._counter);
    return new Uint8Array(nonce);
  }

  /**
   * @param {!(string|Uint8Array)} plaintext
   * @returns {Uint8Array}
   */
  encrypt(plaintext) {
    return this._cipher_key.encrypt(plaintext, this._counter_as_nonce());
  }

  /**
   * @param {!Uint8Array} ciphertext
   * @returns {Uint8Array}
   */
  decrypt(ciphertext) {
    return this._cipher_key.decrypt(ciphertext, this._counter_as_nonce());
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    this._cipher_key.encode(e);
    e.u8(1);
    this._mac_key.encode(e);
    e.u8(2);
    return e.u32(this._counter);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {MessageKeys}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new MessageKeys();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.cipher_key = CipherKey.decode(d);
          break;
        case 1:
          self.mac_key = MacKey.decode(d);
          break;
        case 2:
          self.counter = d.u32();
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_instance(CipherKey, self.cipher_key);
    TypeUtil.assert_is_instance(MacKey, self.mac_key);
    TypeUtil.assert_is_integer(self.counter);

    return self;
  }
}

module.exports = MessageKeys;
