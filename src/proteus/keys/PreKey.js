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
const KeyPair = require('./KeyPair');
const TypeUtil = require('../util/TypeUtil');

/** @module keys **/

/**
 * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
 * @class PreKey
 * @classdesc Pre-generated (and regularly refreshed) pre-keys.
 * @param {!number} pre_key_id
 * @returns {PreKey} - `this`
 * @throws {RangeError}
 */
class PreKey {
  constructor(pre_key_id) {
    if (typeof pre_key_id !== 'undefined') {
      TypeUtil.assert_is_integer(pre_key_id);
    }

    if (pre_key_id < 0 || pre_key_id > PreKey.MAX_PREKEY_ID) {
      throw new RangeError(
        `Argument pre_key_id (${pre_key_id}) must be between 0 (inclusive) and ${PreKey.MAX_PREKEY_ID} (inclusive).`
      );
    }

    this._version = 1;
    this._key_id = pre_key_id;
    this._key_pair = new KeyPair();
  }

  /** @type {number} */
  static get MAX_PREKEY_ID() {
    return 0xFFFF;
  }

  /** @type {number} */
  get version() {
    return this._version;
  }

  set version(version) {
    this._version = version;
  }

  /** @type {number} */
  get key_id() {
    return this._key_id;
  }

  set key_id(key_id) {
    this._key_id = key_id;
  }

  /** @type {keys.KeyPair} */
  get key_pair() {
    return this._key_pair;
  }

  set key_pair(key_pair) {
    this._key_pair = key_pair;
  }


  /** @returns {PreKey} */
  static last_resort() {
    return new PreKey(PreKey.MAX_PREKEY_ID);
  }

  /**
   * @param {!number} start
   * @param {!number} size
   * @returns {Array<PreKey>}
   */
  static generate_prekeys(start, size) {
    const check_integer = (value) => {
      TypeUtil.assert_is_integer(value);

      if (value < 0 || value > PreKey.MAX_PREKEY_ID) {
        throw new RangeError(
          `Arguments must be between 0 (inclusive) and ${PreKey.MAX_PREKEY_ID} (inclusive).`
        );
      }
    };

    check_integer(start);
    check_integer(size);

    if (size === 0) {
      return [];
    }

    return [...Array(size).keys()].map((x) => new PreKey((start + x) % PreKey.MAX_PREKEY_ID));
  }

  /** @returns {ArrayBuffer} */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @param {!ArrayBuffer} buf
   * @returns {PreKey}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKey.decode(new CBOR.Decoder(buf));
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    TypeUtil.assert_is_instance(CBOR.Encoder, e);
    e.object(3);
    e.u8(0);
    e.u8(this._version);
    e.u8(1);
    e.u16(this._key_id);
    e.u8(2);
    return this._key_pair.encode(e);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {PreKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new PreKey();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.key_id = d.u16();
          break;
        case 2:
          self.key_pair = KeyPair.decode(d);
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_integer(self.key_id);
    TypeUtil.assert_is_instance(KeyPair, self.key_pair);

    return self;
  }
}

module.exports = PreKey;
