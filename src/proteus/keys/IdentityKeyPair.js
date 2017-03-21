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

const IdentityKey = require('./IdentityKey');
const KeyPair = require('./KeyPair');
const SecretKey = require('./SecretKey');

/** @module keys */

/**
 * @class IdentityKeyPair
 * @returns {IdentityKeyPair} - `this`
 */
class IdentityKeyPair {
  constructor() {
    const key_pair = new KeyPair();

    /** @type {number} */
    this.version = 1;

    /** @type {number} */
    this.secret_key = key_pair.secret_key;

    /** @type {keys.IdentityKey} */
    this.public_key = new IdentityKey(key_pair.public_key);

    return this;
  }

  /** @returns {ArrayBuffer} */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @param {!ArrayBuffer} buf
   * @returns {IdentityKeyPair}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);

    const d = new CBOR.Decoder(buf);
    return IdentityKeyPair.decode(d);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    this.secret_key.encode(e);
    e.u8(2);
    return this.public_key.encode(e);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {IdentityKeyPair}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new IdentityKeyPair();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.secret_key = SecretKey.decode(d);
          break;
        case 2:
          self.public_key = IdentityKey.decode(d);
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_instance(SecretKey, self.secret_key);
    TypeUtil.assert_is_instance(IdentityKey, self.public_key);

    return self;
  }
}

module.exports = IdentityKeyPair;
