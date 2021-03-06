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

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const InputError = require('../errors/InputError');
const TypeUtil = require('../util/TypeUtil');

const KeyPair = require('./KeyPair');

/** @module keys **/

/**
 * @class PreKey
 * @classdesc Pre-generated (and regularly refreshed) pre-keys.
 * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
 * @throws {DontCallConstructor}
 */
class PreKey {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /** @type {number} */
  static get MAX_PREKEY_ID() {
    return 0xFFFF;
  }

  /**
   * @param {!number} pre_key_id
   * @returns {PreKey} - `this`
   * @throws {errors.InputError.RangeError}
   */
  static new(pre_key_id) {
    this.validate_pre_key_id(pre_key_id);

    const pk = ClassUtil.new_instance(PreKey);

    pk.version = 1;
    pk.key_id = pre_key_id;
    pk.key_pair = KeyPair.new();
    return pk;
  }

  static validate_pre_key_id(pre_key_id) {
    TypeUtil.assert_is_integer(pre_key_id);

    if (pre_key_id < 0 || pre_key_id > PreKey.MAX_PREKEY_ID) {
      const message = `PreKey ID (${pre_key_id}) must be between or equal to 0 and ${PreKey.MAX_PREKEY_ID}.`;
      throw new InputError.RangeError(message, InputError.CODE.CASE_400);
    }
  }

  /** @returns {PreKey} */
  static last_resort() {
    return PreKey.new(PreKey.MAX_PREKEY_ID);
  }

  /**
   * @param {!number} start
   * @param {!number} size
   * @returns {Array<PreKey>}
   * @throws {errors.InputError.RangeError}
   */
  static generate_prekeys(start, size) {
    this.validate_pre_key_id(start);
    this.validate_pre_key_id(size);

    if (size === 0) {
      return [];
    }

    return [...Array(size).keys()].map((x) => PreKey.new((start + x) % PreKey.MAX_PREKEY_ID));
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
    e.u8(this.version);
    e.u8(1);
    e.u16(this.key_id);
    e.u8(2);
    return this.key_pair.encode(e);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {PreKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(PreKey);

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
