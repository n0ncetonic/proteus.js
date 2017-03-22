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
const sodium = require('libsodium-wrappers-sumo');
const TypeUtil = require('../util/TypeUtil');

const DecodeError = require('../errors/DecodeError');
const RandomUtil = require('../util/RandomUtil');

/** @module message */

/**
 * @class SessionTag
 * @returns {SessionTag} - `this`
 */
class SessionTag {
  constructor() {
    this._tag = RandomUtil.random_bytes(16);
  }

  /** @type {Buffer} */
  get tag() {
    return this._tag;
  }

  set tag(tag) {
    this._tag = tag;
  }

  /** @returns {string} */
  toString() {
    return sodium.to_hex(this._tag);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    return e.bytes(this._tag);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {SessionTag}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const bytes = new Uint8Array(d.bytes());
    if (bytes.byteLength !== 16) {
      throw DecodeError.InvalidArrayLen(
        `SessionTag should be 16 bytes, not ${bytes.byteLength} bytes.`
      );
    }

    const st = new SessionTag();
    st.tag = new Uint8Array(bytes);
    return st;
  }
}

module.exports = SessionTag;
