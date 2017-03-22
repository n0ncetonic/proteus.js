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

const IdentityKey = require('./IdentityKey');
const IdentityKeyPair = require('./IdentityKeyPair');
const PreKey = require('./PreKey');
const PreKeyAuth = require('./PreKeyAuth');
const PublicKey = require('./PublicKey');

const TypeUtil = require('../util/TypeUtil');

/** @module keys */

/**
 * @class PreKeyBundle
 * @param {keys.IdentityKey} public_identity_key
 * @param {keys.PreKey} prekey
 * @returns {PreKeyBundle} - `this`
 */
class PreKeyBundle {
  constructor(public_identity_key, prekey) {
    if (typeof public_identity_key !== 'undefined') {
      TypeUtil.assert_is_instance(IdentityKey, public_identity_key);
    }
    if (typeof prekey !== 'undefined') {
      TypeUtil.assert_is_instance(PreKey, prekey);

      this._prekey_id = prekey.key_id;
      this._public_key = prekey.key_pair.public_key;
    }

    this._version = 1;
    this._identity_key = public_identity_key;
    this._signature = null;
  }

  /** @type {number} */
  get version() {
    return this._version;
  }

  set version(version) {
    this._version = version;
  }

  /** @type {keys.IdentityKey} */
  get identity_key() {
    return this._identity_key;
  }

  set identity_key(identity_key) {
    this._identity_key = identity_key;
  }

  /** @type {Uint8Array} */
  get signature() {
    return this._signature;
  }

  set signature(signature) {
    this._signature = signature;
  }

  /**
   * @param {!keys.IdentityKeyPair} identity_pair
   * @param {!keys.PreKey} prekey
   * @returns {PreKeyBundle}
   */
  static signed(identity_pair, prekey) {
    TypeUtil.assert_is_instance(IdentityKeyPair, identity_pair);
    TypeUtil.assert_is_instance(PreKey, prekey);

    const ratchet_key = prekey.key_pair.public_key;
    const signature = identity_pair.secret_key.sign(ratchet_key.pub_edward);
    const bundle = new PreKeyBundle();

    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = ratchet_key;
    bundle.identity_key = identity_pair.public_key;
    bundle.signature = signature;

    return bundle;
  }

  /** @returns {keys.PreKeyAuth} */
  verify() {
    if (!this._signature) {
      return PreKeyAuth.UNKNOWN;
    }

    if (this._identity_key.public_key.verify(this._signature, this._public_key.pub_edward)) {
      return PreKeyAuth.VALID;
    }
    return PreKeyAuth.INVALID;
  }

  /** @returns {ArrayBuffer} */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @typedef {Object} type_serialised_json
   * @property {number} id
   * @property {string} key
   */
  /** @returns {type_serialised_json} */
  serialised_json() {
    return {
      'id': this._prekey_id,
      'key': sodium.to_base64(new Uint8Array(this.serialise()), true),
    };
  }

  /**
   * @param {!ArrayBuffer} buf
   * @returns {PreKeyBundle}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKeyBundle.decode(new CBOR.Decoder(buf));
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    TypeUtil.assert_is_instance(CBOR.Encoder, e);

    e.object(5);
    e.u8(0);
    e.u8(this._version);
    e.u8(1);
    e.u16(this._prekey_id);
    e.u8(2);
    this._public_key.encode(e);
    e.u8(3);
    this._identity_key.encode(e);

    e.u8(4);
    if (!this._signature) {
      return e.null();
    } else {
      return e.bytes(this._signature);
    }
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {PreKeyBundle}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new PreKeyBundle();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.prekey_id = d.u16();
          break;
        case 2:
          self.public_key = PublicKey.decode(d);
          break;
        case 3:
          self.identity_key = IdentityKey.decode(d);
          break;
        case 4:
          self.signature = d.optional(() => new Uint8Array(d.bytes()));
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_integer(self.prekey_id);
    TypeUtil.assert_is_instance(PublicKey, self.public_key);
    TypeUtil.assert_is_instance(IdentityKey, self.identity_key);

    return self;
  }
}

module.exports = PreKeyBundle;
