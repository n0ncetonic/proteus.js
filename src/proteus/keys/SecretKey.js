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
const ed2curve = require('ed2curve');
const sodium = require('libsodium-wrappers-sumo');
if (typeof window === 'undefined') try { Object.assign(sodium, require('libsodium-neon')); } catch (e) { /**/ }

const PublicKey = require('./PublicKey');
const TypeUtil = require('../util/TypeUtil');

/** @module keys */

/**
 * @class SecretKey
 * @param {!Uint8Array} sec_edward
 * @param {!Uint8Array} sec_curve
 * @returns {SecretKey} - `this`
 */
class SecretKey {
  constructor(sec_edward, sec_curve) {
    if (typeof sec_edward !== 'undefined') {
      TypeUtil.assert_is_instance(Uint8Array, sec_edward);
    }
    if (typeof sec_curve !== 'undefined') {
      TypeUtil.assert_is_instance(Uint8Array, sec_curve);
    }

    /** @type {Uint8Array} */
    this.sec_edward = sec_edward;

    /** @type {Uint8Array} */
    this.sec_curve = sec_curve;

    return this;
  }

  /**
   * This function can be used to compute a message signature.
   * @param {!string} message - Message to be signed
   * @returns {Uint8Array} - A message signature
   */
  sign(message) {
    return sodium.crypto_sign_detached(message, this.sec_edward);
  }

  /**
   * This function can be used to compute a shared secret given a user's secret key and another
   * user's public key.
   * @param {!keys.PublicKey} public_key - Another user's public key
   * @returns {Uint8Array} - Array buffer view of the computed shared secret
   */
  shared_secret(public_key) {
    TypeUtil.assert_is_instance(PublicKey, public_key);

    return sodium.crypto_scalarmult(this.sec_curve, public_key.pub_curve);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.sec_edward);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {SecretKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new SecretKey();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.sec_edward = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_instance(Uint8Array, self.sec_edward);

    self.sec_curve = ed2curve.convertSecretKey(self.sec_edward);
    return self;
  }
}

module.exports = SecretKey;
