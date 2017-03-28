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
const TypeUtil = require('../util/TypeUtil');

if (typeof window === 'undefined') try { Object.assign(sodium, require('libsodium-neon')); } catch (e) { /**/ }

/** @module keys */

/**
 * @class PublicKey
 * @param {Uint8Array} [pub_edward]
 * @param {Uint8Array} [pub_curve]
 * @returns {PublicKey} - `this`
 */
class PublicKey {
  constructor(pub_edward, pub_curve) {
    if (typeof pub_edward !== 'undefined') {
      TypeUtil.assert_is_instance(Uint8Array, pub_edward);
    }
    if (typeof pub_edward !== 'undefined') {
      TypeUtil.assert_is_instance(Uint8Array, pub_curve);
    }

    /** @type {Uint8Array} */
    this.pub_edward = pub_edward;

    /** @type {Uint8Array} */
    this.pub_curve = pub_curve;
  }

  /**
   * This function can be used to verify a message signature.
   *
   * @param {!Uint8Array} signature - The signature to verify
   * @param {!string} message - The message from which the signature was computed.
   * @returns {boolean} - `true` if the signature is valid, `false` otherwise.
   */
  verify(signature, message) {
    TypeUtil.assert_is_instance(Uint8Array, signature);
    return sodium.crypto_sign_verify_detached(signature, message, this.pub_edward);
  }

  /** @returns {string} */
  fingerprint() {
    return sodium.to_hex(this.pub_edward);
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.pub_edward);
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {PublicKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new PublicKey();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.pub_edward = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_instance(Uint8Array, self.pub_edward);

    self.pub_curve = ed2curve.convertPublicKey(self.pub_edward);
    return self;
  }
}

module.exports = PublicKey;
