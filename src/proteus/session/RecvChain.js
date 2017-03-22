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

const DecryptError = require('../errors/DecryptError');
const ProteusError = require('../errors/ProteusError');

const CipherMessage = require('../message/CipherMessage');
const Envelope = require('../message/Envelope');

const ChainKey = require('./ChainKey');
const MessageKeys = require('./MessageKeys');
const PublicKey = require('../keys/PublicKey');

/** @module session */

/**
 * @class RecvChain
 * @param {!session.ChainKey} chain_key
 * @param {!keys.PublicKey} public_key
 * @returns {message.PreKeyMessage} - `this`
 */
class RecvChain {
  constructor(chain_key, public_key) {
    if (typeof chain_key !== 'undefined') {
      TypeUtil.assert_is_instance(ChainKey, chain_key);
    }
    if (typeof public_key !== 'undefined') {
      TypeUtil.assert_is_instance(PublicKey, public_key);
    }

    this._chain_key = chain_key;
    this._ratchet_key = public_key;
    this._message_keys = [];
  }

  /** @type {session.ChainKey} */
  get chain_key() {
    return this._chain_key;
  }

  set chain_key(chain_key) {
    this._chain_key = chain_key;
  }

  /** @type {keys.PublicKey} */
  get ratchet_key() {
    return this._ratchet_key;
  }

  set ratchet_key(ratchet_key) {
    this._ratchet_key = ratchet_key;
  }

  /** @type {Array<message.Message>} */
  get message_keys() {
    return this._message_keys;
  }

  set message_keys(message_keys) {
    this._message_keys = message_keys;
  }

  /** @type {number} */
  static get MAX_COUNTER_GAP() {
    return 1000;
  }

  /**
   * @param {!message.Envelope} envelope
   * @param {!message.CipherMessage} msg
   * @returns {Uint8Array}
   */
  try_message_keys(envelope, msg) {
    TypeUtil.assert_is_instance(Envelope, envelope);
    TypeUtil.assert_is_instance(CipherMessage, msg);

    if (this._message_keys[0] && this._message_keys[0].counter > msg.counter) {
      throw new DecryptError.OutdatedMessage();
    }

    const idx = this._message_keys.findIndex((mk) => {
      return mk.counter === msg.counter;
    });

    if (idx === -1) {
      throw new DecryptError.DuplicateMessage();
    }

    const mk = this._message_keys.splice(idx, 1)[0];
    if (!envelope.verify(mk.mac_key)) {
      throw new DecryptError.InvalidSignature();
    }

    return mk.decrypt(msg.cipher_text);
  }

  /**
   * @param {!message.CipherMessage} msg
   * @returns {Array<session.ChainKey>|session.MessageKeys}
   */
  stage_message_keys(msg) {
    TypeUtil.assert_is_instance(CipherMessage, msg);

    const num = msg.counter - this._chain_key.idx;
    if (num > RecvChain.MAX_COUNTER_GAP) {
      throw new DecryptError.TooDistantFuture();
    }

    let keys = [];
    let chk = this._chain_key;

    for (let i = 0; i <= num - 1; i++) {
      keys.push(chk.message_keys());
      chk = chk.next();
    }

    const mk = chk.message_keys();
    return [chk, mk, keys];
  }

  /**
   * @param {!Array<session.MessageKeys>} keys
   * @returns {void}
   */
  commit_message_keys(keys) {
    TypeUtil.assert_is_instance(Array, keys);
    keys.map((k) => TypeUtil.assert_is_instance(MessageKeys, k));

    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError('More keys than MAX_COUNTER_GAP');
    }

    const excess = this._message_keys.length + keys.length - RecvChain.MAX_COUNTER_GAP;

    for (let i = 0; i <= excess - 1; i++) {
      this._message_keys.shift();
    }

    keys.map((k) => this._message_keys.push(k));

    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError('Skipped keys greater than MAX_COUNTER_GAP');
    }
  }

  /**
   * @param {!CBOR.Encoder} e
   * @returns {Array<CBOR.Encoder>}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    this._chain_key.encode(e);
    e.u8(1);
    this._ratchet_key.encode(e);

    e.u8(2);
    e.array(this._message_keys.length);
    return this._message_keys.map((k) => k.encode(e));
  }

  /**
   * @param {!CBOR.Decoder} d
   * @returns {RecvChain}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = new RecvChain();

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.chain_key = ChainKey.decode(d);
          break;
        case 1:
          self.ratchet_key = PublicKey.decode(d);
          break;
        case 2:
          self.message_keys = [];

          let len = d.array();
          while (len--) {
            self.message_keys.push(MessageKeys.decode(d));
          }
          break;

        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_instance(ChainKey, self.chain_key);
    TypeUtil.assert_is_instance(PublicKey, self.ratchet_key);
    TypeUtil.assert_is_instance(Array, self.message_keys);

    return self;
  }
}

module.exports = RecvChain;
