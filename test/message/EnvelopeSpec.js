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

describe('Envelope', () => {
  const mk = new Proteus.derived.MacKey(new Uint8Array(32).fill(1));
  const bk = new Proteus.keys.KeyPair().public_key;
  const ik = new Proteus.keys.IdentityKey(new Proteus.keys.KeyPair().public_key);
  const rk = new Proteus.keys.KeyPair().public_key;

  const tg = new Proteus.message.SessionTag();

  it('should encapsulate a CipherMessage', () => {
    const msg = new Proteus.message.CipherMessage(tg, 42, 3, rk, new Uint8Array([1, 2, 3, 4, 5]));
    const env = new Proteus.message.Envelope(mk, msg);

    assert(env.verify(mk));
  });

  it('should encapsulate a PreKeyMessage', () => {
    const msg = new Proteus.message.PreKeyMessage(
      42, bk, ik,
      new Proteus.message.CipherMessage(
        tg, 42, 43, rk, new Uint8Array([1, 2, 3, 4])
      )
    );

    const env = new Proteus.message.Envelope(mk, msg);
    assert(env.verify(mk));
  });

  it('should encode to and decode from CBOR', () => {
    const msg = new Proteus.message.PreKeyMessage(
      42, bk, ik,
      new Proteus.message.CipherMessage(
        tg, 42, 43, rk, new Uint8Array([1, 2, 3, 4])
      )
    );

    const env = new Proteus.message.Envelope(mk, msg);
    assert(env.verify(mk));

    const env_bytes = env.serialise();
    const env_cpy = Proteus.message.Envelope.deserialise(env_bytes);

    assert(env_cpy.verify(mk));
  });
});
