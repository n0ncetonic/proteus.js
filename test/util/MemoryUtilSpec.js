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

describe('MemoryUtil', () => {
  describe('zeroize', () => {
    it('zeroizes an ArrayBuffer', () => {
      const buffer_random = new ArrayBuffer(32);
      new Uint8Array(buffer_random).fill((Math.random() * 10) + 1);

      Proteus.util.MemoryUtil.zeroize(buffer_random);
      new Uint8Array(buffer_random).every((value) => assert.strictEqual(value, 0));
    });

    it('zeroizes an Uint8Array', () => {
      const array_random = Uint8Array.from({length: 32}, () => (Math.random() * 10) + 1);

      assert.lengthOf(array_random, 32);
      Proteus.util.MemoryUtil.zeroize(array_random);
      array_random.every((value) => assert.strictEqual(value, 0));
    });

    it('deeply zeroizes a KeyPair', async () => {
      const key_pair = await Proteus.keys.KeyPair.new();

      Proteus.util.MemoryUtil.zeroize(key_pair);
      key_pair.secret_key.sec_edward.every((value) => assert.strictEqual(value, 0));
      key_pair.secret_key.sec_curve.every((value) => assert.strictEqual(value, 0));
    });
  });
});
