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

process.env.NODE_PATH = './src';
require('module').Module._initPaths();

assert = require('chai').assert;

global.sodium = require('libsodium-wrappers-sumo');

Proteus = require('proteus');
Proteus.derived = {
  CipherKey: require('proteus/derived/CipherKey'),
  DerivedSecrets: require('proteus/derived/DerivedSecrets'),
  MacKey: require('proteus/derived/MacKey'),
};

Proteus.message.SessionTag = require('proteus/message/SessionTag');

Proteus.util = {
  ArrayUtil: require('proteus/util/ArrayUtil'),
  KeyDerivationUtil: require('proteus/util/KeyDerivationUtil'),
  MemoryUtil: require('proteus/util/MemoryUtil'),
  TypeUtil: require('proteus/util/TypeUtil'),
};
