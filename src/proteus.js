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

module.exports = {
  errors: {
    DecodeError: require('./proteus/errors/DecodeError'),
    DecryptError: require('./proteus/errors/DecryptError'),
    InputError: require('./proteus/errors/InputError'),
    ProteusError: require('./proteus/errors/ProteusError'),
  },

  keys: {
    IdentityKey: require('./proteus/keys/IdentityKey'),
    IdentityKeyPair: require('./proteus/keys/IdentityKeyPair'),
    KeyPair: require('./proteus/keys/KeyPair'),
    PreKey: require('./proteus/keys/PreKey'),
    PreKeyAuth: require('./proteus/keys/PreKeyAuth'),
    PreKeyBundle: require('./proteus/keys/PreKeyBundle'),
    PublicKey: require('./proteus/keys/PublicKey'),
    SecretKey: require('./proteus/keys/SecretKey'),
  },

  message: {
    CipherMessage: require('./proteus/message/CipherMessage'),
    Envelope: require('./proteus/message/Envelope'),
    Message: require('./proteus/message/Message'),
    PreKeyMessage: require('./proteus/message/PreKeyMessage'),
  },

  session: {
    PreKeyStore: require('./proteus/session/PreKeyStore'),
    Session: require('./proteus/session/Session'),
  },
};
