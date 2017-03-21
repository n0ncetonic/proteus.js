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

/* eslint no-unused-vars: "off" */

'use strict';

const ProteusError = require('./ProteusError');

/** @module errors */

/**
 * @extends ProteusError
 * @param {string} [message]
 */
class DecryptError extends ProteusError {
  constructor(message = 'Unknown decryption error') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class RemoteIdentityChanged extends DecryptError {
  constructor(message = 'Remote identity changed') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class InvalidSignature extends DecryptError {
  constructor(message = 'Invalid signature') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class InvalidMessage extends DecryptError {
  constructor(message = 'Invalid message') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class DuplicateMessage extends DecryptError {
  constructor(message = 'Duplicate message') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class TooDistantFuture extends DecryptError {
  constructor(message = 'Message is from too distant in the future') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class OutdatedMessage extends DecryptError {
  constructor(message = 'Outdated message') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecryptError
 * @param {string} [message]
 */
class PrekeyNotFound extends DecryptError {
  constructor(message = 'Pre-key not found') {
    super();
    this.message = message;
  }
}

Object.assign(DecryptError, {
  RemoteIdentityChanged,
  InvalidSignature,
  InvalidMessage,
  DuplicateMessage,
  TooDistantFuture,
  OutdatedMessage,
  PrekeyNotFound,
});

module.exports = ProteusError.DecryptError = DecryptError;
