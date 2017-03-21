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
 * @returns {string}
 */
class DecodeError extends ProteusError {
  constructor(message = 'Unknown decoding error') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecodeError
 * @param {string} [message]
 * @returns {string}
 */
class InvalidType extends DecodeError {
  constructor(message = 'Invalid type') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecodeError
 * @param {string} [message]
 * @returns {string}
 */
class InvalidArrayLen extends DecodeError {
  constructor(message = 'Invalid array length') {
    super();
    this.message = message;
  }
}

/**
 * @extends DecodeError
 * @param {string} [message]
 * @returns {string}
 */
class LocalIdentityChanged extends DecodeError {
  constructor(message = 'Local identity changed') {
    super();
    this.message = message;
  }
}

Object.assign(DecodeError, {
  InvalidType,
  InvalidArrayLen,
  LocalIdentityChanged,
});

module.exports = ProteusError.DecodeError = DecodeError;
