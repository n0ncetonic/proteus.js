'use strict';

const Proteus = require('./commonjs/proteus');

const lastResort = Proteus.keys.PreKey.MAX_PREKEY_ID;
const preKey = new Proteus.keys.PreKey(lastResort);
const serializedPreKey = preKey.serialise();

console.log(serializedPreKey);
