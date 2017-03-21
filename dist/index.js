'use strict';

const Proteus = require('./commonjs/proteus');

const lastResort = Proteus.keys.PreKey.MAX_PREKEY_ID;
const preKey = Proteus.keys.PreKey.new(lastResort);
const serializedPreKey = preKey.serialise();

console.log(serializedPreKey);
