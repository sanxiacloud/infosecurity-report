'use strict';

const mm = require('micromatch');

const serverIP = [
  mm.braces('10.19.{213..214}.*'),
  mm.braces('10.19.{248..255}.*'),
  '10.19.110.*',
  mm.braces('10.19.{136..151}.*'),
  '10.19.195.*',
  mm.braces('10.{27..29}.*.*'),
  '10.30.1.*',
  mm.braces('10.{33..35}.*.*'),
  '172.22.224.*',
  '172.22.228.*',
]; 

const excludedServerIP = [
  '10.33.20.*',
];


const isServerIP = function (ip) {
  return mm.isMatch(ip, serverIP) && !mm.isMatch(ip, excludedServerIP);
};

module.exports = {
  isServerIP,
}; 
