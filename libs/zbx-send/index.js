'use strict';

const ZabbixSender = require('node-zabbix-sender');

const proxy = {
  '0': '10.28.8.66',
  '10693': '10.27.0.252', // spy
  '11056': '10.19.251.108', // legency
  '11203': '10.21.251.26', // wan
  '11356': '10.19.251.107', // original
  '12054': '59.208.226.1', // shiyan
  '13521': '10.35.4.1', // coreapp
  '14123': '10.27.22.70', // outerapp
  '14125': '10.34.8.1', // coredata
  '14572': '10.28.8.65', // innerapp
  '15701': '10.19.253.20', // dataexchange
  '16339': '10.19.251.108', //management
};

module.exports = async function(proxyid, host, item, data) {
  const sender = new ZabbixSender({host: proxy[proxyid]});
  sender.addItem(host, item, data);
  return await new Promise((resolve, reject) => {
    sender.send((err, res) => {
      if (err) {
        reject(err);
      }
      resolve(res);
    });
  });
};
