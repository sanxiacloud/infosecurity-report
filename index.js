'use strict';

const moment = require('moment');
const Splunk = require('splunk');
const ZabbixBuffer = require('./libs/zbx-buf');
const zbxSend = require('./libs/zbx-send');
const es7 = require('es7');
const conf = require('./config');


const tools = {
  splunk: new Splunk(conf.splunk.usr, conf.splunk.pwd, conf.splunk.host),
  zbxBuffer: new ZabbixBuffer(conf.zabbix.usr, conf.zabbix.pwd, conf.zabbix.host, 0, true),
  zbxSend,
  esClient: new es7.Client({node: conf.es.node}),
};

const server = require('./tasks/web');
server.listen(3002);

const {task: yujietask} = require('./tasks/yujie');
yujietask(moment(), tools);

const {task: skyeyetask} = require('./tasks/skyeye');
skyeyetask(moment(), tools);
