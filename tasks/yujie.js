/* eslint-disable require-jsdoc */
'use strict';

const moment = require('moment');
const { isServerIP } = require('../libs/ip-filter');

let timer;

async function task(earliest, tools) {
  let response;
  let latest = earliest;
  const hits = [];
  try {
    response = await tools.esClient.search({
      index: 'syslog-search',
      body: {
        query: {
          bool: {
            filter: [
              {
                bool: {
                  should: [
                    {term: {'yujie.asset': '10.19.213.0/24'}},
                    {term: {'yujie.asset': '10.19.214.0/24'}},
                    {term: {'yujie.asset': '10.19.248.0/21'}},
                    {term: {'yujie.asset': '10.19.110.0/24'}},
                    {term: {'yujie.asset': '10.19.136.0/21'}},
                    {term: {'yujie.asset': '10.19.144.0/21'}},
                    {term: {'yujie.asset': '10.19.195.0/24'}},
                    {term: {'yujie.asset': '10.27.0.0/16'}},
                    {term: {'yujie.asset': '10.28.0.0/16'}},
                    {term: {'yujie.asset': '10.29.0.0/16'}},
                    {term: {'yujie.asset': '10.30.1.0/24'}},
                    {term: {'yujie.asset': '10.33.0.0/16'}},
                    {term: {'yujie.asset': '10.34.0.0/16'}},
                    {term: {'yujie.asset': '10.35.0.0/16'}},
                    {term: {'yujie.asset': '172.22.224.0/24'}},
                    {term: {'yujie.asset': '172.22.248.0/24'}},
                  ],
                },
              },
              {
                range: {
                  'syslog.timestamp': {
                    gt: earliest.format(),
                  },
                },
              },
              {
                'term': {
                  'yujie.message_type': 'sec',
                },
              },
            ],
            must_not: [
              {
                term: {'yujie.type': '入侵感知'},
              },
            ],
          },
        },
      },
      scroll: '10s',
      size: 1000,
    });
  } catch (err) {
    console.log(err);
    return;
  }
  hits.push(...response.body.hits.hits);
  while (hits.length < response.body.hits.total.value) {
    try {
      response = await tools.esClient.scroll({
        scroll_id: response.body._scroll_id,
        scroll: '10s',
      });
    } catch (err) {
      console.log(err);
      return;
    }
    hits.push(...response.body.hits.hits);
  }
  hits.map( (hit)=> {
    const raw = hit._source;
    const current = moment(raw.syslog.timestamp);
    if (current.isAfter(latest)) {
      latest = current;
    }
    const data = {
      time: raw.yujie.time,
      attackStage: raw.yujie.attackStage,
      type: raw.yujie.type,
    };
    raw.yujie.asset.forEach(async (ip) => {
      console.log(ip);
      if (!isServerIP(ip)) {
        console.log(`no server ip address ${ip}`);
        return;
      }
      let hostinfos = [];
      try {
        hostinfos = await tools.zbxBuffer.getHostByIp(ip);
      } catch (err) {
        console.log(`error in get host: ${err}`);
      }
      if (hostinfos.length == 0 ) {
        hostinfos = [{proxyid: '0', name: 'unmonitored-servers'}];
        data.address = ip;
      }
      console.log(hostinfos);
      hostinfos.forEach(async (hostinfo)=>{
        let result = {info: ''};
        try {
          result = await tools.zbxSend(hostinfo.proxyid, hostinfo.name, 'threat.detection.yujie', JSON.stringify(data));
        } catch (err) {
          console.log(`host is ${JSON.stringify(hostinfo)}, error in send: ${err}`);
        }
        if (result.info.includes('failed: 1')) {
          console.log(`failed: ip is ${ip}`);
        }
      });
    });
  });
  return latest;
}

async function run(earliest, tools) {
  console.log(`${moment().format()}: yujie checking earliest ${earliest}`);
  const latest = await task(earliest, tools);
  console.log(`next yujie earliest is at ${latest.format()}`);
  timer = setTimeout(run, 60*1000, latest, tools);
}

module.exports = {task: run, timer};
