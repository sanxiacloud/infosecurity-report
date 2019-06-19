'use strict';

const moment = require('moment');

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
                    {term: {'skyeye.alarm_sip': '10.19.213.0/24'}},
                    {term: {'skyeye.alarm_sip': '10.19.214.0/24'}},
                    {term: {'skyeye.alarm_sip': '10.19.248.0/21'}},
                    {term: {'skyeye.alarm_sip': '10.19.110.0/24'}},
                    {term: {'skyeye.alarm_sip': '10.19.136.0/21'}},
                    {term: {'skyeye.alarm_sip': '10.19.144.0/21'}},
                    {term: {'skyeye.alarm_sip': '10.19.195.0/24'}},
                    {term: {'skyeye.alarm_sip': '10.27.0.0/16'}},
                    {term: {'skyeye.alarm_sip': '10.28.0.0/16'}},
                    {term: {'skyeye.alarm_sip': '10.29.0.0/16'}},
                    {term: {'skyeye.alarm_sip': '10.30.1.0/24'}},
                    {term: {'skyeye.alarm_sip': '10.33.0.0/16'}},
                    {term: {'skyeye.alarm_sip': '10.34.0.0/16'}},
                    {term: {'skyeye.alarm_sip': '10.35.0.0/16'}},
                    {term: {'skyeye.alarm_sip': '172.22.224.0/24'}},
                    {term: {'skyeye.alarm_sip': '172.22.248.0/24'}},
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
            ],
            must_not: [
              {
                term: {'skyeye.host_state': '企图'},
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
  const defers = hits.map(async (hit)=> {
    const raw = hit._source;
    const current = moment(raw.syslog.timestamp);
    if (current.isAfter(latest)) {
      latest = current;
    }
    if (raw.skyeye.host_state == '攻击成功') {
      if (raw.skyeye.attack_sip.ip.indexOf('10') == 0 ) {
        return;
      }
      if (raw.skyeye.attack_sip.ip.indexOf('172.16') == 0 ) {
        return;
      }
      if (raw.skyeye.attack_sip.ip.indexOf('192.168') == 0 ) {
        return;
      }
      if ( raw.skyeye.hazard_level <= 3) {
        return;
      }
    }
    const data = {
      time: raw.skyeye.access_time,
      state: raw.skyeye.host_state,
      type: raw.skyeye.type,
    };
    const ip = raw.skyeye.alarm_sip;
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
    hostinfos.forEach(async (hostinfo) => {
      let result = {info: ''};
      try {
        result = await tools.zbxSend(hostinfo.proxyid, hostinfo.name, 'threat.detection.skyeye', JSON.stringify(data));
      } catch (err) {
        console.log(`host is ${JSON.stringify(hostinfo)}, error in send: ${err}`);
      }
      if (result.info.includes('failed: 1')) {
        console.log(`failed: ip is ${ip}`);
      }
    });
  });
  await Promise.all(defers);
  return latest;
}

async function run(earliest, tools) {
  console.log(`${moment().format()}: skyeye checking earliest ${earliest}`);
  const latest = await task(earliest, tools);
  console.log(`next skyeye earliest is at ${latest.format()}`);
  timer = setTimeout(run, 60*1000, latest, tools);
}

module.exports = {task: run, timer};


