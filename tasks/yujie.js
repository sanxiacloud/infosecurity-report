'use strict';

const moment = require('moment');

let timer;

async function task(earliest, tools) {
  let alerts = [];
  try {
    alerts = await tools.splunk.search(`index="user_index_yujie" message_type=sec
      asset IN ("*10.27.*.*", "*10.28.*.*", "*10.29.*.*", "*10.34.*.*", "*10.35.*.*")`
    , [earliest.format()]);
  } catch (err) {
    console.log(err);
  }
  let latest = earliest;
  alerts.forEach((alert)=>{
    const detail = alert.result._raw.detail;
    const current = moment(detail.time, 'YYYY-MM-DD HH:mm:ss.SSS');
    const data = {
      time: detail.time,
      attackStage: detail.attackStage,
      type: detail.type,
    };
    if (current.isAfter(latest)) {
      latest = current.add(1, 's');
    }
    const ips = alert.result.asset.split(';');
    console.log(ips);
    ips.forEach(async (ip) => {
      // 没有查到hostinfo时考虑使用默认host，顺便提示存在未监控主机
      console.log(ip);
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
