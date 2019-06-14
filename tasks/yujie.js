'use strict';

const moment = require('moment');

let timer;

async function task(earliest, tools) {
  let alerts = [];
  try {
    alerts = await tools.splunk.search(`index="user_index_yujie" message_type=sec
      asset IN ("*10.19.213.*", "*10.19.214.*", "*10.19.248.*", "*10.19.249.*", "*10.19.250.*", "*10.19.251.*", "*10.19.252.*", "*10.19.253.*", "*10.19.254.*", "*10.19.255.*", "*10.19.110.*", "*10.19.136.*", "*10.19.137.*", "*10.19.138.*", "*10.19.139.*", "*10.19.140.*", "*10.19.141.*", "*10.19.142.*", "*10.19.143.*", "*10.19.144.*", "*10.19.145.*", "*10.19.146.*", "*10.19.147.*", "*10.19.148.*", "*10.19.149.*", "*10.19.150.*", "*10.19.151.*", "*10.19.195.*", "*10.27.*.*", "*10.28.*.*", "*10.29.*.*", "*10.30.1.*", "*10.33.*.*", "*10.34.*.*", "*10.35.*.*", "*172.22.224.*", "*172.22.248.*")`
    , [earliest.format()]);
  } catch (err) {
    console.log(err);
  }
  let latest = earliest;
  alerts.forEach((alert)=>{
    const detail = alert.result._raw.detail;
    const current = moment(detail.time, 'YYYY-MM-DD HH:mm:ss.SSS');
    if (current.isAfter(latest)) {
      latest = current.add(1, 's');
    }
    if (detail.type == '入侵感知') {
      return;
    }
    const data = {
      time: detail.time,
      attackStage: detail.attackStage,
      type: detail.type,
    };
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
