'use strict';

const Koa = require('koa');
const logger = require('koa-logger');
const Router = require('koa-router');

const server = new Koa();
const router = new Router();
// todo 如何传递splunk进来?
router.get('/csv', async (ctx) => {
  let alerts = [];
  try {
    alerts = await splunk.search(`index="user_index_yujie" message_type=sec
      asset IN ("*10.27.*.*", "*10.28.*.*", "*10.29.*.*", "*10.34.*.*", "*10.35.*.*")`
    , ['-1d@d', '@d']);
  } catch (err) {
    console.log(err);
  }
  const data = [['asset', 'time', 'name', 'type', 'attackStage', 'score']];
  alerts.forEach((alert) => {
    const result = alert.result;
    const detail = result._raw.detail;
    data.push([result.asset, result._time, detail.name, detail.type, detail.attackStage, detail.score]);
  });
  const strings = [];
  data.forEach(async (row)=> {
    if (row[2] == '内网用户频繁访问445端口（每分钟超100次）' && row[0].includes('10.33.18.')) {
      return;
    }
    strings.push(`"${row[0]}", "${row[1]}", "${row[2]}", "${row[3]}", "${row[4]}", "${row[5]}"`);
  });
  const buf = iconv.encode(strings.join('\n'), 'gbk');
  const filename = `yujie-${moment().subtract(1, 'd').format('YYYY-MM-DD')}.csv`;
  ctx.attachment(filename);
  ctx.body = buf;
});

server.use(logger())
    .use(router.routes())
    .use(router.allowedMethods());

module.exports = server;
