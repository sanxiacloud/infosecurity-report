'use strict';

const ZabbixApi = require('ndzbx');

class ZabbixBuffer {
  constructor(usr, pwd, host, port, useSSL) {
    this.api = new ZabbixApi(usr, pwd, host, port, useSSL);
    this.hosts = {};
  }

  async getHostByIp(ip) {
    if (!this.hosts.hasOwnProperty(ip)) {
      const interfaces = await this.api.request('hostinterface.get', {
        filter: {ip},
        output: ['hostid'],
      });
      const hostinfos = [];
      const defers = interfaces.map(async (iface) => {
        const hosts = await this.api.request('host.get', {
          hostids: [iface.hostid],
          output: ['host', 'proxy_hostid'],
        });
        hosts.forEach((host) => {
          hostinfos.push({
            name: host.host,
            proxyid: host.proxy_hostid,
          });
        });
      });
      await Promise.all(defers);
      this.hosts[ip] = hostinfos;
    }
    return this.hosts[ip];
  }
}

module.exports = ZabbixBuffer;
