import { expect, test } from 'vitest';
import {
    Resolver,
} from 'node:dns/promises';

test('Sample test to verify test runner setup', async () => {
    const resolver = new Resolver();
    resolver.setServers(['1.1.1.1']);
    await expect(resolver.resolve4('example.com')).resolves.toBeDefined();
});

/*
services:
  # mDNS advertiser 1 - Simple hostname
  mdns-host1:
    image: alpine:latest
    hostname: test-host1
    container_name: mdns-host1
    networks:
      mdns-net:
        ipv4_address: 172.20.0.10
    command: >
      sh -c "
        apk add --no-cache avahi avahi-tools dbus &&
        mkdir -p /var/run/dbus &&
        dbus-daemon --system &&
        avahi-daemon --daemonize &&
        sleep 2 &&
        avahi-publish -a test-host1.local 172.20.0.10 &
        tail -f /dev/null
      "

  # mDNS advertiser 2 - HTTP service
  mdns-http-service:
    image: alpine:latest
    hostname: web-server
    container_name: mdns-http-service
    networks:
      mdns-net:
        ipv4_address: 172.20.0.11
    command: >
      sh -c "
        apk add --no-cache avahi avahi-tools dbus &&
        mkdir -p /var/run/dbus &&
        dbus-daemon --system &&
        avahi-daemon --daemonize &&
        sleep 2 &&
        avahi-publish -s WebServer _http._tcp 80 &
        avahi-publish -a web-server.local 172.20.0.11 &
        tail -f /dev/null
      "

  # mDNS advertiser 3 - SSH service
  mdns-ssh-service:
    image: alpine:latest
    hostname: ssh-server
    container_name: mdns-ssh-service
    networks:
      mdns-net:
        ipv4_address: 172.20.0.12
    command: >
      sh -c "
        apk add --no-cache avahi avahi-tools dbus &&
        mkdir -p /var/run/dbus &&
        dbus-daemon --system &&
        avahi-daemon --daemonize &&
        sleep 2 &&
        avahi-publish -s SSHServer _ssh._tcp 22 &
        avahi-publish -a ssh-server.local 172.20.0.12 &
        tail -f /dev/null
      "

  # mDNS advertiser 4 - Multiple services
  mdns-multi-service:
    image: alpine:latest
    hostname: multi-server
    container_name: mdns-multi-service
    networks:
      mdns-net:
        ipv4_address: 172.20.0.13
    command: >
      sh -c "
        apk add --no-cache avahi avahi-tools dbus &&
        mkdir -p /var/run/dbus &&
        dbus-daemon --system &&
        avahi-daemon --daemonize &&
        sleep 2 &&
        avahi-publish -a multi-server.local 172.20.0.13 &
        avahi-publish -s MultiHTTP _http._tcp 8080 &
        avahi-publish -s MultiFTP _ftp._tcp 21 &
        tail -f /dev/null
      "
      */

const mdnsProxyResolver = new Resolver();
mdnsProxyResolver.setServers(['172.20.0.5:5335']);

// Wait for mdnsProxyResolver to be up
let timeout = 10;
while (timeout-- > 0) {
    try {
        await mdnsProxyResolver.resolve4('test-host1.local');
        break;
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ECONNREFUSED') {
            await new Promise((resolve) => setTimeout(resolve, 1000));
        } else {
            break;
        }
    }
}

test('mDNS ipv4 hostname resolution', async () => {
    await expect(mdnsProxyResolver.resolve4('test-host1.local')).resolves.toEqual(['172.20.0.10']);
    await expect(mdnsProxyResolver.resolve4('web-server.local')).resolves.toEqual(['172.20.0.11']);
    await expect(mdnsProxyResolver.resolve4('ssh-server.local')).resolves.toEqual(['172.20.0.12']);
    await expect(mdnsProxyResolver.resolve4('multi-server.local')).resolves.toEqual(['172.20.0.13']);
});

test('mDNS service SRV record resolution', async () => {
    await expect(mdnsProxyResolver.resolveSrv('_http._tcp.local')).resolves.toEqual([
        {
            name: 'web-server.local',
            port: 80,
            priority: 0,
            weight: 0,
        },
        {
            name: 'multi-server.local',
            port: 8080,
            priority: 0,
            weight: 0,
        },
    ]);

    await expect(mdnsProxyResolver.resolveSrv('_ssh._tcp.local')).resolves.toEqual([
        {
            name: 'ssh-server.local',
            port: 22,
            priority: 0,
            weight: 0,
        },
    ]);

    await expect(mdnsProxyResolver.resolveSrv('_ftp._tcp.local')).resolves.toEqual([
        {
            name: 'multi-server.local',
            port: 21,
            priority: 0,
            weight: 0,
        },
    ]);
});

test('mDNS non-existent hostname resolution', async () => {
    await expect(mdnsProxyResolver.resolve4('nonexistent.local')).rejects.toThrow();
});

test('mDNS non-existent service SRV record resolution', async () => {
    await expect(mdnsProxyResolver.resolveSrv('_nonexistent._tcp.local')).rejects.toThrow();
});

