"""Offline regression tests for 0.2.1; no external VPN or scan target used."""
import contextlib
import errno
import io
import ipaddress
from pathlib import Path
import socket
import struct
import sys
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'l2tp_ipsec_client'))
import vpn_tools as t
from test_main import m, data, Base


class ModeTests(Base):
    def test_adapter_optional_only_in_test_and_discovery(self):
        for mode in ('vpn_test', 'discover'):
            c = m.Config.load(data(connection_mode=mode, adapter_ip='',
                                   discovery_networks=['192.168.50.0/24']))
            self.assertEqual(c.adapter, '')
        with self.assertRaises(m.ConfigError):
            m.Config.load(data(adapter_ip=''))

    def test_old_fake_adapter_ignored(self):
        c = m.Config.load(data(connection_mode='vpn_test', adapter_ip='not-an-ip'))
        self.assertEqual(c.target_networks(), ())

    def test_unknown_mode_rejected(self):
        with self.assertRaises(m.ConfigError):
            m.Config.load(data(connection_mode='auto-all-networks'))

    def test_discovery_requires_scope(self):
        with self.assertRaises(m.ConfigError):
            m.Config.load(data(connection_mode='discover', adapter_ip=''))

    def test_discovery_server_collision(self):
        with self.assertRaises(m.ConfigError):
            m.Config.load(data(connection_mode='discover', vpn_server='192.168.50.1',
                               discovery_networks=['192.168.50.0/24']))

    def test_discovery_cannot_overlap_docker(self):
        c = m.Config.load(data(connection_mode='discover', discovery_networks=['172.30.32.0/23']))
        with self.assertRaises(m.ConfigError):
            m.check_subnet_conflict(c, [{'ifname':'eth0','addr_info':[
                {'family':'inet','local':'172.30.33.20','prefixlen':23}]}])

    def test_test_mode_creates_no_target_route(self):
        c = m.Config.load(data(connection_mode='vpn_test'))
        commands = m.route_commands(c, '10.20.30.4', 1400)
        self.assertEqual(len(commands), 2)
        self.assertFalse(any('route' in command for command in commands))

    def test_only_explicit_networks_routed(self):
        c = m.Config.load(data(connection_mode='discover', discovery_networks=['192.168.50.0/24']))
        commands = m.route_commands(c, '10.20.30.4', 1400)
        self.assertIn('192.168.50.0/24', commands[-1])
        self.assertNotIn('default', repr(commands))

    def test_trace_is_opt_in(self):
        c = m.Config.load(data())
        self.assertFalse(c.ike_trace)
        runner=mock.Mock()
        self.assertIsNone(m.start_ike_trace(c, runner))
        runner.command.assert_not_called()

    def test_trace_permission_error_does_not_disable_vpn(self):
        c=m.Config.load(data(ike_trace=True))
        runner=mock.Mock()
        runner.command.return_value.stdout='[{"dev":"eth0","prefsrc":"172.30.33.4"}]'
        with mock.patch.object(m,'IKETrace',side_effect=PermissionError(errno.EPERM,'denied')):
            self.assertIsNone(m.start_ike_trace(c,runner))
        self.assertIn('IKE_TRACE_UNAVAILABLE',str(runner.logger.log.call_args_list))

    def test_vpn_test_success_never_proxies_or_scans(self):
        cfg=m.Config.load(data(connection_mode='vpn_test'))
        engine=mock.Mock()
        engine.up={'address':'10.1.2.3','mtu':1400}
        runner=mock.Mock()
        with mock.patch.object(m,'VPNProcess',return_value=engine), \
             mock.patch.object(m,'Proxy') as proxy, \
             mock.patch.object(m,'scan_networks') as scan:
            m.vpn_cycle(cfg,runner)
        engine.close.assert_called_once()
        proxy.assert_not_called();scan.assert_not_called()
        self.assertIn('VPN_TEST_OK',str(runner.logger.log.call_args_list))

    def test_ike_failure_never_scans(self):
        cfg=m.Config.load(data(connection_mode='discover',discovery_networks=['192.168.50.0/24']))
        engine=mock.Mock()
        engine.check.side_effect=RuntimeError('l2tp: IKE: exchange timed out')
        with mock.patch.object(m,'VPNProcess',return_value=engine),mock.patch.object(m,'scan_networks') as scan:
            with self.assertRaisesRegex(RuntimeError,'timed out'):
                m.vpn_cycle(cfg,mock.Mock())
        scan.assert_not_called();engine.close.assert_called_once()

    def test_discovery_after_routes_and_no_proxy(self):
        cfg=m.Config.load(data(connection_mode='discover',discovery_networks=['192.168.50.0/24']))
        engine=mock.Mock();engine.up={'address':'10.1.2.3','mtu':1400}
        runner=mock.Mock()
        def check_order(*args,**kwargs):
            self.assertTrue(any('192.168.50.0/24' in str(c) and 'replace' in str(c)
                                for c in runner.command.call_args_list))
            return []
        with mock.patch.object(m,'VPNProcess',return_value=engine), \
             mock.patch.object(m,'scan_networks',side_effect=check_order) as scan, \
             mock.patch.object(m,'Proxy') as proxy:
            m.vpn_cycle(cfg,runner)
        scan.assert_called_once();proxy.assert_not_called();engine.close.assert_called_once()


class ScopeTests(unittest.TestCase):
    def test_maximum_and_large_ranges(self):
        self.assertEqual(t.discovery_networks(['192.168.0.0/22'])[0].num_addresses,1024)
        for value in (['10.0.0.0/8'],['192.168.0.0/21'],['0.0.0.0/0'],['8.8.8.0/24'],
                      ['127.0.0.0/24'],['169.254.0.0/24'],['192.168.0.1/24'],[],
                      ['192.168.0.0/24','192.168.0.128/25'],['192.168.0.1'],['::/0']):
            with self.subTest(value=value),self.assertRaises(ValueError):
                t.discovery_networks(value)

    def test_small_authorized_ranges(self):
        for value in ['192.168.1.2/32','10.0.0.0/24','172.16.0.0/24','100.64.1.0/24']:
            self.assertEqual(len(t.discovery_networks([value])),1)

    def test_total_network_limit(self):
        with self.assertRaises(ValueError):
            t.discovery_networks(['10.0.0.0/22','10.0.4.0/24'])

    def test_port_validation(self):
        self.assertEqual(t.discovery_ports([9999,80,9999]),(9999,80))
        for values in ([],[True],[0],[65536],['80'],list(range(1,10))):
            with self.subTest(values=values),self.assertRaises(ValueError):
                t.discovery_ports(values)


class ScanTests(unittest.TestCase):
    def test_only_explicit_target_and_no_extra_probes(self):
        log=mock.Mock();check=mock.Mock();probe=mock.Mock(return_value='open')
        hits=t.scan_networks(t.discovery_networks(['192.168.50.60/32']), (9999,),
                             '10.20.1.3','c6vpn0',threading.Event(),log,check,prober=probe)
        probe.assert_called_once_with('192.168.50.60',9999,'10.20.1.3','c6vpn0',1.0)
        self.assertEqual(hits[0]['open'],[9999])
        self.assertIn('C6_CANDIDATE',str(log.call_args_list))

    def test_skips_assigned_ip(self):
        probe=mock.Mock()
        hits=t.scan_networks(t.discovery_networks(['192.168.50.60/32']), (9999,),
                             '192.168.50.60','c6vpn0',threading.Event(),mock.Mock(),mock.Mock(),prober=probe)
        self.assertEqual(hits,[]);probe.assert_not_called()

    def test_stopped_scan_never_connects(self):
        event=threading.Event();event.set();probe=mock.Mock()
        t.scan_networks(t.discovery_networks(['192.168.50.60/32']), (9999,),
                        '10.20.1.3','c6vpn0',event,mock.Mock(),mock.Mock(),prober=probe)
        probe.assert_not_called()

    def test_vpn_failure_never_falls_back(self):
        probe=mock.Mock();check=mock.Mock(side_effect=RuntimeError('VPN down'))
        with self.assertRaisesRegex(RuntimeError,'VPN down'):
            t.scan_networks(t.discovery_networks(['192.168.50.60/32']), (9999,),
                            '10.20.1.3','c6vpn0',threading.Event(),mock.Mock(),check,prober=probe)
        probe.assert_not_called()

    def test_tcp_response_is_not_a_c6_identity(self):
        hits=t.scan_networks(t.discovery_networks(['192.168.50.60/32']), (80,),
                             '10.20.1.3','c6vpn0',threading.Event(),mock.Mock(),mock.Mock(),
                             prober=mock.Mock(return_value='refused'))
        self.assertEqual(hits[0]['open'],[]);self.assertEqual(hits[0]['refused'],[80])

    def test_socket_bind_before_connect_no_application_bytes(self):
        sock=mock.MagicMock();sock.__enter__.return_value=sock
        with mock.patch.object(t.socket,'socket',return_value=sock):
            self.assertEqual(t.probe_tcp('192.168.50.60',9999,'10.20.1.3','c6vpn0',1.0),'open')
        calls=sock.mock_calls
        self.assertLess(calls.index(mock.call.bind(('10.20.1.3',0))),calls.index(mock.call.connect(('192.168.50.60',9999))))
        sock.send.assert_not_called();sock.sendall.assert_not_called()

    def test_bind_failure_propagates_without_connect(self):
        sock=mock.MagicMock();sock.__enter__.return_value=sock
        sock.setsockopt.side_effect=PermissionError(errno.EPERM,'denied')
        with mock.patch.object(t.socket,'socket',return_value=sock),self.assertRaises(PermissionError):
            t.probe_tcp('192.168.50.60',9999,'10.20.1.3','c6vpn0',1)
        sock.connect.assert_not_called()

    def test_connection_refused_and_timeout(self):
        for error,expected in ((ConnectionRefusedError(errno.ECONNREFUSED,'refused'),'refused'),
                               (socket.timeout(),'no_response')):
            sock=mock.MagicMock();sock.__enter__.return_value=sock;sock.connect.side_effect=error
            with mock.patch.object(t.socket,'socket',return_value=sock):
                self.assertEqual(t.probe_tcp('192.168.50.60',9999,'10.20.1.3','c6vpn0',1),expected)


def ike_packet(*,direction='TX',natt=False,cookie=b'12345678',version=0x10,
               exchange=2,encrypted=False,payload=b'',first=1):
    server='203.0.113.15';local='172.30.33.3'
    ike=cookie+b'abcdefgh'+bytes([first,version,exchange,int(encrypted)])+b'\0'*4+struct.pack('!I',28+len(payload))+payload
    if natt:ike=b'\0'*4+ike
    port=4500 if natt else 500
    src,dst=(local,server) if direction=='TX' else (server,local)
    sport,dport=(51234,port) if direction=='TX' else (port,51234)
    udp=struct.pack('!HHHH',sport,dport,8+len(ike),0)+ike
    ip=bytes([0x45,0])+struct.pack('!H',20+len(udp))+b'\0'*4+bytes([64,17])+b'\0'*2+socket.inet_aton(src)+socket.inet_aton(dst)
    return ip+udp


class IKEParserTests(unittest.TestCase):
    def test_tx_and_rx_headers(self):
        for direction in ('TX','RX'):
            info=t.parse_ike_packet(ike_packet(direction=direction),'203.0.113.15')
            self.assertEqual(info['direction'],direction);self.assertEqual(info['exchange'],2)

    def test_natt_encrypted_header(self):
        info=t.parse_ike_packet(ike_packet(natt=True,encrypted=True,first=5),'203.0.113.15')
        self.assertEqual(info['dport'],4500);self.assertTrue(info['encrypted'])

    def test_other_server_and_wrong_ike_version_ignored(self):
        self.assertIsNone(t.parse_ike_packet(ike_packet(),'198.51.100.1'))
        self.assertIsNone(t.parse_ike_packet(ike_packet(version=0x20),'203.0.113.15'))

    def test_truncated_packets_never_crash(self):
        packet=ike_packet(natt=True)
        for n in range(len(packet)):
            self.assertIsNone(t.parse_ike_packet(packet[:n],'203.0.113.15'))

    def test_fragments_and_bad_lengths_ignored(self):
        for pos,value in ((6,0x20),(2,0xff),(0,0x40),(24,0xff),(16,0xff)):
            packet=bytearray(ike_packet());packet[pos]=value
            self.assertIsNone(t.parse_ike_packet(bytes(packet),'203.0.113.15'))

    def test_esp_not_logged(self):
        packet=bytearray(ike_packet(natt=True));packet[28]=0x55
        self.assertIsNone(t.parse_ike_packet(bytes(packet),'203.0.113.15'))

    def trace(self):
        trace=t.IKETrace.__new__(t.IKETrace)
        trace.cookies=set();trace.counts={'TX':0,'RX':0};trace.rx4500=0;trace.last=None
        trace.log=mock.Mock();trace.error=None
        return trace

    def test_cookie_correlation(self):
        trace=self.trace()
        trace.record(t.parse_ike_packet(ike_packet(),'203.0.113.15'))
        trace.record(t.parse_ike_packet(ike_packet(direction='RX',cookie=b'87654321'),'203.0.113.15'))
        self.assertEqual(trace.counts,{'TX':1,'RX':0})
        trace.record(t.parse_ike_packet(ike_packet(direction='RX'),'203.0.113.15'))
        self.assertEqual(trace.counts,{'TX':1,'RX':1})

    def test_no_payload_or_cookie_logging(self):
        trace=self.trace()
        trace.record(t.parse_ike_packet(ike_packet(payload=b'SECRET-PSK-AND-IDENTITY'),'203.0.113.15'))
        text=str(trace.log.call_args_list)
        for sensitive in ('SECRET','12345678','abcdefgh'):
            self.assertNotIn(sensitive,text)
        self.assertIn('IKE_TX',text)

    def test_trace_logs_are_bounded(self):
        trace=self.trace();info=t.parse_ike_packet(ike_packet(),'203.0.113.15')
        for _ in range(100):trace.record(info)
        self.assertEqual(trace.log.call_count,48)
        self.assertEqual(trace.counts['TX'],100)


if __name__=='__main__':unittest.main()
