#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cmd
from binascii import crc32, a2b_hex, b2a_hex, hexlify
import socket
from os import path
import struct


def make_tlv(tag, val):
    b = bytearray(tag)
    if len(val) < 127:
        b += bytes([len(val)])
    else:
        sz = len(val)
        i = 0
        while int(sz):
            sz /= 256
            i += 1
        sz = i
        b += bytes([0x80 + sz])
        for i in range(sz):
            b += bytes([len(val) >> ((sz - 1 - i) * 8) & 0xff])
    return b + val


def break_tlv(data):
    sz = 0
    tag = bytes([data[0]])
    if data[1] & 0x80:
        # FIXME !!!
        sz_len = (data[1] & 0x7f)
        sz = data[2]
        for i in range(1, sz_len):
            sz = sz << 8 + data[2 + i]
        value = data[sz_len + 2: sz_len + 2 + sz]
    else:
        sz = 1
        value = bytes(data[2: 2 + data[1]])
    return tag, value


class Packet:
    def __init__(self):
        self.count = 0

    def encode(self, tlv):
        self.count += 1
        arr = self.count.to_bytes(2, 'big')
        tlv = arr + tlv
        tlv = make_tlv([0x80], tlv + crc32(tlv).to_bytes(4, 'big'))
        return self._stuff(tlv)

    def decode(self, data):
        return self._unstuff(data)

    def _stuff(self, tlv):
        ba = bytearray()
        ba += bytes([0xC0])
        for b in tlv:
            if b == 0xC0:
                ba += bytes([0xDB, 0xDC])
            elif b == 0xDB:
                ba += bytes([0xDB, 0xDD])
            else:
                ba += bytes([b])
        ba += bytes([0xC0])
        return ba

    def _unstuff(self, data):
        ba = bytearray()
        db = False
        for b in data:
            if b == 0xC0:
                db = False
                continue
            elif b == 0xDB:
                db = True
                continue
            elif b == 0xDC and db:
                ba += bytes([0xC0])
                db = False
            elif b == 0xDD and db:
                ba += bytes([0xDB])
                db = False
            else:
                if db:
                    ba += bytes([0xDB])
                    db = False
                ba += bytes([b])
        return ba


class MyException(BaseException):
    pass


class Command(cmd.Cmd):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    packet = Packet()
    host = '192.168.0.3'
    # host = '10.0.40.177'
    port = 1234
    debug = 0
    value = bytearray()
    status_names = ('Waiting for input', 'Running',
        'Input disappeared waiting', 'Frequency too large',
        'Frequency too small')

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.modes = self._modes()

    def do_help(self, rest):
        rest = rest.split()
        if rest == []:
            print('Command list:')
            print('exit - program exit')
            print('debug [0|1] - get/set debug mode')
            print('host [X.X.X.X] - get/set host')
            print('upgrade <file_name> - firmware upgrade')
            print('help <cmd> - command help')
            print('devmode - чтение/запись режима работы '),
            print('aux - чтение/запись режима работы светодиода, динамика, согласователей')
            print('output - чтение/запись параметров выходов'),
            print('controller - чтение/запись параметров регулятора')
            print('network - чтение/запись параметров внутренней сети ethernet')
            print('version - чтение s/n и версии прошивки')
            print('restart - перезапуск платы')
            print('factory - чтение/запись заводских настроек')
            print('ptp - чтение состояния PTP')
            print('tlv - send TLV')
        elif len(rest) == 1:
            cmd  = rest[0]
            if cmd == 'devmode':
                print('devmode ([r] | w <mode>)')
                print('<mode> - 0..47')
                print('0,1     - off-line')
                print('2       - PTP-client')
                print('3..10   - 1Hz (positive|negative) (input1|input2) (stable|unstable)')
                print('11      - 50Hz input3')
                print('12..17  - 5MHz (positive|negative) (input1|input2|input4)')
                print('18..23  - 10MHz (positive|negative) (input1|input2|input4)')
                print('24..29  - 20MHz (positive|negative) (input1|input2|input4)')
                print('30..35  - 5MHz (positive|negative) (input1|input2|input4) without compensation')
                print('36..41  - 10MHz (positive|negative) (input1|input2|input4) without compensation')
                print('42..47  - 20MHz (positive|negative) (input1|input2|input4) without compensation')
            elif cmd == 'aux':
                print('aux ([r] | w <led> <speaker> <input adapter 1> <input adapter 2> <PoE>)')
                print('<led> 0 - 0 (default 1Hz 100ms)/1 (on)/2 (off)')
                print('<speaker> - 0 (default 1Hz 100ms)/ 1 (on)/ 2 (off)')
                print('<input adapter1> - 0 (off)/1 (on)')
                print('<input adapter2> - 0 (off)/1 (on)')
                print('<PoE> - 0 (off)/1 (on)')
            elif cmd == 'output':
                print('output ([r] <N>|w <N> <output-mode> <frequency Hz> <impulse duration s> <pulse delay s>)')
                print('<N> - output number 1..4')
                print('output-mode - 0 (off 0)/1 (off 1)/2 (active)/3 (active and inversion)')
            elif cmd == 'controller':
                print('controller ([r] <index> | d <index> | w <index> <par1> .. <par8>)')
                print('<index> - 0(1Hz stable)/1(1Hz unstable)/2(50Hz)/3(5MHz)/4(10MHz)/5(20MHz)/6(PTP)')
            elif cmd == 'network':
                print('network ([r] | w <ip-address> <mask> <gateway>)')
                print('need \'restart\' to apply')
            elif cmd == 'version':
                print('serial number and version info')
            elif cmd == 'restart':
                print('restart <mode>')
                print('<mode> - 0..47  см. help devmode')
            elif cmd == 'factory':
                print('factory ([r] | w <serial number>)')
            elif cmd == 'ptp':
                print('ptp')
            elif cmd == 'tlv':
                print('tlv <tag> [<data>]')

    def _modes(self):
        arr = []
        arr.append('off-line')
        arr.append('off-line')
        arr.append('PTP-client')
        for state in ('stable', 'unstable'):
            for inp in ('input1', 'input2'):
                for sign in ('positive', 'negative'):
                    arr.append('1Hz {} {} {}'.format(sign, inp, state))
        arr.append('50Hz input3')
        for inp in ('input1', 'input2', 'input4'):
            for sign in ('positive', 'negative'):
                arr.append('5MHz {} {}'.format(sign, inp))
        for inp in ('input1', 'input2', 'input4'):
            for sign in ('positive', 'negative'):
                arr.append('10MHz {} {}'.format(sign, inp))
        for inp in ('input1', 'input2', 'input4'):
            for sign in ('positive', 'negative'):
                arr.append('20MHz {} {}'.format(sign, inp))
        for inp in ('input1', 'input2', 'input4'):
            for sign in ('positive', 'negative'):
                arr.append('5MHz {} {} without compensation'.format(sign, inp))
        for inp in ('input1', 'input2', 'input4'):
            for sign in ('positive', 'negative'):
                arr.append('10MHz {} {} without compensation'.format(sign, inp))
        for inp in ('input1', 'input2', 'input4'):
            for sign in ('positive', 'negative'):
                arr.append('20MHz {} {} without compensation'.format(sign, inp))
        return arr

    def _mode_name(self, v):
        if v >= 0 and v < len(self.modes):
            return self.modes[v]
        elif v == 254:
            return 'service (BIOS)'
        elif v == 255:
            return 'firmware upgrade'
        else:
            return 'unknown'

    def _print_result(self, tag, value):
        res = None
        try:
            if tag[0] == 0x32:
                res = ('Fail', 'Ok')[value[0]]
            elif tag[0] == 0x31:
                res = value.decode()
        except:
            pass
        if res:
            print(res)
        else:
            print('tag=', b2a_hex(tag), ' value=', b2a_hex(value))

    def _reopen_socket(self):
        self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5.0)

    def _send_tlv(self, tag, data):
            tlv = make_tlv(tag, data)
            # print(b2a_hex(tlv))
            msg = self.packet.encode(tlv)
            if self.debug:
                print('To send: ', b2a_hex(msg))
            self.sock.sendto(msg, (self.host, self.port))
            if self.debug:
                print('Server reply :')
            while True:
                reply = self.sock.recv(4096)
                # print(b2a_hex(reply))
                reply = self.packet.decode(bytes(reply))
                if self.debug:
                    print(b2a_hex(reply))
                rtag, value = break_tlv(reply)
                if rtag[0] != 0x81:
                    raise MyException('Unknown tag ' + b2a_hex(tag).decode())
                # strip packet order number and crc
                rtag, value = break_tlv(bytes(value[2:-4]))
                if rtag == tag or rtag[0] in (0x31, 0x32):
                    if self.debug:
                        print('tag=', b2a_hex(rtag), ' value=', b2a_hex(value))
                    break
            return rtag, value

    def do_tlv(self, rest):
        try:
            p = rest.split()
            if len(p) > 1:
                tag, value = self._send_tlv(bytes(a2b_hex(p[0])),
                                            bytes(a2b_hex(p[1])))
            else:
                tag, value = self._send_tlv(bytes(a2b_hex(p[0])), b'')

            self.value = value
            # print(b2a_hex(tag), b2a_hex(value))
        except IndexError:
            print('*** error paremeters')
        except ValueError:
            print('*** value error')
        except MyException as e:
            print(e)
            self._reopen_socket()
        except socket.timeout:
            print('*** timeout')

    def do_utf8(self, rest):
        print(self.value.decode())

    def do_upgrade(self, rest):
        try:
            sz = path.getsize(rest)
            if sz != 768 * 1024:
                raise MyException('Bad file size:' + sz)
            print('read device mode ...')
            tag, value = self._send_tlv(bytes([0xC7]), bytes())
            if tag[0] != 0xC7:
                raise MyException('Read deviceMode failed!')
            mod = int(value[0])
            if mod == 0xFF:
                raise MyException('The device is already in firmware update mode!')
            if mod == 0xFE:
                # service mode
                print('clear all firmware ...')
                tag, value = self._send_tlv(bytes([0xF4]), bytes([0]))
                if tag[0] != 0xF4 or value[0] != 1:
                    raise MyException('Clear all firmware failed!')
                self._send_tlv(bytes([0xF3]), bytes([0]))

            # reset last upgrade
            print('clear last firmware ...')
            tag, value = self._send_tlv(bytes([0xF1]), bytes([0]))
            if tag[0] != 0xF1 or value[0] != 1:
                raise MyException('Reset firmware failed!')
            i = 0
            print('write firmware ...')
            with open(rest, 'rb') as fw:
                buf = fw.read(1024)
                while buf:
                    tag, value = self._send_tlv(bytes([0xF2]), buf)
                    if tag[0] != 0xF2 or value[0] != 1:
                        raise MyException("Write firmware failed!")
                    buf = fw.read(1024)
                    print(i)
                    i += 1

            print('reset device ...')
            tag, value = self._send_tlv(bytes([0xF3]), bytes([0]))

        except FileNotFoundError as e:
            print(e)
        except MyException as e:
            print(e)
            self._reopen_socket()
        except (ValueError or IndexError) as e:
            print(e)
        except socket.timeout:
            print('*** timeout')

    def do_exit(self, rest):
        return True

    def do_debug(self, rest):
        '''
        debug [0|1]
        '''
        rest = rest.split()
        if not rest:
            print('debug =', self.debug)
        elif len(rest) == 1 and rest[0] in ('0', '1'):
            self.debug = int(rest[0])
            print('debug =', self.debug)
        else:
            print('wrong parameters!')

    def do_host(self, rest):
        '''
        host [X.X.X.X] - get/set host
        '''
        rest = rest.split()
        if not rest:
            print('host =', self.host)
        elif len(rest) == 1:
            self.host = rest[0]
            print('host =', self.host)
        else:
            print('wrong parameters!')

    def do_devmode(self, rest):
        '''
        devmode ([r] | w <mode>)
        '''
        rest = rest.split()
        data = bytearray()
        if not rest or (len(rest) == 1 and rest[0] == 'r'):
            try:
                tag, value = self._send_tlv(bytes([0xC7]), data)
                mod = int(value[0])
                st = int(value[1])
                wt = struct.unpack('<I', value[2:])[0]
                print('Mode: ({}) {}'.format(mod, self._mode_name(mod)))
                try:
                    print('Status: ({}) {}'.format(st, self.status_names[st]))
                except IndexError:
                    print('Status: ({}) {}'.format(st, 'unknown'))
                print('running time: {} s'.format(wt))

            except socket.timeout:
                print('*** timeout')
            return
        elif len(rest) == 2 and rest[0] == 'w':
            try:
                mode = int(rest[1])
            except ValueError as e:
                print('Wrong argument value: ', e)
                return
            if mode < 0 or mode > 47:
                print('Wrong mode num: ', mode)
                return
            print('Set mode: {}'.format(self._mode_name(mode)))
            data += mode.to_bytes(1, 'little')

            try:
                tag, value = self._send_tlv(bytes([0xC8]), data)
                self._print_result(tag, value)

            except socket.timeout:
                print('*** timeout')

        else:
            print('bad parameters!')

    def do_aux(self, rest):
        '''
        aux ([r] | w <led> <speaker> <input adapter 1> <input adapter 2> <PoE>)
        '''
        led_spk_nm = ('default 1Hz 100ms', 'on', 'off')
        others_nm = ('off', 'on')
        rest = rest.split()
        data = bytearray()
        if not rest or (len(rest) == 1 and rest[0] == 'r'):
            try:
                tag, value = self._send_tlv(bytes([0xB0]), data)
                led = int(value[0])
                spk = int(value[1])
                in1 = int(value[2])
                in2 = int(value[3])
                poe = int(value[4])
                try:
                    print('LED: ({}) {}'.format(led, led_spk_nm[led]))
                    print('speaker: ({}) {}'.format(spk, led_spk_nm[spk]))
                    print('input adapter 1: ({}) {}'.format(in1, others_nm[in1]))
                    print('input adapter 2: ({}) {}'.format(in2, others_nm[in2]))
                    print('PoE: ({}) {}'.format(poe, others_nm[poe]))
                except:
                    print('Parse error: tag=', b2a_hex(tag), 'value=', b2a_hex(value))

            except socket.timeout:
                print('*** timeout')
            return
        elif len(rest) == 6 and rest[0] == 'w':
            try:
                led = int(rest[1])
                spk = int(rest[2])
                in1 = int(rest[3])
                in2 = int(rest[4])
                poe = int(rest[5])
            except ValueError as e:
                print('Wrong argument value: ', e)
                return
            if led not in range(3):
                print('Wrong led value: ', led)
                return
            if spk not in range(3):
                print('Wrong speaker value: ', spk)
                return
            if in1 not in range(2):
                print('Wrong input 1 value: ', in1)
                return
            if in2 not in range(2):
                print('Wrong input 2 value: ', in2)
                return
            if poe not in range(2):
                print('Wrong poe value: ', poe)
                return
            print('Set aux:')
            print('led - ', led_spk_nm[led])
            print('speaker - ', led_spk_nm[spk])
            print('input adapter 1 - ', others_nm[in1])
            print('input adapter 2 - ', others_nm[in2])
            print('input adapter 2 - ', others_nm[in2])
            print('PoE - ', others_nm[poe])

            data += led.to_bytes(1, 'little')
            data += spk.to_bytes(1, 'little')
            data += in1.to_bytes(1, 'little')
            data += in2.to_bytes(1, 'little')
            data += poe.to_bytes(1, 'little')

            try:
                tag, value = self._send_tlv(bytes([0xB1]), data)
                self._print_result(tag, value)

            except socket.timeout:
                print('*** timeout')

        else:
            print('wrong arguments!')

    def do_output(self, rest):
        '''
        output ([r] <N>|w <N> <output-mode> <frequency Hz> <impulse duration s> <pulse delay s>)
        '''
        mode = ('off', 'off', 'active', 'active and inversion')
        rest = rest.split()
        data = bytearray()
        if len(rest) == 1 or (len(rest) == 2 and rest[0] == 'r'):


            try:
                if len(rest) == 1:
                    num = int(rest[0])
                else:
                    num = int(rest[1])
            except ValueError as e:
                print('wrong parameter:', e)

            if num not in range(1, 5):
                print('wrong number: ', num)
                return

            try:
                tag, value = self._send_tlv(bytes([0xA0 + (num - 1) * 2]), data)
                mod = int(value[0])
                freq, dur, delay, r_freq, r_dur, r_delay  = struct.unpack('<dddddd', value[1:])
                print('mode: ({}) {}'.format(mod, mode[mod]))
                print('frequency: ', freq, 'Hz')
                print('duration: ', dur, 's')
                print('delay: ', delay, 's')
                print('real frequency: ', r_freq, 'Hz')
                print('real duration: ', r_dur, 's')
                print('real delay: ', r_delay, 's')
            except socket.timeout:
                print('*** timeout')
            except:
                print('parser failed: tag=', b2a_hex(tag), 'value=', b2a_hex(value))
            return
        elif len(rest) == 6 and rest[0] == 'w':
            try:
                num = int(rest[1])
                mod = int(rest[2])
                freq = float(rest[3])
                dur = float(rest[4])
                delay = float(rest[5])
                if num not in range(1, 5):
                    raise ValueError(num)
                if mod not in range(0, len(mode)):
                    raise ValueError(mod)
                if freq < 0.:
                    raise ValueError(freq)
                if dur < 0.:
                    raise ValueError(dur)
                if delay < 0.:
                    raise ValueError(delay)
            except ValueError as e:
                print('Wrong argument value: ', e)
                return
            data += mod.to_bytes(1, 'little')
            data += struct.pack('<d', freq)
            data += struct.pack('<d', dur)
            data += struct.pack('<d', delay)

            try:
                tag, value = self._send_tlv(bytes([0xA1 + (num - 1) * 2]), data)
                self._print_result(tag, value)

            except socket.timeout:
                print('*** timeout')

        else:
            print('bad parameters!')

    def do_controller(self, rest):
        '''
        controller ([r] <index> | d <index> | w <index> <par1> .. <par8>)
        '''
        idx_nm = ('1Hz stable', '1Hz unstable', '50Hz', '5MHz', '10MHz', '20MHz', 'PTP-server')
        rest = rest.split()
        data = bytearray()
        if len(rest) == 1 or (len(rest) == 2 and rest[0] == 'r'):
            try:
                if len(rest) == 1:
                    idx = int(rest[0])
                else:
                    idx = int(rest[1])
            except ValueError as e:
                print('wrong parameter:', e)

            if idx not in range(7):
                print('wrong index: ', idx)
                return

            try:
                data += idx.to_bytes(1, 'little')
                tag, value = self._send_tlv(bytes([0xB2]), data)
                idx = int(value[0])
                print('idx: ({}) {}'.format(idx, idx_nm[idx]))
                if tag[0] == 0xB2:
                    pars = struct.unpack('<8f', value[1:33])
                    print(pars)
                    i = 0
                    for p in pars:
                        print('param[{}] = {}'.format(i, p))
                        i += 1
                else:
                    print('tag = ', b2a_hex(tag), ' value = ', b2a_hex(value))

            except socket.timeout:
                print('*** timeout')
            except:
                print('parser failed: tag=', b2a_hex(tag), 'value=', b2a_hex(value))
            return
        elif len(rest) == 10 and rest[0] == 'w':
            try:
                idx = int(rest[1])
                par = [float(v) for v in rest[2:]]
            except ValueError as e:
                print('Wrong argument value: ', e)
                return
            data += idx.to_bytes(1, 'little')
            data += struct.pack('<8d', par)

            try:
                tag, value = self._send_tlv(bytes([0xB3]), data)
                self._print_result(tag, value)
            except socket.timeout:
                print('*** timeout')

        elif len(rest) == 2 and rest[0] == 'd':
            try:
                idx = int(rest[1])
            except ValueError as e:
                print('Wrong argument value: ', e)
                return
            try:
                print('set default values for index:({})  {}'.format(idx, idx_nm[idx]))
                data += idx.to_bytes(1, 'little')
                tag, value = self._send_tlv(bytes([0xB4]), data)
                self._print_result(tag, value)

            except socket.timeout:
                print('*** timeout')

        else:
            print('bad parameters!')

    def do_network(self, rest):
        '''
        network ([r] | w <ip-address> <mask> <gateway>)
        '''
        rest = rest.split()
        data = bytearray()
        if not rest or (len(rest) == 1 and rest[0] == 'r'):
            try:
                tag, value = self._send_tlv(bytes([0xB6]), data)
                if len(value) != 12:
                    print('bad reply: tag=', b2a_hex(tag), ' value=', b2a_hex(value))
                    return
                ip = '{}.{}.{}.{}'.format(value[0], value[1], value[2], value[3])
                mask = '{}.{}.{}.{}'.format(value[4], value[5], value[6], value[7])
                gt = '{}.{}.{}.{}'.format(value[8], value[9], value[10], value[11])
                print('ip: {}'.format(ip))
                print('mask: {}'.format(mask))
                print('gateway: {}'.format(gt))

            except socket.timeout:
                print('*** timeout')
        elif len(rest) == 4 and rest[0] == 'w':
            try:
                ip = rest[1].split('.')
                ip = bytes([int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])])
                mask = rest[2].split('.')
                mask = bytes([int(mask[0]), int(mask[1]), int(mask[2]), int(mask[3])])
                gw = rest[3].split('.')
                gw = bytes([int(gw[0]), int(gw[1]), int(gw[2]), int(gw[3])])

            except (ValueError or IndexError) as e:
                print('Wrong argument value: ', e)
                return
            data += ip
            data += mask
            data += gw
            if len(data) != 12:
                print('wrong arguments')
                return

            try:
                tag, value = self._send_tlv(bytes([0xB7]), data)
                self._print_result(tag, value)

                tag, value = self._send_tlv(bytes([0xF3]), bytes([0x0]))

            except socket.timeout:
                print('*** timeout')

        else:
            print('bad parameters!')

    def do_version(self, rest):
        '''
        version
        '''
        rest = rest.split()
        data = bytearray()
        blk_nm = ('debug block or BIOS', 'normal first block', 'normal second block')
        if not rest:
            try:
                tag, value = self._send_tlv(bytes([0xF0]), data)
                try:
                    print('serial: ', struct.unpack('<H', value[:2])[0])
                    print('ver.: {}.{}.{}'.format(value[2], value[3], value[4]))
                    print('build: {}'.format(struct.unpack('<I', value[5:9])[0]))
                    print('cur block: ({}) {}'.format(value[9], blk_nm[value[9]]))
                    print('info string: ', value[10:].decode())

                except:
                    print('error to parse:', b2a_hex(value))
            except socket.timeout:
                print('*** timeout')
        else:
            print('bad parameters!')

    def do_restart(self, rest):
        '''
        restart
        '''
        rest = rest.split()
        if not rest:
            try:
                tag, value = self._send_tlv(bytes([0xF3]), bytes([0x0]))
                self._print_result(tag, value)
            except socket.timeout:
                print('*** timeout')
        else:
            print('bad parameters!')

    def do_factory(self, rest):
        '''
        factory ([r] | w <serial number>
        '''
        rest = rest.split()
        data = bytearray()
        if not rest or (len(rest) == 1 and rest[0] == 'r'):
            try:
                tag, value = self._send_tlv(bytes([0xF5]), data)
                if len(value) != 2:
                    print('bad reply: tag=', b2a_hex(tag), ' value=', b2a_hex(value))
                print('serial: ', struct.unpack('<H', value)[0])
            except socket.timeout:
                print('*** timeout')
        elif len(rest) == 2 and rest[0] == 'w':
            try:
                sn = struct.pack('<H', int(rest[1]))
            except (ValueError or IndexError) as e:
                print('Wrong argument value: ', e)
                return
            data += sn

            try:
                tag, value = self._send_tlv(bytes([0xF6]), data)
                self._print_result(tag, value)

            except socket.timeout:
                print('*** timeout')

        else:
            print('bad parameters!')

    def do_ptp(self, rest):
        '''
        ptp
        '''
        rest = rest.split()
        data = bytearray()
        if not rest:
            try:
                tag, value = self._send_tlv(bytes([0xD0]), data)
                try:
                    print('year: ', struct.unpack('<H', value[:2])[0])
                    print('month:', struct.unpack('<H', value[2:4][0]))
                    print('day:', struct.unpack('<H', value[4:6])[0])
                    print('hour:', struct.unpack('<H', value[6:8])[0])
                    print('minute:', struct.unpack('<H', value[8:10])[0])
                    print('second:', struct.unpack('<H', value[10:12])[0])
                    print('validity: ', value[12])
                    print('GPS sattelites: ', value[13])
                    print('GLONASS sattelites: ', value[14])
                    print('GPS sattelites status: ', struct.unpack('s', value[15:143]))
                    print('GLONASS sattelites status: ', struct.unpack('s', value[143:]))
                except:
                    print('error to parse:', b2a_hex(value))
            except socket.timeout:
                print('*** timeout')
        else:
            print('bad parameters!')



def main():
    Command().cmdloop()

if __name__ == '__main__':
    main()
