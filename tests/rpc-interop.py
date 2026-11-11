#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent RPC/NDR32/NDR64 interoperability tests using an external client.

Impacket is a test-only dependency. Neither its code nor its runtime is linked
into ksmbd-tools. The fixture runs mountd's real RPC IPC entry points with
isolated users/shares; a kernel module and SMB server are not required.
"""
import argparse
import os
import random
import struct
import subprocess
import unittest
import uuid

from impacket.dcerpc.v5 import samr, lsad, lsat, srvs, wkst, dssp, transport
from impacket.dcerpc.v5.ndr import NULL
from impacket.uuid import uuidtup_to_bin

SYNTAXES = {
    'samr': ('12345778-1234-abcd-ef00-0123456789ac', '1.0'),
    'lsa': ('12345778-1234-abcd-ef00-0123456789ab', '0.0'),
    'dssetup': ('3919286a-b10c-11d0-9ba8-00c04fd92ef5', '0.0'),
    'srvsvc': ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0'),
    'wkssvc': ('6bffd098-a112-3610-9833-46c3f87e345a', '1.0'),
}
NDR32 = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
NDR64 = ('71710533-beba-4937-8319-b5dbef9ccc36', '1.0')
USER = 'user-0000-abcdefghijklmnopqrstuvwxyz'
SID = 'S-1-5-21-1-2-3'


class Pipe:
    def __init__(self, interface, bigendian=False):
        self.process = subprocess.Popen(
            [RPC_TEST, '--wire', 'lsa' if interface == 'dssetup' else interface],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.interface = interface
        self.endian = '>' if bigendian else '<'
        self.bigendian = bigendian
        self.fragments = 0

    def pack(self, fmt, *values):
        return struct.pack(self.endian + fmt, *values)

    def read(self, length):
        data = self.process.stdout.read(length)
        if len(data) != length:
            raise AssertionError('RPC fixture terminated unexpectedly')
        return data

    def transact(self, pdu=b''):
        self.process.stdin.write(struct.pack('<I', len(pdu)) + pdu)
        self.process.stdin.flush()
        status, length = struct.unpack('<II', self.read(8))
        reply = self.read(length)
        if status:
            raise AssertionError('IPC status %d, reply %s' % (status, reply.hex()))
        if reply and reply[2] == 2:
            self.fragments += 1
        return reply

    def pdu(self, ptype, body, flags=3):
        return bytes((5, 0, ptype, flags, 0 if self.bigendian else 16, 0, 0, 0)) + self.pack(
            'HHI', 16 + len(body), 0, 1) + body

    def request(self, opnum, stub, context=0):
        reply = b''
        for offset in range(0, max(1, len(stub)), 4000):
            chunk = stub[offset:offset + 4000]
            flags = (1 if offset == 0 else 0) | (2 if offset + len(chunk) == len(stub) else 0)
            reply = self.transact(self.pdu(0, self.pack('IHH', len(stub) - offset,
                                                      context, opnum) + chunk, flags))
            if not flags & 2:
                assert not reply
        if reply[2] != 2:
            return reply[2], reply[3], reply[24:]
        data = bytearray()
        while True:
            assert reply[2] == 2
            assert self.pack('H', len(reply)) == reply[8:10]
            data.extend(reply[24:])
            if reply[3] & 2:
                break
            assert (len(reply) - 24) % 8 == 0
            reply = self.transact()
        return 2, 3, bytes(data)

    def syntax(self, value):
        ident = uuid.UUID(value[0])
        major, minor = map(int, value[1].split('.'))
        return (ident.bytes if self.bigendian else ident.bytes_le) + self.pack('I', major | minor << 16)

    def bind(self, contexts, alter=False):
        body = self.pack('HHIB3x', 4096, 257, 0, len(contexts))
        for context, syntax in contexts:
            body += self.pack('HBB', context, 1, 0)
            body += self.syntax(SYNTAXES[self.interface]) + self.syntax(syntax)
        reply = self.transact(self.pdu(14 if alter else 11, body))
        assert reply[2] == (15 if alter else 12), reply.hex()
        address = struct.unpack(self.endian + 'H', reply[24:26])[0]
        offset = ((26 + address + 3) & ~3) + 4
        return [struct.unpack(self.endian + 'HH', reply[offset + i * 24:offset + i * 24 + 4])
                for i in range(len(contexts))]

    def close(self):
        self.process.stdin.close()
        self.process.stdout.close()
        if self.process.wait(timeout=10):
            raise AssertionError('RPC fixture failed during cleanup')


class WireTransport(transport.DCERPCTransport):
    def __init__(self, pipe):
        super().__init__('fixture', 0)
        self.pipe, self.pending = pipe, b''

    def connect(self):
        pass

    def disconnect(self):
        pass

    def send(self, data, **kwargs):
        assert not self.pending
        self.pending = self.pipe.transact(data)

    def recv(self, forceRecv=0, count=0):
        if self.pending:
            result, self.pending = self.pending, b''
            return result
        return self.pipe.transact()


class Interop(unittest.TestCase):
    def modes(self):
        return (False, True) if WITH_NDR64 else (False,)

    def require_ndr64(self):
        if not WITH_NDR64:
            self.skipTest('NDR64 build not requested')

    def client(self, interface, ndr64):
        pipe = Pipe(interface)
        self.addCleanup(pipe.close)
        dce = WireTransport(pipe).get_dce_rpc()
        dce.connect()
        dce.bind(uuidtup_to_bin(SYNTAXES[interface]), transfer_syntax=NDR64 if ndr64 else NDR32)
        return pipe, dce

    def raw(self, interface, ndr64=True, bigendian=False):
        pipe = Pipe(interface, bigendian)
        self.addCleanup(pipe.close)
        self.assertEqual(pipe.bind([(0, NDR64 if ndr64 else NDR32)]), [(0, 0)])
        return pipe

    def result(self, function, expected=0):
        try:
            packet = function()
        except (samr.DCERPCSessionError, lsad.DCERPCSessionError, lsat.DCERPCSessionError,
                srvs.DCERPCSessionError, wkst.DCERPCSessionError) as error:
            self.assertEqual(error.get_error_code(), expected)
            packet = error.get_packet()
        if 'ErrorCode' in packet.fields:
            self.assertEqual(packet['ErrorCode'], expected)
        return packet

    def test_samr(self):
        for ndr64 in self.modes():
            with self.subTest(ndr64=ndr64):
                pipe, dce = self.client('samr', ndr64)
                server = samr.hSamrConnect5(dce)['ServerHandle']
                self.assertGreater(samr.hSamrEnumerateDomainsInSamServer(dce, server)['CountReturned'], 0)
                sid = samr.hSamrLookupDomainInSamServer(dce, server, 'SERVER')['DomainId']
                self.assertEqual(sid.formatCanonical(), SID)
                domain = samr.hSamrOpenDomain(dce, server, domainId=sid)['DomainHandle']
                self.assertEqual(samr.hSamrEnumerateUsersInDomain(dce, domain)['CountReturned'], 1000)
                samr.hSamrEnumerateGroupsInDomain(dce, domain)
                samr.hSamrEnumerateAliasesInDomain(dce, domain)
                samr.hSamrLookupNamesInDomain(dce, domain, [USER, USER.upper()])
                self.result(lambda: samr.hSamrLookupNamesInDomain(dce, domain, ['missing']), 0xc0000073)
                self.result(lambda: samr.hSamrLookupNamesInDomain(dce, domain, [USER, 'missing']), 0x107)
                samr.hSamrLookupIdsInDomain(dce, domain, [1000, 1001])
                user = samr.hSamrOpenUser(dce, domain, userId=1000)['UserHandle']
                for level in (1, 6, 7, 8, 9, 10, 11, 12, 13, 14, 21):
                    result = samr.hSamrQueryInformationUser(dce, user, level)
                    if level == 21:
                        self.assertEqual(result['Buffer']['All']['UserName'], USER)
                samr.hSamrQuerySecurityObject(dce, user, 7)
                samr.hSamrGetGroupsForUser(dce, user)
                group = samr.hSamrOpenGroup(dce, domain, groupId=0xffffffff)['GroupHandle']
                samr.hSamrGetMembersInGroup(dce, group)
                unix_sid = samr.hSamrLookupDomainInSamServer(dce, server, 'Unix Group')['DomainId']
                unix = samr.hSamrOpenDomain(dce, server, domainId=unix_sid)['DomainHandle']
                alias = samr.hSamrOpenAlias(dce, unix, aliasId=0)['AliasHandle']
                samr.hSamrGetMembersInAlias(dce, alias)
                sid_array = samr.SAMPR_PSID_ARRAY()
                sid_array['Count'] = 1
                # This client version models SAMR's SID pointer as inline data.
                # LSAT exposes the matching MS-SAMR unique-pointer wire type.
                member = lsat.LSAPR_SID_INFORMATION()
                member['Sid'].fromCanonical(SID + '-1000')
                sid_array['Sids'].append(member)
                samr.hSamrGetAliasMembership(dce, unix, sid_array)
                for handle in (alias, unix, group, user, domain, server):
                    samr.hSamrCloseHandle(dce, handle)
                self.assertGreater(pipe.fragments, 20)

    def test_lsa(self):
        for ndr64 in self.modes():
            with self.subTest(ndr64=ndr64):
                _, dce = self.client('lsa', ndr64)
                for open_policy in (lsad.hLsarOpenPolicy, lsad.hLsarOpenPolicy2):
                    policy = open_policy(dce)['PolicyHandle']
                    lsad.hLsarQueryInformationPolicy(dce, policy, 5)
                    for lookup in (lsat.hLsarLookupNames, lsat.hLsarLookupNames3):
                        result = lookup(dce, policy, [USER, 'Everyone'])
                        self.assertEqual(result['MappedCount'], 2)
                        self.result(lambda: lookup(dce, policy, [USER, 'missing']), 0x107)
                        self.result(lambda: lookup(dce, policy, ['missing']), 0xc0000073)
                    for lookup in (lsat.hLsarLookupSids, lsat.hLsarLookupSids2):
                        result = lookup(dce, policy, [SID + '-1000', 'S-1-1-0'])
                        self.assertEqual(result['MappedCount'], 2)
                    lsad.hLsarClose(dce, policy)
                call = lsad.LsarOpenPolicy2()
                call['SystemName'] = NULL
                for name in ('RootDirectory', 'ObjectName', 'SecurityDescriptor'):
                    call['ObjectAttributes'][name] = NULL
                qos = call['ObjectAttributes']['SecurityQualityOfService']
                qos['Length'], qos['ImpersonationLevel'] = 0xffffffff, 2
                qos['ContextTrackingMode'], qos['EffectiveOnly'] = 1, 1
                call['DesiredAccess'] = 0x02000000
                dce.request(call)

    def test_shares(self):
        for ndr64 in self.modes():
            with self.subTest(ndr64=ndr64):
                _, dce = self.client('srvsvc', ndr64)
                for level in (0, 1, 2, 502):
                    result = srvs.hNetrShareEnum(dce, level)
                    self.assertEqual(result['TotalEntries'], 3)
                    sticky = srvs.hNetrShareEnumSticky(dce, level)
                    self.assertEqual(sticky['TotalEntries'], 3)
                    srvs.hNetrShareGetInfo(dce, 'share0', level)
                for level in (100, 101, 102, 103):
                    result = srvs.hNetrServerGetInfo(dce, level)
                    field = 'ServerInfo%d' % level
                    self.assertEqual(result['InfoStruct'][field]['sv%d_name' % level], 'SERVER\0')

    def test_workstation(self):
        for ndr64 in self.modes():
            with self.subTest(ndr64=ndr64):
                _, dce = self.client('wkssvc', ndr64)
                for level in (100, 101, 102):
                    call = wkst.NetrWkstaGetInfo()
                    call['ServerName'], call['Level'] = '\0', level
                    result = dce.request(call)
                    self.assertEqual(result['WkstaInfo']['WkstaInfo%d' % level][
                        'wki%d_computername' % level], 'SERVER\0')
                _, dce = self.client('dssetup', ndr64)
                result = dssp.hDsRolerGetPrimaryDomainInformation(dce, 1)
                self.assertEqual(result['DomainInfo']['DomainInfoBasic']['MachineRole'], 2)

    def test_error_responses(self):
        for ndr64 in self.modes():
            with self.subTest(ndr64=ndr64):
                _, dce = self.client('samr', ndr64)
                for cls in (samr.SamrCloseHandle, samr.SamrQuerySecurityObject,
                            samr.SamrEnumerateDomainsInSamServer, samr.SamrEnumerateGroupsInDomain,
                            samr.SamrEnumerateUsersInDomain, samr.SamrEnumerateAliasesInDomain,
                            samr.SamrLookupNamesInDomain, samr.SamrLookupIdsInDomain,
                            samr.SamrOpenUser, samr.SamrOpenGroup, samr.SamrOpenAlias,
                            samr.SamrGetMembersInGroup, samr.SamrGetMembersInAlias,
                            samr.SamrGetGroupsForUser, samr.SamrGetAliasMembership,
                            samr.SamrQueryInformationUser):
                    call = cls()
                    for field in call.fields:
                        if field.endswith('Handle'):
                            call[field] = b'\0' * 20
                    if cls == samr.SamrQueryInformationUser:
                        call['UserInformationClass'] = 21
                    self.result(lambda: dce.request(call), 0xc0000008)
                _, dce = self.client('lsa', ndr64)
                for cls in (lsad.LsarClose, lsad.LsarQueryInformationPolicy,
                            lsat.LsarLookupNames, lsat.LsarLookupNames3,
                            lsat.LsarLookupSids, lsat.LsarLookupSids2):
                    call = cls()
                    for field in call.fields:
                        if field.endswith('Handle'):
                            call[field] = b'\0' * 20
                    if cls == lsad.LsarQueryInformationPolicy:
                        call['InformationClass'] = 5
                    elif cls != lsad.LsarClose:
                        call['LookupLevel'] = 1
                    self.result(lambda: dce.request(call), 0xc0000008)

    def test_contexts(self):
        self.require_ndr64()
        pipe = self.raw('lsa', False)
        self.assertEqual(pipe.bind([(1, NDR64)], alter=True), [(0, 0)])
        self.assertEqual(pipe.bind([(0, NDR64)], alter=True), [(2, 2)])
        self.assertEqual(pipe.bind([(1, NDR32)], alter=True), [(2, 2)])
        for context, ndr64 in ((1, True), (0, False), (1, True)):
            call = lsad.LsarOpenPolicy2(isNDR64=ndr64)
            call['SystemName'] = NULL
            for name in ('RootDirectory', 'ObjectName', 'SecurityDescriptor', 'SecurityQualityOfService'):
                call['ObjectAttributes'][name] = NULL
            call['DesiredAccess'] = 0x02000000
            kind, _, reply = pipe.request(44, call.getData(), context)
            self.assertEqual(kind, 2)
            self.assertEqual(struct.unpack('<I', reply[20:24])[0], 0)

    def test_faults_and_big_endian_bind(self):
        for interface in ('samr', 'lsa', 'srvsvc', 'wkssvc'):
            pipe = self.raw(interface, False, True)
            if interface == 'samr':
                kind, _, data = pipe.request(64, pipe.pack('IIIIII', 0, 0x02000000, 1, 1, 1, 0))
                self.assertEqual(kind, 2)
                self.assertEqual(struct.unpack('>I', data[-4:])[0], 0)
            elif interface == 'lsa':
                kind, _, data = pipe.request(44, pipe.pack('IIIIIIII', 0, 24, 0, 0, 0, 0, 0, 0x02000000))
                self.assertEqual(kind, 2)
                self.assertEqual(struct.unpack('>I', data[-4:])[0], 0)
            else:
                kind, _, data = pipe.request(21 if interface == 'srvsvc' else 0,
                                             pipe.pack('II', 0, 100))
                self.assertEqual(kind, 2)
                self.assertEqual(struct.unpack('>I', data[-4:])[0], 0)
        if not WITH_NDR64:
            return
        pipe = self.raw('lsa')
        kind, flags, data = pipe.request(65535, b'')
        self.assertEqual((kind, flags & 0x20), (3, 0x20))
        pipe.endian, pipe.bigendian = '>', True
        kind, _, data = pipe.request(44, b'')
        self.assertEqual(kind, 3)
        self.assertEqual(struct.unpack('>I', data[:4])[0], 0x1c01000b)

    def test_high_referents(self):
        self.require_ndr64()
        pipe = self.raw('samr')
        call = samr.SamrConnect5(isNDR64=True)
        call['ServerName'], call['DesiredAccess'], call['InVersion'] = 'SERVER\0', 0x02000000, 1
        call['InRevisionInfo']['tag'] = 1
        call['InRevisionInfo']['V1']['Revision'] = 3
        data = call.getData()
        for referent in (0x100020000, 0x100000000, 0xffffffffffffffff):
            kind, _, reply = pipe.request(64, struct.pack('<Q', referent) + data[8:])
            self.assertEqual(kind, 2)
            self.assertEqual(struct.unpack('<I', reply[-4:])[0], 0)

    def test_malformed(self):
        self.require_ndr64()
        pipe = self.raw('lsa')
        call = lsad.LsarOpenPolicy2(isNDR64=True)
        call['SystemName'] = NULL
        for name in ('RootDirectory', 'ObjectName', 'SecurityDescriptor', 'SecurityQualityOfService'):
            call['ObjectAttributes'][name] = NULL
        call['DesiredAccess'] = 0x02000000
        valid = call.getData()
        for bad in (valid[:-1], valid + b'\0' * 8, valid + b'\1'):
            kind, _, data = pipe.request(44, bad)
            self.assertEqual(kind, 3)
            self.assertEqual(struct.unpack('<I', data[:4])[0], 0x6f7)
        call = srvs.NetrShareGetInfo(isNDR64=True)
        call['ServerName'], call['NetName'], call['Level'] = NULL, 'share0Xjunk\0', 1
        data = call.getData()
        offset = data.index('Xjunk'.encode('utf-16-le'))
        pipe = self.raw('srvsvc')
        kind, _, reply = pipe.request(16, data[:offset] + b'\0\0' + data[offset + 2:])
        self.assertEqual(kind, 3)
        self.assertEqual(struct.unpack('<I', reply[:4])[0], 0x6f7)

    def test_large_lookup(self):
        for ndr64 in self.modes():
            with self.subTest(ndr64=ndr64):
                pipe, dce = self.client('lsa', ndr64)
                policy = lsad.hLsarOpenPolicy2(dce)['PolicyHandle']
                result = lsat.hLsarLookupSids2(dce, policy, [SID + '-1000'] * 1000)
                self.assertEqual(result['MappedCount'], 1000)
                self.assertGreater(pipe.fragments, 20)

    def test_conformance_and_counted_nuls(self):
        self.require_ndr64()
        pipe = self.raw('lsa')
        call = lsat.LsarLookupNames3(isNDR64=True)
        call['PolicyHandle'] = b'\0' * 20
        call['Count'], call['LookupLevel'] = 2, 1
        for name in (USER, 'Everyone'):
            item = lsat.RPC_UNICODE_STRING(isNDR64=True)
            item['Data'] = name
            call['Names'].append(item)
        call['TranslatedSids']['Sids'] = NULL
        original = call.getData()
        # Both elements remain on the wire while the separate Count says one.
        bad = original[:20] + struct.pack('<I', 1) + original[24:]
        variants = [bad, original[:24] + struct.pack('<Q', 1 << 32) + original[32:]]
        offset = original.index(USER.encode('utf-16-le'))
        variants.append(original[:offset + 4] + b'\0\0' + original[offset + 6:])
        for data in variants:
            kind, _, reply = pipe.request(call.opnum, data)
            self.assertEqual(kind, 3)
            self.assertEqual(struct.unpack('<I', reply[:4])[0], 0x6f7)
        call = lsat.LsarLookupSids2(isNDR64=True)
        call['PolicyHandle'] = b'\0' * 20
        call['SidEnumBuffer']['Entries'] = 1
        item = lsat.LSAPR_SID_INFORMATION(isNDR64=True)
        item['Sid'].fromCanonical(SID + '-1000')
        call['SidEnumBuffer']['SidInfo'].append(item)
        call['TranslatedNames']['Names'] = NULL
        call['LookupLevel'] = 1
        original = call.getData()
        sid_start = original.index(b'\x01\x05\0\0\0\0\0\x05')
        for maximum in (4, 6, 16, 1 << 63):
            bad = original[:sid_start - 8] + struct.pack('<Q', maximum) + original[sid_start:]
            kind, _, reply = pipe.request(call.opnum, bad)
            self.assertEqual(kind, 3)
            self.assertEqual(struct.unpack('<I', reply[:4])[0], 0x6f7)


    def test_mutated_stubs(self):
        self.require_ndr64()
        pipe = self.raw('samr')
        call = samr.SamrConnect5(isNDR64=True)
        call['ServerName'], call['DesiredAccess'], call['InVersion'] = 'SERVER\0', 0x02000000, 1
        call['InRevisionInfo']['tag'] = 1
        call['InRevisionInfo']['V1']['Revision'] = 3
        seed = call.getData()
        rng = random.Random(0x4e44523634)
        variants = [seed[:length] for length in range(len(seed))]
        for _ in range(256):
            data = bytearray(seed)
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            variants.append(bytes(data))
        for data in variants:
            kind, _, reply = pipe.request(call.opnum, data)
            self.assertIn(kind, (2, 3))
            self.assertGreaterEqual(len(reply), 4)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc-test', default=os.environ.get('KSMBD_RPC_TEST', './rpc-test'))
    parser.add_argument('--ndr64', action='store_true',
                        default=os.environ.get('KSMBD_RPC_NDR64') == '1')
    args, remaining = parser.parse_known_args()
    RPC_TEST = os.path.abspath(args.rpc_test)
    WITH_NDR64 = args.ndr64
    unittest.main(argv=[__file__] + remaining)
