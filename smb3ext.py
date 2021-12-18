import impacket.smb3 as smb3

import struct
from six import indexbytes
from binascii import a2b_hex

from impacket import ntlm
from impacket.smb3structs import *
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED
from impacket.spnego import TypesMech, SPNEGO_NegTokenResp


class Smb3Ext(smb3.SMB3):
    def __init__(self, remote_name='', remote_host='', sess_port='', target=''):
        super().__init__(remote_name=remote_name, remote_host=remote_host, sess_port=sess_port)
        self.os_info_list = ['ServerName', 'ServerDNSDomainName', 'ServerDNSHostName', 'ServerOS', 'ServerOSMajor',
                             'ServerOSMinor', "ServerOSBuild", "ServerDomain"]
        self.session_info_list = ['SessionID', 'UserCredentials', 'EncryptData']
        self.connection_info_list = ['ServerIP', 'ClientName', 'RequireSigning', 'Dialect']
        self.dialects = {SMB2_DIALECT_311: '3.1.1', SMB2_DIALECT_302: '3.0.2', SMB2_DIALECT_30: '3.0.0',
                         SMB2_DIALECT_21: '2.1.0', SMB2_DIALECT_002: '2.0.0'}
        self.target = target

    def get_smbinfo(self, user, password, domain='', lmhash='', nthash=''):
        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try:  # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        self.__userName = user
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = ''
        self.__TGT = None
        self.__TGS = None

        sessionSetup = SMB2SessionSetup()
        if self.RequireMessageSigning is True:
            sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
            sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0
        # sessionSetup['Capabilities'] = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_DFS

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = smb3.SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(self._Connection['ClientName'], domain, self._Connection['RequireSigning'])
        blob['MechToken'] = auth.getData()

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer'] = blob.getData()

        # ToDo:
        # If this authentication is for establishing an alternative channel for an existing Session, as specified
        # in section 3.2.4.1.7, the client MUST also set the following values:
        # The SessionId field in the SMB2 header MUST be set to the Session.SessionId for the new
        # channel being established.
        # The SMB2_SESSION_FLAG_BINDING bit MUST be set in the Flags field.
        # The PreviousSessionId field MUST be set to zero.

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data'] = sessionSetup

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if self._Connection['Dialect'] == SMB2_DIALECT_311:
            self.__UpdatePreAuthHash(ans.rawData)

        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            self._Session['SessionID'] = ans['SessionID']
            self._Session['SigningRequired'] = self._Connection['RequireSigning']
            self._Session['UserCredentials'] = (user, password, domain, lmhash, nthash)
            self._Session['Connection'] = self._NetBIOSSession.get_socket()
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                    try:
                        self._Session['ServerName'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                    try:
                        if self._Session['ServerName'] != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                            self._Session['ServerDomain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                    try:
                        self._Session['ServerDNSDomainName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode(
                            'utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                    try:
                        self._Session['ServerDNSHostName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode(
                            'utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

                if self._strict_hostname_validation:
                    self.perform_hostname_validation()

                # Parse Version to know the target Operating system name. Not provided elsewhere anymore
                if 'Version' in ntlmChallenge.fields:
                    version = ntlmChallenge['Version']

                    if len(version) >= 4:
                        self._Session['ServerOS'] = "Windows %d.%d Build %d" % (
                            indexbytes(version, 0), indexbytes(version, 1), struct.unpack('<H', version[2:4])[0])
                        self._Session["ServerOSMajor"] = indexbytes(version, 0)
                        self._Session["ServerOSMinor"] = indexbytes(version, 1)
                        self._Session["ServerOSBuild"] = struct.unpack('<H', version[2:4])[0]
            self.print_session_info(self.os_info_list)
            self.close_session()

    def print_session_info(self, alist):
        # Session info list
        for k, v in self._Connection.items():
            for i in alist:
                if i == k:
                    if k == 'Dialect':
                        for key, val in self.dialects.items():
                            if v == key:
                                print("\t{:<20}: {}".format(k, val))
                    else:
                        print("\t{:<20}: {}".format(k, v))
        for k, v in self._Session.items():
            for i in alist:
                if i == k:
                    print("\t{:<20}: {}".format(k, v))
