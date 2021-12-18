"""
Wrapper for smb1/2/3 libraries with some help from impacket smbconection. Functionality to determine preferred
dialect and the ability to fingerprint OS builds without authentication
"""

from binascii import a2b_hex
from impacket.smb3structs import SMB2SessionSetup_Response
from impacket import ntlm, smb3, smb
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED
from impacket.smb import NewSMBPacket, SMBCommand, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMB, SMB_DIALECT, SMBSessionSetupAndX_Extended_Response_Parameters, \
    SMBSessionSetupAndX_Extended_Response_Data
from impacket.smb3structs import SMB2_DIALECT_311, SMB2_DIALECT_302, SMB2_DIALECT_30, SMB2_DIALECT_21, SMB2_DIALECT_002, \
    SMB2_SESSION_SETUP, SMB2_NEGOTIATE_SIGNING_REQUIRED, SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2SessionSetup
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from six import indexbytes
import struct

DIALECTS = {SMB2_DIALECT_30: '3.0.0', SMB2_DIALECT_21: '2.1.0', SMB2_DIALECT_002: '2.0.2',
            SMB_DIALECT: '1.0.0'}


class SmbExt(SMBConnection):

    def __init__(self, remoteName='', remoteHost='', sess_port='', target='', preferredDialect=None):
        super().__init__(remoteName=remoteName, remoteHost=remoteHost, myName=None, sess_port=sess_port, timeout=60,
                         preferredDialect=preferredDialect, existingConnection=None, manualNegotiate=False)

        self._Session = {
            'SessionID': 0,  #
            'TreeConnectTable': {},  #
            'SessionKey': b'',  #
            'SigningRequired': False,  #
            'Connection': 0,  #
            'UserCredentials': '',  #
            'OpenTable': {},  #
            # If the client implements the SMB 3.0 dialect,
            # it MUST also implement the following
            'ChannelList': [],
            'ChannelSequence': 0,
            # 'EncryptData'              : False,
            'EncryptData': True,
            'EncryptionKey': '',
            'DecryptionKey': '',
            'SigningKey': '',
            'ApplicationKey': b'',
            # Outside the protocol
            'SessionFlags': 0,  #
            'ServerName': '',  #
            'ServerDomain': '',  #
            'ServerDNSDomainName': '',  #
            'ServerDNSHostName': '',  #
            'ServerOS': '',  #
            'SigningActivated': False,  #
            'PreauthIntegrityHashValue': a2b_hex(b'0' * 128),
            'CalculatePreAuthHash': True,
        }

        self._Connection = {
            # Indexed by SessionID
            # 'SessionTable'             : {},
            # Indexed by MessageID
            'OutstandingRequests': {},
            'OutstandingResponses': {},  #
            'SequenceWindow': 0,  #
            'GSSNegotiateToken': '',  #'NT LM 0.12'
            'MaxTransactSize': 0,  #
            'MaxReadSize': 0,  #
            'MaxWriteSize': 0,  #
            'ServerGuid': '',  #
            'RequireSigning': False,  #
            'ServerName': '',  #
            # If the client implements the SMB 2.1 or SMB 3.0 dialects, it MUST
            # also implement the following
            'Dialect': 0,  #
            'SupportsFileLeasing': False,  #
            'SupportsMultiCredit': False,  #
            # If the client implements the SMB 3.0 dialect,
            # it MUST also implement the following
            'SupportsDirectoryLeasing': False,  #
            'SupportsMultiChannel': False,  #
            'SupportsPersistentHandles': False,  #
            'SupportsEncryption': False,  #
            'ClientCapabilities': 0,
            'ServerCapabilities': 0,  #
            'ClientSecurityMode': 0,  #
            'ServerSecurityMode': 0,  #
            # Outside the protocol
            'ServerIP': '',  #
            'ClientName': '',  #
        }
        self.os_info_list = ['ServerName', 'ServerDNSDomainName', 'ServerDNSHostName', 'ServerOS', 'ServerOSMajor',
                             'ServerOSMinor', "ServerOSBuild", "ServerDomain"]
        self.session_info_list = ['SessionID', 'UserCredentials']
        self.connection_info_list = ['ServerIP', 'RequireSigning', 'Dialect', 'SupportsEncryption']
        self.target = target

    def get_smbinfo(self, domain='', use_ntlmv2=None):

        try:
            if self.getDialect() == SMB_DIALECT:
                print("\tDialect is {}".format(DIALECTS[self.getDialect()]))

                self._SMBConnection.set_flags(flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES)
                # Get SMB v1 info
                smb1 = NewSMBPacket()

                sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
                sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
                sessionSetup['Data'] = SMBSessionSetupAndX_Extended_Data()

                sessionSetup['Parameters']['MaxBufferSize'] = 61440
                sessionSetup['Parameters']['MaxMpxCount'] = 2
                sessionSetup['Parameters']['VcNumber'] = 1
                sessionSetup['Parameters']['SessionKey'] = 0
                sessionSetup['Parameters'][
                    'Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE | SMB.CAP_LARGE_READX | SMB.CAP_LARGE_WRITEX

                # Let's build a NegTokenInit with the NTLMSSP
                blob = SPNEGO_NegTokenInit()

                # NTLMSSP
                blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
                auth = ntlm.getNTLMSSPType1(self.getClientName(), domain, self.isSigningRequired(),
                                            use_ntlmv2=use_ntlmv2)
                blob['MechToken'] = auth.getData()

                sessionSetup['Parameters']['SecurityBlobLength'] = len(blob)
                sessionSetup['Parameters'].getData()
                sessionSetup['Data']['SecurityBlob'] = blob.getData()

                # Fake Data here, don't want to get us fingerprinted
                sessionSetup['Data']['NativeOS'] = 'Windows'
                sessionSetup['Data']['NativeLanMan'] = 'Windows NT 5.0'

                smb1.addCommand(sessionSetup)
                self._SMBConnection.sendSMB(smb1)

                smb_recv = self._SMBConnection.recvSMB()
                if smb_recv.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
                    sessionResponse = SMBCommand(smb_recv['Data'][0])
                    sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
                    sessionData = SMBSessionSetupAndX_Extended_Response_Data(flags=smb_recv['Flags2'])
                    sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
                    sessionData.fromString(sessionResponse['Data'])
                    respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])
                    # parse function here
                    # print function here
                    self.parse_smb(respToken)
                    self.print_info(self.os_info_list)
                    self._SMBConnection.close_session()

            else:
                # Get smb3 info
                print("\tDialect is {}".format(DIALECTS[self.getDialect()]))
                sessionSetup = SMB2SessionSetup()
                if self._SMBConnection.RequireMessageSigning is True:
                    sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
                else:
                    sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

                sessionSetup['Flags'] = 0

                # Let's build a NegTokenInit with the NTLMSSP
                blob = smb3.SPNEGO_NegTokenInit()

                # NTLMSSP
                blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
                auth = ntlm.getNTLMSSPType1(self._Connection['ClientName'], domain,
                                            self._Connection['RequireSigning'])
                blob['MechToken'] = auth.getData()

                sessionSetup['SecurityBufferLength'] = len(blob)
                sessionSetup['Buffer'] = blob.getData()

                packet = self._SMBConnection.SMB_PACKET()
                packet['Command'] = SMB2_SESSION_SETUP
                packet['Data'] = sessionSetup

                packetID = self._SMBConnection.sendSMB(packet)
                ans = self._SMBConnection.recvSMB(packetID)
                if self._Connection['Dialect'] == SMB2_DIALECT_311:
                    self._SMBConnection.__UpdatePreAuthHash(ans.rawData)

                if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
                    self._Session['SessionID'] = ans['SessionID']
                    self._Session['SigningRequired'] = self._Connection['RequireSigning']
                    self._Session['Connection'] = self._SMBConnection._NetBIOSSession.get_socket()
                    sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
                    respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])
                    self.parse_smb(respToken)
                    self.print_info(self.os_info_list)
                    self._SMBConnection.close_session()
        except (smb.SessionError, smb3.SessionError) as e:
            print("Error getting SMB info.")

    def parse_smb(self, respToken):
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

            if self._SMBConnection._strict_hostname_validation:
                self._SMBConnection.perform_hostname_validation()

            # Parse Version to know the target Operating system name. Not provided elsewhere anymore
            if 'Version' in ntlmChallenge.fields:
                version = ntlmChallenge['Version']
                if self._SMBConnection.getDialect() == SMB_DIALECT:
                    if len(version) >= 4:
                        self._Session["ServerOSMajor"], self._Session["ServerOSMinor"], self._Session["ServerOSBuild"] = struct.unpack('<BBH', version[:4])
                        self._Session['ServerOS'] = "Windows {}.{}".format(indexbytes(version, 0), indexbytes(version, 1))
                else:
                    if len(version) >= 4:
                        self._Session['ServerOS'] = "Windows %d.%d Build %d" % (
                            indexbytes(version, 0), indexbytes(version, 1), struct.unpack('<H', version[2:4])[0])
                        self._Session["ServerOSMajor"] = indexbytes(version, 0)
                        self._Session["ServerOSMinor"] = indexbytes(version, 1)
                        self._Session["ServerOSBuild"] = struct.unpack('<H', version[2:4])[0]

    def print_info(self, alist):
        # Session info list
        for k, v in self._Connection.items():
            for i in alist:
                if i == k:
                    if k == 'Dialect':
                        for key, val in DIALECTS.items():
                            if v == key:
                                print("\t{:<20}: {}".format(k, val))
                    else:
                        print("\t{:<20}: {}".format(k, v))
        for k, v in self._Session.items():
            for i in alist:
                if i == k:
                    print("\t{:<20}: {}".format(k, v))
