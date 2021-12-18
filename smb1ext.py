import struct
from binascii import a2b_hex
from struct import unpack
from impacket import ntlm
from impacket.smb import SMB, SMBCommand, NewSMBPacket, SMBSessionSetupAndX_Extended_Parameters, \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Parameters, \
    SMBSessionSetupAndX_Extended_Response_Data

from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from six import indexbytes


class Smb1Ext(SMB):

    def __init__(self, remote_name='', remote_host='', sess_port=''):
        super().__init__(remote_name=remote_name, remote_host=remote_host, sess_port=sess_port)
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
            #'SessionTable'             : {},
            # Indexed by MessageID
            'OutstandingRequests'      : {},
            'OutstandingResponses'     : {},    #
            'SequenceWindow'           : 0,     #
            'GSSNegotiateToken'        : '',    #
            'MaxTransactSize'          : 0,     #
            'MaxReadSize'              : 0,     #
            'MaxWriteSize'             : 0,     #
            'ServerGuid'               : '',    #
            'RequireSigning'           : False, #
            'ServerName'               : '',    #
            # If the client implements the SMB 2.1 or SMB 3.0 dialects, it MUST
            # also implement the following
            'Dialect'                  : 0,    #
            'SupportsFileLeasing'      : False, #
            'SupportsMultiCredit'      : False, #
            # If the client implements the SMB 3.0 dialect,
            # it MUST also implement the following
            'SupportsDirectoryLeasing' : False, #
            'SupportsMultiChannel'     : False, #
            'SupportsPersistentHandles': False, #
            'SupportsEncryption'       : False, #
            'ClientCapabilities'       : 0,
            'ServerCapabilities'       : 0,    #
            'ClientSecurityMode'       : 0,    #
            'ServerSecurityMode'       : 0,    #
            # Outside the protocol
            'ServerIP'                 : '',    #
            'ClientName'               : '',    #
        }
        self.os_info_list = ['ServerName', 'ServerDNSDomainName', 'ServerDNSHostName', 'ServerOS', 'ServerOSMajor',
                             'ServerOSMinor', "ServerOSBuild", "ServerDomain"]
        self._Connection['ServerIP'] = remote_name

    def get_smbinfo(self, domain='', use_ntlmv2=None):

        # Once everything's working we should join login methods into a single one
        smb = NewSMBPacket()

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
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(self.get_client_name(), domain, self._SignatureRequired, use_ntlmv2=use_ntlmv2)
        blob['MechToken'] = auth.getData()

        sessionSetup['Parameters']['SecurityBlobLength'] = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob'] = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS'] = 'Windows'
        sessionSetup['Data']['NativeLanMan'] = 'Windows NT 5.0'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):

            sessionResponse = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData = SMBSessionSetupAndX_Extended_Response_Data(flags=smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                    try:
                        self._Session['ServerName'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                    try:
                        if self._Session['ServerName'] != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                            self._Session['ServerDomain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                    try:
                        self._Session['ServerDNSDomainName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                    try:
                       self._Session['ServerDNSHostName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode('utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

            if self._strict_hostname_validation:
                self.perform_hostname_validation()

            # Parse Version to know the target Operating system name. Not provided elsewhere anymore
            if 'Version' in ntlmChallenge.fields:
                version = ntlmChallenge['Version']

                if len(version) >= 4:
                    self._Session['ServerOS'] = "Windows %d.%d Build %d" % (indexbytes(version, 0), indexbytes(version, 1), struct.unpack('<H', version[2:4])[0])
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
