from cmd2 import Cmd
import cmd2
import argparse
import asciiart
from impacket.dcerpc.v5 import transport, srvs, rrp, scmr
from impacket.dcerpc.v5.dtypes import NULL
import ntpath
import time
from impacket.smbconnection import SessionError, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY
import os

SERVICE_STATES = {'Running' : 0x00000004, "Stopped": 0x00000001, "Continue Pending" : 0x00000005,
                      "Pause Pending" : 0x00000006, "Paused" : 0x00000007, "Start Pending": 0x00000002,
                      "Stop Pending" : 0x00000003}

class FinishingNail(Cmd):
    FILESYSTEM_CMD = 'Filesystem Commands'
    SYSTEMINFO_CMD = 'System Information Commands'
    REGISTRY_CMD = 'Registry commands'
    SERVICE_CMD = 'Service Commands'


    def __init__(self, sess):
        super().__init__()
        self.intro = asciiart.get_art("FINISHINGNAIL", False)
        self.session = sess
        self.prompt = "{}# ".format(self.session.getRemoteHost())
        self.self_in_py = True
        self.default_category = 'Built-in Commands'
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = self.session.getCredentials()
        self.tid = None
        self.pwd = ''
        self.share = None
        self.completion = []
        self._srvs = None
        self._rrp = None
        self._scmr = None
        self._scManagerHandle = None
        self._serviceHandle = None

    def srvs_connect(self):
        rpctransport = transport.SMBTransport(self.session.getRemoteHost(), filename=r'\srvsvc',
                                              smb_connection=self.session)
        self._srvs = rpctransport.get_dce_rpc()
        self._srvs.connect()
        self._srvs.bind(srvs.MSRPC_UUID_SRVS)

    def rrp_connect(self):
        rpctransport = transport.SMBTransport(self.session.getRemoteHost(), filename=r'\winreg',
                                              smb_connection=self.session)
        self._rrp = rpctransport.get_dce_rpc()
        self._rrp.connect()
        self._rrp.bind(rrp.MSRPC_UUID_RRP)

    def scmr_connect(self):
        rpctransport = transport.SMBTransport(self.session.getRemoteHost(), filename=r'\svcctl',
                                              smb_connection=self.session)
        self._scmr = rpctransport.get_dce_rpc()
        self._scmr.connect()
        self._scmr.bind(scmr.MSRPC_UUID_SCMR)

    def list_services(self):
        resp = scmr.hROpenSCManagerW(self._scmr)
        self._scManagerHandle = resp['lpScHandle']
        resp = scmr.hREnumServicesStatusW(self._scmr, self._scManagerHandle)
        for record in resp:
            self.poutput('{:<25} | {:<65} | {:<10}'.format(record['lpServiceName'], record['lpDisplayName'],
                                                           self.resolve_svcstate(record['ServiceStatus']
                                                                                 ['dwCurrentState'])))

    def resolve_svcstate(self, state):
        for k, v in SERVICE_STATES.items():
            if state == v:
                return k

    '''
    def check_services(self, servicename):
        # Open SC Manager
        resp = scmr.hROpenSCManagerW(self._scmr)
        self._scManagerHandle = resp['lpScHandle']
        # Now let's open the service
        resp = scmr.hROpenServiceW(self._scmr, self._scManagerHandle, servicename)
        self._serviceHandle = resp['lpServiceHandle']
        # Let's check its status
        resp = scmr.hRQueryServiceStatus(self._scmr, self._serviceHandle)
        if resp['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            self.poutput('Service {} is in stopped state'.format(servicename))

        elif resp['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            self.poutput('Service {} is already running'.format(servicename))

        else:
            raise Exception('Unknown service state 0x{}x - Aborting'.format(resp['CurrentState']))

        # Let's check its configuration if service is stopped, maybe it's disabled :s
    '''

    def start_service(self, servicename):
        self.check_service(servicename)
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                self.poutput('Service {} is disabled, enabling it'.format(servicename))
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x3)
            self.poutput('Starting service {}'.format(self.__serviceName))
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
            time.sleep(1)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_shares(self, args):
        """Get the shares through RPC"""
        if self._srvs is None:
            self.srvs_connect()
        resp = srvs.hNetrShareEnum(self._srvs, 1)
        resp = resp['InfoStruct']['ShareInfo']['Level1']['Buffer']
        self.poutput("Available shares:")
        for i in range(len(resp)):
            print(resp[i]['shi1_netname'][:-1])

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include=2)

    def complete_get(self, text, line, begidx, endidx, include=1):
        # include means
        # 1 just files
        # 2 just directories
        p = line.replace('/', '\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def complete_ls(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include=2)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_use(self, args):
        self.share = args
        self.tid = self.session.connectTree(args)
        self.pwd = '\\'
        self.do_ls('', False)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_ls(self, wildcard, display=True):
        if self.tid is None:
            self.perror("No share selected")
            return
        if wildcard == '':
            pwd = ntpath.join(self.pwd, '*')
        else:
            pwd = ntpath.join(self.pwd, wildcard + '\\*')
        self.completion = []
        pwd = pwd.replace('/', '\\')
        pwd = ntpath.normpath(pwd)
        for f in self.session.listPath(self.share, pwd):
            if display is True:
                print("%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(),
                                                   time.ctime(float(f.get_mtime_epoch())), f.get_longname()))
            self.completion.append((f.get_longname(), f.is_directory()))

    @cmd2.with_category(SYSTEMINFO_CMD)
    def do_info(self, args):
        if self._srvs is None:
            self.srvs_connect()
        resp = srvs.hNetrServerGetInfo(self._srvs, 102)

        print("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
        print("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
        print("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
        print("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
        print("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
        print("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_pwd(self, args):
        print(self.pwd)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_cd(self, line):
        p = line.replace('/', '\\')
        oldpwd = self.pwd
        if p[0] == '\\':
            self.pwd = line
        else:
            self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.session.openFile(self.tid, self.pwd, creationOption=FILE_DIRECTORY_FILE,
                                        desiredAccess=FILE_READ_DATA | FILE_LIST_DIRECTORY,
                                        shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE)
            self.session.closeFile(self.tid, fid)
        except SessionError:
            self.pwd = oldpwd
            raise

    @cmd2.with_category(SYSTEMINFO_CMD)
    def do_who(self, args):
        if self._srvs is None:
            self.srvs_connect()
        resp = srvs.hNetrSessionEnum(self._srvs, NULL, NULL, 10)

        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            print("host: %15s, user: %5s, active: %5d, idle: %5d" % (
                session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
                session['sesi10_idle_time']))

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_rm(self, filename):
        if self.tid is None:
            self.perror("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = f.replace('/', '\\')
        self.session.deleteFile(self.share, file)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_mkdir(self, path):
        if self.tid is None:
            self.perror("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/', '\\')
        self.session.createDirectory(self.share, pathname)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_rmdir(self, path):
        if self.tid is None:
            self.perror("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = p.replace('/', '\\')
        self.session.deleteDirectory(self.share, pathname)

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_put(self, pathname):
        if self.tid is None:
            self.perror("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd, dst_name)
        finalpath = f.replace('/', '\\')
        self.session.putFile(self.share, finalpath, fh.read)
        fh.close()

    @cmd2.with_category(FILESYSTEM_CMD)
    def do_get(self, filename):
        if self.tid is None:
            self.perror("No share selected")
            return
        filename = filename.replace('/', '\\')
        fh = open(ntpath.basename(filename), 'wb')
        pathname = ntpath.join(self.pwd, filename)
        try:
            self.session.getFile(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

    @cmd2.with_category(SYSTEMINFO_CMD)
    def do_list_snapshots(self, line):
        l = line.split(' ')
        if len(l) > 0:
            pathName = l[0].replace('/', '\\')

        # Relative or absolute path?
        if pathName.startswith('\\') is not True:
            pathName = ntpath.join(self.pwd, pathName)

        snapshotList = self.session.listSnapshots(self.tid, pathName)

        if not snapshotList:
            print("No snapshots found")
            return

        for timestamp in snapshotList:
            print(timestamp)

    @cmd2.with_category(SYSTEMINFO_CMD)
    def do_drives(self, args):
        if self._srvs is None:
            self.srvs_connect()
        resp = srvs.hNetrServerDiskEnum(self._srvs, 0)
        for i in resp['DiskInfoStruct']['Buffer']:
            self.poutput(i['Disk'])

    regquery_parser = argparse.ArgumentParser()
    regquery_parser.add_argument('-k', '--key', required=True, help='Key to query')
    regquery_parser.add_argument('-v', '--value', required=True, help='Value to query')

    @cmd2.with_argparser(regquery_parser)
    @cmd2.with_category(REGISTRY_CMD)
    def do_regquery(self, args):
        if self._rrp is None:
            self.rrp_connect()

    def do_service(self, args):
        if self._scmr is None:
            self.scmr_connect()
        self.list_services()




'''
    """Unreliable.  Worthless"""
    @cmd2.with_category(SYSTEMINFO_CMD)
    def do_time(self, args):
        rpctransport = transport.SMBTransport(self.session.getRemoteHost(), filename=r'\srvsvc',
                                              smb_connection=self.session)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrRemoteTOD(dce)
        self.poutput("\t{:<10}: {}".format('Timezone', time_zone(resp['BufferPtr']['tod_timezone'])))
        self.poutput("\t{:<10}: {} {}-{}-{}".format('Date', DAY_OF_WEEK[resp['BufferPtr']['tod_weekday']],
                                                    resp['BufferPtr']['tod_day'], resp['BufferPtr']['tod_month'],
                                                    resp['BufferPtr']['tod_year'], resp['BufferPtr']['tod_year']))
        self.poutput("\t{:<10}: {}:{}:{}".format('Time', resp['BufferPtr']['tod_hours'], resp['BufferPtr']['tod_mins'],
                                                 resp['BufferPtr']['tod_secs']))
'''