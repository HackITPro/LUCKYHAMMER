from rdplib import rdp
import os


class RdpConnection(rdp):

    def __init__(self, address='', port='', client='', user='', domain='', local_hostname='', force_splash=''):
        super().__init__(address=address, port=port)
        self.domain = domain
        self.client = client
        self.user = user
        self.file_name = os.getcwd() + "\configs\default.rdp"
        self.local_hostname = local_hostname
        self.force_splash = force_splash

        if client == '1':
            self.connect()
        elif client == '2':
            self.rdesktop_connect()

    # Windows RDP connect
    def connect(self):
        # Write win RDP config to local directory
        self.save_file(self.file_name)

        connect_args = ' ' + self.file_name
        os.system('mstsc.exe' + connect_args)

    # rdesktop RDP connect
    def rdesktop_connect(self):
        connect_args = " -u {} -d '{}' {}:{}".format(self.user, self.domain, self.address, self.port)
        os.system('rdesktop' + connect_args)

    # Force splash if available using mstsc.exe
    def get_splash(self):
        self.save_file(self.file_name)

        # Disable credssp and authlevel 0
        self.file.write('enablecredsspsupport:i:0\n')
        self.file.write('authentication level:i:0\n')

        connect_args = ' ' + self.file_name
        os.system('mstsc.exe' + connect_args)

    # Server Hostname and Domain
    def get_remote_hostname(self):
        pass

    # Write default rdp file for native RDP client
    def save_file(self, file_name):
        self.file = open(self.file_name, 'w')
        self.file.write('screen mode id:i:1\n')
        self.file.write('use multimon:i:0\n')
        self.file.write('desktopwidth:i:1280\n')
        self.file.write('desktopheight:i:768\n')
        self.file.write('session bpp:i:16\n')
        self.file.write('winposstr:s:0,1,2079,151,3007,1063\n')
        self.file.write('compression:i:1\n')
        self.file.write('keyboardhook:i:0\n')
        self.file.write('audiocapturemode:i:0\n')
        self.file.write('videoplaybackmode:i:1\n')
        self.file.write('connection type:i:4\n')
        self.file.write('networkautodetect:i:0\n')
        self.file.write('bandwidthautodetect:i:1\n')
        self.file.write('displayconnectionbar:i:1\n')
        self.file.write('enableworkspacereconnect:i:0\n')
        self.file.write('disable wallpaper:i:1\n')
        self.file.write('allow font smoothing:i:0\n')
        self.file.write('allow desktop composition:i:1\n')
        self.file.write('disable full window drag:i:1\n')
        self.file.write('disable menu anims:i:1\n')
        self.file.write('disable themes:i:1\n')
        self.file.write('disable cursor setting:i:0\n')
        self.file.write('bitmapcachepersistenable:i:1\n')
        self.file.write('audiomode:i:2\n')
        self.file.write('redirectprinters:i:0\n')
        self.file.write('redirectcomports:i:0\n')
        self.file.write('redirectsmartcards:i:0\n')
        self.file.write('redirectclipboard:i:1\n')
        self.file.write('redirectposdevices:i:0\n')
        self.file.write('autoreconnection enabled:i:1\n')
        self.file.write('prompt for credentials:i:0\n')
        self.file.write('negotiate security layer:i:1\n')
        self.file.write('remoteapplicationmode:i:0\n')
        self.file.write('alternate shell:s:\n')
        self.file.write('shell working directory:s:\n')
        self.file.write('gatewayhostname:s:\n')
        self.file.write('gatewayusagemethod:i:4\n')
        self.file.write('gatewaycredentialssource:i:4\n')
        self.file.write('gatewayprofileusagemethod:i:1\n')
        self.file.write('promptcredentialonce:i:0\n')
        self.file.write('gatewaybrokeringtype:i:0\n')
        self.file.write('use redirection server name:i:0\n')
        self.file.write('rdgiskdcproxy:i:0\n')
        self.file.write('kdcproxyname:s:\n')
        self.file.write('drivestoredirect:s:\n')
        self.file.write('full address:s:{}:{}\n'.format(self.address, self.port))
        self.file.write('username:s:{}\n'.format(self.user))
        self.file.write('domain:s:{}'.format(self.domain) + '\\\n')