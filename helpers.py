DAY_OF_WEEK = {0: 'Sunday', 1: 'Monday', 2: 'Tuesday', 3: 'Wednesday', 4: 'Thursday', 5: 'Friday', 6: 'Saturday'}


def time_zone(mins):
    if mins < 0:
        return 'UTC -{}'.format(mins / 60)
    else:
        return 'UTC +{}'.format(mins / 60)


def build_smbv1_dict(sess):
    sess._Session['ServerName'] = sess._SMBConnection.get_server_name()
    sess._Session['ServerDomain'] = sess._SMBConnection.get_server_domain()
    sess._Session['ServerDNSDomainName'] = sess._SMBConnection.get_server_dns_domain_name()
    sess._Session['ServerDNSHostName'] = sess._SMBConnection.get_server_dns_host_name()
    sess._Session['ServerOSMajor'] = sess._SMBConnection.get_server_os_major()
    sess._Session['ServerOSMinor'] = sess._SMBConnection.get_server_os_minor()
    sess._Session['ServerOSBuild'] = sess._SMBConnection.get_server_os_build()
    sess._Session['ServerOS'] = sess._SMBConnection.get_server_os()
    sess._Session['UserCredentials'] = sess._SMBConnection.getCredentials()
    sess._Connection['RequireSigning'] = sess._SMBConnection._SignatureEnabled
    sess._Connection['ServerIP'] = sess._SMBConnection.get_remote_host()
