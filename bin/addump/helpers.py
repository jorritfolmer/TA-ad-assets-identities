import sys
sys.path.append('/usr/lib64/python2.7/site-packages')
try:
    import ldap
except Exception:
    raise ValueError("Error importing system ldap librabry")
import struct
from ldap.controls import SimplePagedResultsControl
from distutils.version import StrictVersion


def uac2flag(uac):
    ADS_UF_SCRIPT = 1
    ADS_UF_ACCOUNTDISABLE = 2
    ADS_UF_HOMEDIR_REQUIRED = 8
    ADS_UF_LOCKOUT = 16
    ADS_UF_PASSWD_NOTREQD = 32
    ADS_UF_PASSWD_CANT_CHANGE = 64
    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128
    ADS_UF_TEMP_DUPLICATE_ACCOUNT = 256
    ADS_UF_NORMAL_ACCOUNT = 512
    ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048
    ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096
    ADS_UF_SERVER_TRUST_ACCOUNT = 8192
    ADS_UF_DONT_EXPIRE_PASSWD = 65536
    ADS_UF_MNS_LOGON_ACCOUNT = 131072
    ADS_UF_SMARTCARD_REQUIRED = 262144
    ADS_UF_TRUSTED_FOR_DELEGATION = 524288
    ADS_UF_NOT_DELEGATED = 1048576
    ADS_UF_USE_DES_KEY_ONLY = 2097152
    ADS_UF_DONT_REQUIRE_PREAUTH = 4194304
    ADS_UF_PASSWORD_EXPIRED = 8388608
    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216
    val = []
    uac = int(uac)

    if (uac & ADS_UF_SCRIPT):
        val.append("SCRIPT")
    if (uac & ADS_UF_ACCOUNTDISABLE):
        val.append("ACCOUNTDISABLE")
    if (uac & ADS_UF_HOMEDIR_REQUIRED):
        val.append("HOMEDIR_REQUIRED")
    if (uac & ADS_UF_LOCKOUT):
        val.append("LOCKOUT")
    if (uac & ADS_UF_PASSWD_NOTREQD):
        val.append("PASSWD_NOTREQD")
    if (uac & ADS_UF_PASSWD_CANT_CHANGE):
        val.append("PASSWD_CANT_CHANGE")
    if (uac & ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED):
        val.append("ENCRYPTED_TEXT_PASSWORD_ALLOWED")
    if (uac & ADS_UF_TEMP_DUPLICATE_ACCOUNT):
        val.append("TEMP_DUPLICATE_ACCOUNT")
    if (uac & ADS_UF_NORMAL_ACCOUNT):
        val.append("NORMAL_ACCOUNT")
    if (uac & ADS_UF_INTERDOMAIN_TRUST_ACCOUNT):
        val.append("INTERDOMAIN_TRUST_ACCOUNT")
    if (uac & ADS_UF_WORKSTATION_TRUST_ACCOUNT):
        val.append("WORKSTATION_TRUST_ACCOUNT")
    if (uac & ADS_UF_SERVER_TRUST_ACCOUNT):
        val.append("SERVER_TRUST_ACCOUNT")
    if (uac & ADS_UF_DONT_EXPIRE_PASSWD):
        val.append("DONT_EXPIRE_PASSWD")
    if (uac & ADS_UF_MNS_LOGON_ACCOUNT):
        val.append("MNS_LOGON_ACCOUNT")
    if (uac & ADS_UF_SMARTCARD_REQUIRED):
        val.append("SMARTCARD_REQUIRED")
    if (uac & ADS_UF_TRUSTED_FOR_DELEGATION):
        val.append("TRUSTED_FOR_DELEGATION")
    if (uac & ADS_UF_NOT_DELEGATED):
        val.append("NOT_DELEGATED")
    if (uac & ADS_UF_USE_DES_KEY_ONLY):
        val.append("USE_DES_KEY_ONLY")
    if (uac & ADS_UF_DONT_REQUIRE_PREAUTH):
        val.append("DONT_REQUIRE_PREAUTH")
    if (uac & ADS_UF_PASSWORD_EXPIRED):
        val.append("PASSWORD_EXPIRED")
    if (uac & ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION):
        val.append("TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION")
    return val

def sid2string(binary):
    version = struct.unpack('B', binary[0])[0]
    # I do not know how to treat version != 1 (it does not exist yet)
    assert version == 1, version
    length = struct.unpack('B', binary[1])[0]
    authority = struct.unpack('>Q', '\x00\x00' + binary[2:8])[0]
    string = 'S-%d-%d' % (version, authority)
    binary = binary[8:]
    assert len(binary) == 4 * length
    for i in xrange(length):
        value = struct.unpack('<L', binary[4*i:4*(i+1)])[0]
        string += '-%d' % (value)
    return string

def ad_time_to_seconds(ad_time):
    return -(int(ad_time) / 10000000)

def ad_seconds_to_unix(ad_seconds):
    return  ((int(ad_seconds) + 11644473600) if int(ad_seconds) != 0 else 0)

def ad_time_to_unix(ad_time):
    #  A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates that the account never expires.
    # FIXME: Better handling of account-expires!
    if ad_time == "9223372036854775807":
        ad_time = "0"
    ad_seconds = ad_time_to_seconds(ad_time)
    return -ad_seconds_to_unix(ad_seconds)

def create_controls(pagesize):
    """Create an LDAP control with a page size of "pagesize"."""
    # Initialize the LDAP controls for paging. Note that we pass ''
    # for the cookie because on first iteration, it starts out empty.
    LDAP24API = StrictVersion(ldap.__version__) >= StrictVersion('2.4')
    if LDAP24API:
        return SimplePagedResultsControl(True, size=pagesize, cookie='')
    else:
        return SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True,
                                         (pagesize,''))

def get_pctrls(serverctrls):
    """Lookup an LDAP paged control object from the returned controls."""
    # Look through the returned controls and find the page controls.
    # This will also have our returned cookie which we need to make
    # the next search request.
    LDAP24API = StrictVersion(ldap.__version__) >= StrictVersion('2.4')
    if LDAP24API:
        return [c for c in serverctrls
                if c.controlType == SimplePagedResultsControl.controlType]
    else:
        return [c for c in serverctrls
                if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]

def set_cookie(lc_object, pctrls, pagesize):
    """Push latest cookie back into the page control."""
    LDAP24API = StrictVersion(ldap.__version__) >= StrictVersion('2.4')
    if LDAP24API:
        cookie = pctrls[0].cookie
        lc_object.cookie = cookie
        return cookie
    else:
        est, cookie = pctrls[0].controlValue
        lc_object.controlValue = (pagesize,cookie)
        return cookie

# This is essentially a placeholder callback function. You would do your real
# work inside of this. Really this should be all abstracted into a generator...
def process_entry(dn, attrs):
    """Process an entry. The two arguments passed are the DN and
       a dictionary of attributes."""
    if 'objectSid' in attrs:
        attrs['objectSid'] = [sid2string(attrs['objectSid'][0])]
    if 'pwdLastSet' in attrs:
        attrs['pwdLastSet'] = [ad_time_to_unix(attrs['pwdLastSet'][0])]
    if 'lastLogon' in attrs:
        attrs['lastLogon'] = [ad_time_to_unix(attrs['lastLogon'][0])]
    if 'badPasswordTime' in attrs:
        attrs['badPasswordTime'] = [ad_time_to_unix(attrs['badPasswordTime'][0])]
    if 'userAccountControl' in attrs:
        attrs['userAccountControl'] = [uac2flag(attrs['userAccountControl'][0])]
    lines = "dn=\"%s\"\n" % dn
    for k,v in attrs.items():
        for val in v:
            if type(val) is list:
                 for val2 in val:
                     lines += "%s=\"%s\"\n" % (k,val2)
            else:
                 lines += "%s=\"%s\"\n" % (k,val)
    return lines
