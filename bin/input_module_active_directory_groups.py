# encoding = utf-8

from builtins import str
import os
import sys
import time
import datetime
sys.path.append('/usr/lib64/python2.7/site-packages')
try:
    import ldap
except Exception:
    raise ValueError("Error importing system ldap librabry")
import struct
from ldap.controls import SimplePagedResultsControl
from distutils.version import StrictVersion
import addump.helpers

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    global_account = definition.parameters.get('global_account', None)
    domain_controller = definition.parameters.get('domain_controller', None)
    base_dn = definition.parameters.get('base_dn', None)
    ldap_attributes = definition.parameters.get('ldap_attributes', None)

    return True

def collect_events(helper, ew):
    """Implement your data collection logic here """

    loglevel = helper.get_log_level()
    opt_global_account = helper.get_arg('global_account')
    opt_domain_controller = helper.get_arg('domain_controller')
    opt_base_dn = helper.get_arg('base_dn')
    opt_ldap_attributes = helper.get_arg('ldap_attributes')
    opt_pagesize = 1000

    new_opt_ldap_attributes = []
    for i in opt_ldap_attributes.split(','):
        new_opt_ldap_attributes.append(str(i.strip(' ')))
    opt_ldap_attributes = new_opt_ldap_attributes

    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    ldap.set_option(ldap.OPT_REFERRALS, 0)

    l = ldap.initialize("ldaps://%s" % opt_domain_controller)
    l.protocol_version = 3          # Paged results only apply to LDAP v3
    try:
        l.simple_bind_s(opt_global_account['username'], opt_global_account['password'])
    except ldap.LDAPError as e:
        helper.log_error('LDAP bind failed: %s' % e)
        exit(1)
    
    lc = addump.helpers.create_controls(opt_pagesize)
    
    while True:
        # Send search request
        try:
            msgid = l.search_ext(opt_base_dn, ldap.SCOPE_SUBTREE, "(objectclass=group)",
                                 opt_ldap_attributes, serverctrls=[lc])
        except ldap.LDAPError as e:
            helper.log_error('LDAP search failed: %s' % e)
            break
    
        try:
            rtype, rdata, rmsgid, serverctrls = l.result3(msgid)
        except ldap.LDAPError as e:
            helper.log_error('Could not pull LDAP results: %s' % e)
            break
    
        for dn, attrs in rdata:
            if dn is not None:
                data = addump.helpers.process_entry(helper, dn, attrs)
                event = helper.new_event(data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
                ew.write_event(event)
    
        pctrls = addump.helpers.get_pctrls(serverctrls)
        if not pctrls:
            helper.log_warning('Warning: Server ignores RFC 2696 control.')
            break
        cookie = addump.helpers.set_cookie(lc, pctrls, opt_pagesize)
        if not cookie:
            break
    l.unbind()
