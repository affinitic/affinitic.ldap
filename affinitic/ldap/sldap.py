# -*- coding: utf-8 -*-
"""
affinitic.ldap

Licensed under the GPL license, see LICENCE.txt for more details.
Copyright by Affinitic sprl

$Id$
"""

import ldap
import grokcore.component as grok
from affinitic.ldap.interfaces import ILDAP


class LDAP(grok.GlobalUtility):
    """
    An ldap connection
    """
    grok.implements(ILDAP)

    server = None
    managerDn = None
    managerPwd = None
    userBaseDn = None
    groupBaseDn = None

    def __init__(self):
        self.connect()

    def connect(self):
        """
        """
        self._connection = ldap.initialize("ldap://%s" % self.server)
        print self._connection.simple_bind(self.managerDn, self.managerPwd)

    def close(self):
        self._connection.unbind()

    def addUser(self, dn, userAttributes):
        attributes = [(key, item) for key, item in userAttributes.items()]
        return self._connection.add_s(dn, attributes)

    def addUserToGroup(self, dn, groupId):
        group = self.searchGroup(groupId)
        if not group:
            raise AttributeError("Can't find group: %s" % groupId)
        groupDn = group[0][0]
        uniqueMembers = group[0][1].get('uniqueMember', [])
        if dn not in uniqueMembers:
            uniqueMembers.append(str(dn))
        self._connection.modify_s(groupDn, [(ldap.MOD_REPLACE,
                                             'uniqueMember',
                                             uniqueMembers)])

    def updateUser(self, dn, userAttributes):
        attributes = [(ldap.MOD_REPLACE, key, item) for key, item in \
                      userAttributes.items()]
        return self._connection.modify_s(dn, attributes)

    def searchGroup(self, groupId):
        filterSearch = u"(ou=%s)" % groupId
        return self._connection.search_s(self.groupBaseDn, ldap.SCOPE_SUBTREE,
                                         filterSearch)

    def searchUser(self, userId):
        filterSearch = u"(cn=%s)" % userId
        return self._connection.search_s(self.userBaseDn, ldap.SCOPE_SUBTREE,
                                         filterSearch)

    def searchForAttr(self, attr, value):
        filterSearch = u"(%s=%s)" % (attr, value)
        return self._connection.search_s(self.userBaseDn, ldap.SCOPE_SUBTREE,
                                         filterSearch)

    def searchAll(self, objectClass='person'):
        filterSearch = u"(objectClass=%s)" % objectClass
        return self._connection.search_s(self.userBaseDn, ldap.SCOPE_SUBTREE,
                                         filterSearch)
