# -*- coding: utf-8 -*-
"""
gites.ldapimport

Licensed under the GPL license, see LICENCE.txt for more details.
Copyright by Affinitic sprl

$Id$
"""
import string
from random import choice
from affinitic.ldap import SSHA
import base64
import md5
import sha
import random
import crypt

mapping_latin_chars = {138: 's', 140: 'O', 142: 'z', 154: 's',
                       156: 'o', 158: 'z', 159: 'Y',
192: 'A', 193: 'A', 194: 'A', 195: 'a', 196: 'A', 197: 'A', 198: 'E',
199: 'C', 200: 'E', 201: 'E', 202: 'E', 203: 'E', 204: 'I', 205: 'I',
206: 'I', 207: 'I', 208: 'D', 209: 'N', 210: 'O', 211: 'O', 212: 'O',
213: 'O', 214: 'O', 215: 'x', 216: 'O', 217: 'U', 218: 'U', 219: 'U',
220: 'U', 221: 'Y', 223: 's', 224: 'a', 225: 'a', 226: 'a', 227: 'a',
228: 'a', 229: 'a', 230: 'e', 231: 'c', 232: 'e', 233: 'e', 234: 'e',
235: 'e', 236: 'i', 237: 'i', 238: 'i', 239: 'i', 240: 'd', 241: 'n',
242: 'o', 243: 'o', 244: 'o', 245: 'o', 246: 'o', 248: 'o', 249: 'u',
250: 'u', 251: 'u', 252: 'u', 253: 'y', 255: 'y'}


def normalizeString(text, withDash=False):
    if text is None:
        return ''
    text = text.strip()
    text = text.lower()
    res = ""
    allowed = string.ascii_letters + string.digits
    if withDash:
        allowed += '-'
    for ch in text:
        if ch in allowed:
            res += ch
        else:
            ordinal = ord(ch)
            if ordinal in mapping_latin_chars:
                res += mapping_latin_chars.get(ordinal)
    return res


def generateRandomPassword(passwordLength):
    """
    A simple script for making random passwords, WITHOUT 1,l,O,0.  Because
    those characters are hard to tell the difference between in some fonts.

    """
    return ''.join([choice(string.letters+string.digits) for i in \
                    range(1, passwordLength)])


def generateRandomLogin():
    """
    A simple script for making random passwords, WITHOUT 1,l,O,0.  Because
    those characters are hard to tell the difference between in some fonts.

    """
    return generateRandomPassword(6)


def createLDAPPassword(password, encoding='SHA'):
    """ Create a password string suitable for userPassword """
    if encoding == 'SSHA':
        pwd_str = '{SSHA}' + SSHA.encrypt(password)
    elif encoding == 'crypt':
        saltseeds = list('%s%s' % (string.lowercase[:26],
                                   string.uppercase[:26]))
        salt = ''
        for n in range(2):
            salt += random.choice(saltseeds)
        pwd_str = '{crypt}%s' % crypt.crypt(password, salt)
    elif encoding == 'md5':
        m = md5.new(password)
        pwd_str = '{md5}' + base64.encodestring(m.digest())
    elif encoding == 'clear':
        pwd_str = password
    else:
        sha_obj = sha.new(password)
        pwd_str = '{SHA}' + base64.encodestring(sha_obj.digest())

    return pwd_str.strip()
