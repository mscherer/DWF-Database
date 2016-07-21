#!/usr/bin/python

# (c) 2016 Michael Scherer, <mscherer@redhat.com>
#
# This script is under the Apache Public License 2.0
#  

import csv
import sys
# TODO check the replaced_by
#        - check the format of the id
#        - check that the id is in the db
#        - check the state is correct

# add a better check for email
#
#
class MissingHeader(Exception):
    def __str__(self):
        return "The header of the file is not correct"

class IncorrectID(Exception):
    def __init__(self, incorrect_id):
        self._id = incorrect_id
    def __str__(self):
        return "The ID {} is incorrect".format(self._id)

class IncorrectMail(Exception):
    def __init__(self, mail):
        self._mail = mail
    def __str__(self):
        return "The mail {} is incorrect".format(self._mail)

class MissingDate(Exception):
    def __init__(self, vuln_id):
        self._id = vuln_id
    def __str__(self):
        return "The line for {} has a missing date".format(self._id)

class IncorrectState(Exception):
    def __init__(self, state):
        self._state = state
    def __str__(self):
        return "The state {} is incorrect".format(self._state)

def check_header(row):
    for i in ("DATE_REQUESTED","DATE_ASSIGNED","DATE_PUBLIC","REQUESTER","ASSIGNER","REPLACED_BY","VERSION","LAST_UPDATE","STATE","TITLE"):
        if not i in row:
            raise MissingHeader
    if not "CVE_ID" in row and not "DWF_ID" in row:
        raise MissingHeader

def check_email(email):
    if not '@' in email:
        raise IncorrectMail(email)

def check_date(row, date, can_be_null=False):
    if not can_be_null and date == '':
        raise MissingDate(get_vuln_id(row))

def get_vuln_id(row):
    if 'CVE_ID' in row:
        id_string = row['CVE_ID']
    else:
        id_string = row['DWF_ID']
    return id_string

already_seen = []
def check_id(row):
    id_string = get_vuln_id(row)
    id_parts = id_string.split('-')
    if len(id_parts) != 3:
        raise IncorrectID(id_string)

    if id_parts[0] not in ('CVE','DWF'):
        raise IncorrectID(id_string)
    # TODO add verification of the 2nd part and check the 3rd part too
    if id_string in already_seen:
        raise DuplicateID(id_string)

    already_seen.append(id_string)


def check_dates(row):
    check_date(row, row['DATE_REQUESTED'])
    check_date(row, row['DATE_ASSIGNED'])
    check_date(row, row['DATE_PUBLIC'], True)

def check_emails(row):
    check_email(row['REQUESTER'])
    check_email(row['ASSIGNER'])

def check_state(row):
    state = row['STATE']
    if state not in ['RESERVED','PUBLIC','REPLACED','REJECT']:
        raise IncorrectState(state)

f = sys.argv[1]
reader = csv.DictReader(open(f))
line = 0

for row in reader:
    if line == 0:
        check_header(row)
    else:
        check_id(row)
        check_dates(row)    
        check_emails(row)
        check_state(row)
    

    line += 1
