#! /usr/bin/python3

# Check Passwords for complexity, length and character requirements.
# Uses Python Regular Expressions, argparse, and NamedTuple.
# This project was started 18 December 2016 on Python 3.5

# $ python3 -i chkpwd.py --password SECRET -v
# $ python3 -i chkpwd.py -p 'secretSECRET123!@#' -l 10 -a 3 -A 3 -n 3 -s 3 -v

# TODO Accept passwords in stdin. Newline seperates passwords, EOF ends input (Ctrl-D).
# TODO modfiy output to inlcude the password tested

import argparse
import re

import collections

DEFAULT_SPECIAL_CHAR = '!@#$%^&*.'


def main():
    parser = build_parser()
    args = parse_args(parser)
    
    # go into input loop if password was not provided
    # TODO print(args.password)
    if not args.password:
        try:
            while True:
                args.password = input()
                
                if check_password(**vars(args)):
                    print('PASSED - All tests passed.')
        
        except Exception as exception:
            print(exception)
    else:
        if check_password(**vars(args)):
            print('PASSED - All tests passed.')


def check_password(password='', length=0, lower=0, upper=0, number=0, special=0, special_charset=DEFAULT_SPECIAL_CHAR, verbose=False, **extra_args):
    passed = True
    tests = []

    PasswordTest = collections.namedtuple('PasswordTest', ['name', 'value', 'regex'])

    if length:
        tests.append(PasswordTest('length', length, r'.{' + str(length) + ',}'))

    if lower:
        str_regex_lower = r''

        for count in range(lower):
            str_regex_lower += r'[a-z].*'

        str_regex_lower = str_regex_lower[:-2]

        tests.append(PasswordTest('lower', lower, str_regex_lower))

    if upper:
        str_regex_upper = r''

        for count in range(upper):
            str_regex_upper += r'[A-Z].*'

        str_regex_upper = str_regex_upper[:-2]

        tests.append(PasswordTest('upper', upper, str_regex_upper))

    if number:
        str_regex_number = r''

        for count in range(number):
            str_regex_number += r'\d.*'

        str_regex_number = str_regex_number[:-2]

        tests.append(PasswordTest('number', number, str_regex_number))

    if special:
        str_regex_special = r''

        for count in range(special):
            str_regex_special += r'[' + special_charset + r'].*'

        str_regex_special = str_regex_special[:-2]

        tests.append(PasswordTest('special', special, str_regex_special))

    for test in tests:
        if verbose:
            print('Testing ' + test.name + ': ' + str(test.value))

        compiled_regex = re.compile(test.regex)

        if verbose:
            print('\tRegex for ' + test.name + ': ' + test.regex)

        regex_result = compiled_regex.search(password)

        if not regex_result:
            print('FAILED - Password failed ' + test.name + ' requirement.')
            passed = False
        else:
            if verbose:
                print('\t' + test.name + '  regex result: ' + regex_result.group())
                print('\tPassed ' + test.name)

    return passed


def parse_args(parser):
    # execute command parser
    args = parser.parse_args()
    if args.verbose:
        print('Verbose mode.')
        print('Password is: ' + args.password)
        print('Settings are:')
        print('\tlength: ' + str(args.length))
        print('\tlower-case: ' + str(args.lower))
        print('\tupper-case: ' + str(args.upper))
        print('\tspecial: ' + str(args.special))
        print('\tspecial set: ' + args.set)
        print('\tnumber: ' + str(args.number))
        print('')
    return args


def build_parser():
    parser = argparse.ArgumentParser(description='Check if a password meets complexity requirements')
    parser.add_argument('--password', '-p', help='password to check', default='')
    parser.add_argument('--length', '-l', help='minimum length of password, default is 0', default=0, type=int)
    parser.add_argument('--lower', '-a', help='number of lower-case alphabet letters required, default is 0', default=0, type=int)
    parser.add_argument('--upper', '-A', help='number of upper-case alphabet letters required, default is 0', default=0, type=int)
    parser.add_argument('--special', '-s', help='number of special characters required, default is 0', default=0, type=int)
    # argparse note: % must be escaped to print in argparse help strings because %-formatting is supported.
    parser.add_argument('--set', help='set of special characters allowed, default is \'!@#$%%^&*.\'', default=DEFAULT_SPECIAL_CHAR, type=str)
    parser.add_argument('--number', '-n', help='number of numeric characters required, default is 0', default=0, type=int)
    parser.add_argument('--verbose', '-v', help='enable verbose mode', action='store_true')
    return parser


def test_main(monkeypatch):
    # need to mock parse_args()
    global parse_args 
    # save the function to restore at the end
    temp_parse_args = parse_args
    parse_args = lambda args: settings
    
    # create named tuple to mock the argparse.Namespace oject
    # Settings = collections.namedtuple('Settings', ['verbose', 'password', 'length', 'lower', 'upper', 'special', 'set', 'number'])

    # create class to mock argparse.Namespace object
    class Settings(object):
        # def __init__(self, verbose=True, password='', length=0, lower=0, upper=0, special=0, set=DEFAULT_SPECIAL_CHAR, number=0):
        def __init__(self, **attrs):
            for attr in attrs:
                self.__setattr__(attr, attrs[attr])

    # test with password
    settings = Settings(verbose=True, password='pasword123', length=0, lower=0, upper=0, special=0, set='!@#', number=0)
    main() 
    
    # test without password
    settings = Settings(verbose=True, password='', length=0, lower=0, upper=0, special=0, set='!@#', number=0)
    
    # DEBUG
    # import pdb; pdb.set_trace()
    
    # mock input()
    input_list_iter = iter(['password123', 'password123', 'password123'])
    monkeypatch.setattr('builtins.input', lambda **kw: next(input_list_iter))
    assert input()=='password123'
    main()

    # done testing, restore the function
    parse_args = temp_parse_args


def test_parse_args():
    # build mock for argparse.parser.parse_args()
    Settings = collections.namedtuple('Settings', ['verbose', 'password', 'length', 'lower', 'upper', 'special', 'set', 'number'])
    settings = Settings(verbose=True, password='', length=0, lower=0, upper=0, special=0, set='!@#', number=0)
    
    parser = build_parser()
    parser.parse_args = lambda: settings
    
    # lambda: {'verbose': True, 'password': '', 'length': 0, 'lower': 0, 'upper': 0, 'special': 0, 'set': '!@#', 'number': 0}
    parse_args(parser)


def test_build_parser():
    parser = build_parser()

    # test 1
    args = parser.parse_args(['-v', '--password', 'SECRET'])
    assert args.password == 'SECRET'
    assert args.verbose

    # test 2
    # -p secretSECRET123!@# -l 10 -a 3 -A 3 -n 3 -s 3 -v
    args = parser.parse_args(['-v', '-p', 'secretSECRET123!@#', '-l', '10', '-a', '3', '-A', '3', '-n', '3', '-s', '3'])
    assert args.password == 'secretSECRET123!@#'
    assert args.verbose
    assert args.length == 10


def test_check_password():
    parser = build_parser()

    def test(args, expected):
        parsed = parser.parse_args(args)
        result = check_password(parsed.password, length=parsed.length, lower=parsed.lower, upper=parsed.upper,
                                number=parsed.number, special=parsed.special, special_charset=parsed.set,
                                verbose=parsed.verbose)
        assert result == expected

    test(['-v', '--password', 'SECRET'], True)
    test(['-v', '--password', 'SECRET', '-l', '4'], True)
    test(['-v', '--password', 'SECRET', '-l', '10'], False)
    test(['-v', '--password', 'secret', '-a', '4'], True)
    test(['-v', '--password', 'secret', '-a', '10'], False)
    test(['-v', '--password', '0s1e2c3r4e5t6', '-a', '10'], False)
    test(['-v', '--password', 'SECRET', '-A', '4'], True)
    test(['-v', '--password', 'SECRET', '-A', '10'], False)
    test(['-v', '--password', '12345', '-n', '4'], True)
    test(['-v', '--password', '12345', '-n', '10'], False)
    test(['-v', '--password', '0s1e2c3r4e5t6', '-n', '4'], True)
    test(['-v', '--password', '0s1e2c3r4e5t6', '-n', '10'], False)
    test(['-v', '--password', '0S1E2CRETsecr!e@t#', '-s', '3'], True)
    test(['-v', '--password', '0S1E2CRETsecr!e@t#', '-s', '10'], False)
    test(['-v', '--password', '0S1E2CRETsecr!e@t#', '-l', '10', '-a', '3', '-A', '3', '-n', '3', '-s', '3'], True)
    test(['-v', '--password', '0S1E2CRETsecr!e@t#', '-s', '3', '--set', r',./<>?'], False)
    test(['-v', '--password', r'0S1E<2>C/\xRETsecr', '-s', '3', '--set', r',./\<>?'], True)


if __name__ == '__main__':
    main()
