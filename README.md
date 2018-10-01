# chkpwd
Check Passwords for complexity, length and character requirements. Uses Python Regular Expressions, argparse, and NamedTuple.

```bash
$ python3 -i chkpwd.py --password SECRET -v
$ python3 -i chkpwd.py -p 'secretSECRET123!@#' -l 10 -a 3 -A 3 -n 3 -s 3 -v
$ pytest -v -pdb --fulltrace chkpwd.py
$ coverage run -m pytest chkpwd.py && coverage html
$ cd htmlcov/ && python3 -m http.server
```