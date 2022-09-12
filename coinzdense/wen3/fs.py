#!/usr/bin/python3
import os
import json
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


def read_pw_protected_bin(infile, password):
    # FIXME: decrypt stuff here
    with open(infile, "rb") as inputfile:
        return infile.read()

def write_pw_protected_bin(seedfile, password, seed):
    # FIXME: encrypt stuff here
    with open(seedfile, "wb") as outputfile:
        return outputfile.write(seed)

class _HotKey:
    def __init__(self,
                 conf,
                 account,
                 vardir,
                 petname,
                 seed,
                 password):
        self.plainstate = os.path.join(vardir, "pubkeystate.json")
        self.keycache_dir = os.path.join(vardir, "private_cache")
        # FIXME
        


class _PasswordProtected:
    def __init__(self, conf, account, account_var_dir, key_petname):
        self.conf = conf
        self.account = account
        self.vardir = account_var_dir
        self.petname = key_petname
    def exists(self):
        return True
    def get_seed(self, password):
        seedfile = os.path.join(self.vardir, "private_seed.key")
        if not os.path.exists(seedfile):
            raise RuntimeError("Missing private_seed.key")
        return read_pw_protected_bin(seedfile, password)
    def decrypt(self, password):
        seed = self.get_seed(password)
        return _HotKey(self.conf, self.account, self.vardir, self.petname, seed, password)

class _Seedable:
    def __init__(self, conf, account, account_var_dir, key_petname):
        self.conf = conf
        self.account = account
        self.vardir = os.path.join(account_var_dir, key_petname)
        self.petname = key_petname
    def exists(self):
        return False
    def create(self, seed, password):
        if os.path.exists(self.vardir):
            raise RuntimeError("Can call create on _Seedable only once:" + self.vardir)
        os.mkdir(self.vardir)
        seedfile = os.path.join(self.vardir, "private_seed.key")
        write_pw_protected_bin(seedfile, password, seed)
        return _HotKey(self.conf, self.account, self.vardir, self.petname, seed, password)

class _AccountEnv:
    def __init__(self, conf, name, vardir):
        self.conf = conf
        self.name = name
        self.vardir = vardir
    def __get_item__(self, petname):
        keyvardir = os.path.join(self.vardir, petname)
        if not os.path.exists(accountvar):
            raise RuntimeError("Asked for a non-existing subkey: " + petname)
        return _PasswordProtected(self.conf, self.name, self.vardir, petname)
    def __call__(self):
        keyvardir = os.path.join(self.vardir, "OWNER")
        if not os.path.exists(keyvardir):
            return _Seedable(self.conf, self.name, self.vardir, "OWNER")
        return _PasswordProtected(self.conf, self.name, self.vardir, "OWNER")

class _AppEnv:
    def __init__(self, appconf, vardir):
        self.conf = appconf
        self.vardir = vardir
    def __getitem__(self, accountname):
        accountvar = os.path.join(self.vardir,accountname)
        if not os.path.exists(accountvar):
            os.mkdir(accountvar)
        return _AccountEnv(self.conf, accountname, accountvar)


class FsEnv:
    def __init__(self,
                 minimum_keyspace_usage_percentage=0.0):
        self.minimum = minimum_keyspace_usage_percentage
        owndir = os.path.join(os.path.expanduser("~"), ".coinzdense")
        etcdir = os.path.join(owndir,"etc")
        self.vardir = os.path.join(owndir,"var")
        if not os.path.exists(owndir):
            os.mkdir(owndir)
        if not os.path.exists(etcdir):
            os.mkdir(etcdir)
        if not os.path.exists(self.vardir):
            os.mkdir(self.vardir)
        fsroot = os.path.abspath('.').split(os.path.sep)[0]+os.path.sep
        etcdirlist = [etcdir]
        globaletc = os.path.join(os.path.join(fsroot, "etc"), "coinzdense.d")
        localetc = os.path.join(os.path.join(os.getcwd(), "etc"), "coinzdense.d")
        if os.path.exists(globaletc):
            etcdirlist.append(globaletc)
        if os.path.exists(localetc):
            etcdirlist.append(localetc)
        self.confmap = {}
        for mydir in etcdirlist:
            if os.path.isdir(mydir):
                for filename in os.listdir(mydir):
                    if os.path.splitext(filename)[1].lower() == ".yml":
                        fullpath = os.path.join(mydir, filename)
                        if os.path.isfile(fullpath):
                            with open(fullpath, encoding="utf8") as yamlfile:
                                try:
                                    content = load(yamlfile, Loader=Loader)
                                except ValueError:
                                    content = {}
                            if "appname" in content and isinstance(content["appname"], str):
                                appname = content["appname"]
                                if appname not in self.confmap:
                                    self.confmap[appname] = content

    def __getitem__(self, appname):
        if appname in self.confmap:
            app_var_dir = os.path.join(self.vardir, appname)
            if not os.path.exists(app_var_dir):
                os.mkdir(app_var_dir)
            return _AppEnv(self.confmap[appname], app_var_dir)
        else:
            raise KeyError("No coinZdense Wen3 blockchain RC named " + appname)

if __name__ == "__main__":
    env = FsEnv()
    ownerenv = env["HIVEISH"]["pibara"]()
    if not ownerenv.exists():
        hotkey = ownerenv.create(b"xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx","DumbPasssssssWord1234#")

