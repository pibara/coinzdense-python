#!/usr/bin/python3
from coinzdense.signing import SigningKey as _SigningKey
from coinzdense.validation import ValidationEnv as _ValidationEnv
from coinzdense.wallet import create_wallet as _create_wallet
from coinzdense.wallet import open_wallet as _open_wallet

def _keys_per_signature(hashlen, otsbits):
    return 2*(((hashlen*8-1) // otsbits)+1)

def _sub_sub_keyspace_usage(hashlen, otsbits, height):
    return 1 + _keys_per_signature(hashlen, otsbits) * (1 << height)

def _sub_keyspace_usage(hashlen, otsbits, heights):
    usage = _sub_sub_keyspace_usage(hashlen, otsbits,heights[0])
    if len(heights) > 1:
        usage += (1 << heights[0]) * _sub_keyspace_usage(hashlen, otsbits, heights[1:])
    return usage

def _keyspace_usage(hashlen, otsbits, keyspace):
    usage = (1 << sum(keyspace[0]["heights"])) + _sub_keyspace_usage(hashlen, otsbits, keyspace[0]["heights"])
    if len(keyspace) > 1:
        usage += (1 << keyspace[0]["reserve"]) * _keyspace_usage(hashlen, otsbits, keyspace[1:])
    return usage

class KeySpace:
    def __init__(self, hashlen, otsbits, keyspace, offset=0, size=1<<64, state=None):
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.keyspace = keyspace
        if state is None:
            self.state = {}
            self.state["offset"] = offset
            self.state["stack"] = size
            reserve_bits = keyspace[0].get("reserve", None)
            if reserve_bits is None:
                self.state["heap_start"] = offset
                self.state["heap"] = offset
                self.state["has_reserved"] = False
                self.state["reserved_heap_start"] = offset
                self.state["reserved_heap"] = offset
            else:
                reserved = (1 << reserve_bits) * _keyspace_usage(hashlen, otsbits, keyspace[1:])
                self.state["heap_start"] = offset + reserved
                self.state["heap"] = offset + reserved
                self.state["has_reserved"] = True
                self.state["reserved_heap_start"] = offset
                self.state["reserved_heap"] = offset
            self.state["own_offset"] = self.state["heap"]
            self.state["heap"] += (1 << sum(keyspace[0]["heights"])) + _sub_keyspace_usage(hashlen, otsbits, keyspace[0]["heights"])
        else:
            self.state = state
    def own_offset(self):
        return self.state["own_offset"]
    def allocate_subspace(self):
        keyspace_size = _keyspace_usage(hashlen, otsbits, keyspace[1:])
        self.state["stack"] -= keyspace_size
        return KeySpace(self.hashlen, self.otsbits, self.keyspace[1:], self.state["stack"], keyspace_size)
    def get_state(self):
        return self.state

class BlockChainEnv:
    def __init__(self, conf):
        assert "appname" in conf, "Please run coinzdense-lint on your blockchain RC"
        assert "hashlen" in conf, "Please run coinzdense-lint on your blockchain RC"
        assert "otsbits" in conf, "Please run coinzdense-lint on your blockchain RC"
        assert "keyspace" in conf, "Please run coinzdense-lint on your blockchain RC"
        self.appname = conf["appname"]
        self.hashlen = conf["hashlen"]
        self.otsbits = conf["otsbits"]
        self.keyspace = conf["keyspace"]
        if "hierarchy" in conf:
            self.hierarchy = conf["hierarchy"]
        else:
            self.hierarchy = {}
        if "sub_path" in conf:
            self.subpath = conf["sub_path"]
        else:
            self.subpath = []
        assert isinstance(self.appname, str), "Please run coinzdense-lint on your blockchain RC"
        assert isinstance(self.hashlen, int), "Please run coinzdense-lint on your blockchain RC"
        assert isinstance(self.otsbits, int), "Please run coinzdense-lint on your blockchain RC"
        assert isinstance(self.keyspace, list), "Please run coinzdense-lint on your blockchain RC"
        assert isinstance(self.hierarchy, dict), "Please run coinzdense-lint on your blockchain RC"
        assert isinstance(self.subpath, list), "Please run coinzdense-lint on your blockchain RC"
        assert self.hashlen > 15
        assert self.hashlen < 65
        assert self.otsbits > 3
        assert self.otsbits < 17
        self.depth = 0
        self._check_hierarchy()
        for idx, val in enumerate(self.keyspace):
            assert isinstance(val, dict), "Please run coinzdense-lint on your blockchain RC"
            total_height = 0
            assert "heights" in val, "Please run coinzdense-lint on your blockchain RC"
            assert isinstance(val["heights"], list), "Please run coinzdense-lint on your blockchain RC"
            assert len(val["heights"]) > 1, "Please run coinzdense-lint on your blockchain RC"
            assert len(val["heights"]) < 33, "Please run coinzdense-lint on your blockchain RC"
            for idx2,height in enumerate(val["heights"]):
                assert isinstance(height, int), "Please run coinzdense-lint on your blockchain RC"
                assert height > 2, "Please run coinzdense-lint on your blockchain RC"
                assert height < 17, "Please run coinzdense-lint on your blockchain RC"
                total_height += height
            if idx < len(self.keyspace) -1:
                assert "reserve" in val, "Please run coinzdense-lint on your blockchain RC"
                assert isinstance(val["reserve"], int), "Please run coinzdense-lint on your blockchain RC"
                assert val["reserve"] > 1, "Please run coinzdense-lint on your blockchain RC"
                assert val["reserve"] < total_height - 1, "Please run coinzdense-lint on your blockchain RC"
            else:
                assert "reserve" not in val, "Please run coinzdense-lint on your blockchain RC"
        for subpath_part in self.subpath:
            assert isinstance(subpath_part, str), "Please run coinzdense-lint on your blockchain RC"
        total = _keyspace_usage(self.hashlen, self.otsbits, self.keyspace)
        assert total.bit_length() < 65, "Please run coinzdense-lint on your blockchain RC"

    def _check_hierarchy(self, sub_hierarchy=None, depth=0):
        if sub_hierarchy is not None:
            my_hierarchy = sub_hierarchy
        else:
            my_hierarchy = self.hierarchy
        my_depth = depth + 1
        if my_depth > self.depth:
            self.depth = my_depth
        for key, val in my_hierarchy.items():
            assert isinstance(val, dict), "Please run coinzdense-lint on your blockchain RC"
            self._check_hierarchy(val, my_depth)

    def __getitem__(self, key):
        if key in self.hierarchy:
            subconf = {}
            subconf["appname"] = self.appname
            subconf["hashlen"] = self.hashlen
            subconf["otsbits"] = self.otsbits
            subconf["keyspace"] = self.keyspace[1:]
            subconf["hierarchy"] = self.hierarchy[key]
            subconf["sub_path"] = self.subpath[:] + [key]
            return BlockChainEnv(subconf)
        else:
            raise KeyError("No sub-key hierarchy named " + key)

    def get_signing_key(self, wallet, idx=0, idx2=0, backup=None):
        path = [self.appname] + self.subpath
        return _SigningKey(self.hashlen, self.otsbits, self.keyspace, path, self.hierarchy, wallet, idx, idx2, backup)

    def get_validator(self):
        path = [self.appname] + self.subpath
        return _ValidationEnv(self.hashlen, self.otsbits, self.keyspace, path, self.hierarchy)

    def create_wallet(self, salt, key, password):
        path = [self.appname] + self.subpath
        return _create_wallet(salt, key, password, path)

    def open_wallet(self, wdata, password):
        path = [self.appname] + self.subpath
        return _open_wallet(wdata, password, path)
