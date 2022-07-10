#!/usr/bin/python3
"""Experimental code for new YAML based application-RC app config"""
import json
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

def _params_to_chunk_count(hashlen, otsbits):
    return (hashlen * 8 + otsbits -1) // otsbits

def _params_to_per_signature_index_space(hashlen, otsbits):
    # *2 : secret_up + secret_down
    # +2 : + transaction salt + misc seed/salt
    return _params_to_chunk_count(hashlen, otsbits) *2 + 2


def _params_to_index_space(hashlen, otsbits, heights):
    lowest_level_signing_space = (1 << sum(heights)) * _params_to_per_signature_index_space(hashlen, otsbits)
    if len(heights) > 1:
        lowest_level_level_key_salts = 1 << sum(heights[:-1])
        return lowest_level_signing_space + \
                lowest_level_level_key_salts + \
                _params_to_index_space(hashlen, otsbits, heights[:-1])
    return lowest_level_signing_space + 1

def _check_heights(val):
    if not isinstance(val, list):
        raise ApplicationRcError("1 heights should be a list of integers: " + str(val))
    if len(val) < 2 or len(val) > 32:
        raise ApplicationRcError("heights should be alist of two upto thirty two integers")
    for height in val:
        if not isinstance(height, int):
            raise ApplicationRcError("2 heights should be a list of integers: " + str(height))
        if height < 3 or height >16:
            raise ApplicationRcError("height should be a value from the range 3..16")

def _check_subkeys(val):
    if not isinstance(val, list):
        raise ApplicationRcError("subkeys should be a list of objects")
    for subobj in val:
        if not isinstance(subobj, dict):
            raise ApplicationRcError("subkey should be a list of objects")
        if "typ" in subobj and subobj["typ"] == "default":
            for key2,val2 in subobj.items():
                if key2 not in ["typ", "heights","shared", "allocated"]:
                    raise ApplicationRcError("Invalid dictionary key in defaults section of subkeys: " + key2)
                if key2 == "heights":
                    _check_heights(val2)
                if key2 in ["shared", "allocated"]:
                    if (not isinstance(val2, int)) or (val2 < 0):
                        raise ApplicationRcError("A shared or allocated must be a non-negative integer")

def _check_object(obj, parent):
    for key,val in obj.items():
        if key in ["heights", "subkeys"]:
            if key == "heights":
                _check_heights(val)
            else:
                _check_subkeys(val)
        elif parent is None and key in ["appname", "hashlen", "otsbits"]:
            if key == "appname" and not isinstance(val, str):
                raise ApplicationRcError("appname should be a string")
            if key == "hashlen" and (not isinstance(val, int) or val < 16 or val > 64):
                raise ApplicationRcError("hashlen should be an integer in the range 16..64")
            if key == "otsbits" and  (not isinstance(val, int) or val < 4 or val > 16):
                raise ApplicationRcError("otsbits should be an integer in the range 4..16")
        elif parent is not None and key in ["name", "shared", "allocated"]:
            if key == "name" and not isinstance(key, str):
                raise ApplicationRcError("name should be a string")
        else:
            if key in ["appname", "hashlen", "otsbits", "name", "shared", "allocated"]:
                if parent is None:
                    raise ApplicationRcError("Entry not a valid dictionary key for top-level node in Application RC:" + key)
                raise ApplicationRcError("Entry not a valid dictionary key for sub-level node in Application RC:" + key)
            raise ApplicationRcError("Entry not a valid dictionary key for Application RC:" + key)

class ApplicationRcError(ValueError):
    """Exception for Application RC value errors"""

class RcSubKey:
    """Application RC data abstraction for top and sub keys"""
    def __init__(self, obj, parent=None, default=None, minimum=0.0):
        _check_object(obj, parent)
        if parent is None:
            if "appname" in obj:
                self.node = [obj["appname"]]
            else:
                raise ApplicationRcError("Missing mandatory 'appname' from application RC")
            if "hashlen" in obj:
                self.hashlen = obj["hashlen"]
            else:
                self.hashlen = 16
            if "otsbits" in obj:
                self.otsbits = obj["otsbits"]
            else:
                self.otsbits = 4
            if "heights" in obj:
                self.heights = obj["heights"]
            else:
                raise ApplicationRcError("Missing mandatory 'heights' from applicatio  RC")
            self.allocated = 1
            self.shared = 1
            self.default = {}
            self.subkeys = []
            if "subkeys" in obj:
                for subkey in obj["subkeys"]:
                    if "typ" in subkey and subkey["typ"] == "default":
                        self.default = subkey
                    else:
                        self.subkeys.append(subkey)
            self.check(minimum=minimum)
        else:
            self._init_sub(obj, parent, default)
    def _init_sub(self,obj, parent, default):
        if default is None:
            raise ApplicationRcError("default should not be None if parent is defined")
        if "name" not in obj:
            raise ApplicationRcError("Subkey should have a name:" + str(obj))
        self.node = parent.node[:]
        self.node.append(obj["name"])
        self.hashlen = parent.hashlen
        self.otsbits = parent.otsbits
        if "heights" in obj:
            self.heights = obj["heights"]
        elif "heights" in default:
            self.heights = default["heights"]
        else:
            self.heights = parent.heights
        if "allocated" in obj:
            self.allocated = obj["allocated"]
        elif "allocated" in default:
            self.allocated = default["allocated"]
        else:
            self.allocated = 0
        if "shared" in obj:
            self.shared = obj["shared"]
        elif "shared" in default:
            self.shared = default["shared"]
        else:
            if self.allocated <= 0:
                raise ApplicationRcError("Either allocated or shared must be defined for subkey " + str(self.node))
            self.shared = 0
        self.default = {}
        self.subkeys = []
        if "subkeys" in obj:
            for subkey in obj["subkeys"]:
                if "typ" in subkey and subkey["typ"] == "default":
                    self.default = subkey
                else:
                    self.subkeys.append(subkey)
    def index_space(self):
        """Get the amount of index space that this level could allocate"""
        ownkey_space = _params_to_index_space(self.hashlen, self.otsbits, self.heights)
        biggest_shared = 0
        total_reserved = 0
        for subkey in self.subkeys:
            child = RcSubKey(subkey, self, self.default)
            one_child_size = sum(child.index_space())
            shared_candidate = one_child_size * self.shared
            if shared_candidate > biggest_shared:
                biggest_shared = shared_candidate
            total_reserved += one_child_size * self.allocated
        return [ownkey_space, total_reserved, biggest_shared]

    def reserved_count(self):
        """Reserved number of signatures for this key"""
        rval = 0
        for subkey in self.subkeys:
            child = RcSubKey(subkey, self, self.default)
            rval += child.allocated
        return rval

    def total_count(self):
        """Total number of signatures possible for this key"""
        return 1 << sum(self.heights)

    def check(self, minimum=0.0):
        """Check key and all subkeys in application RC"""
        total_index_space = sum(self.index_space())
        for subkey in self.subkeys:
            to_test = RcSubKey(subkey, self, self.default)
            to_test.check()
        percentage = total_index_space * 100.0 / float(1 << 64)
        if len(self.node) == 1 and percentage < minimum:
            raise ApplicationRcError("Maximum allocatable index space is lower than the check treshold of " + \
                    str(minimum) + \
                    "% (" + str(percentage) + "%)")
        if percentage > 100.0:
            raise ApplicationRcError("Maximum allocatable index space exceeds the maximum available index space " + \
                    str(percentage) + "% used",str(self.node))
        return percentage

    def __getitem__(self, key):
        """Get a subkey node"""
        for subkey in self.subkeys:
            if subkey["name"] == key:
                return RcSubKey(subkey, self, self.default)
        raise KeyError(key)

class KsSubKey:
    """Key-space abstraction for top level and sub keys"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self,
                 rckey,
                 offset=0,
                 kssize=1<<64,
                 old_state=None,
                 sync=None,
                 blockchain_state=None,
                 parent_sign_index=0):
        # pylint: disable=too-many-arguments
        # The rckey could be the actual rckey or one of its ancestors
        self.rckey = rckey
        # If its not the actual rckey, try to walk the parent
        if old_state and old_state["node"] != rckey.node:
            if len(rckey.node) < len(old_state.node):
                # If the ancestor node array thoesn't match the start of the old_state node,
                #   then it can't be a valid ancestor rcnode
                if old_state.node[:len(rckey.node)] != rckey.node:
                    raise RuntimeError("Resource key is not a possible ancestor (2)")
                # Walk the RC-node tree till we get the proper node
                for nextnode in old_state.node[len(rckey.node)]:
                    self.rckey = self.rckey[nextnode]
            else:
                # The lengths exclude the posibility that this might be an rcnode ancestor
                raise RuntimeError("Resource key is not a possible ancestor (1)")
        # Get two main attributes from the rckey
        self.reserved_count = rckey.reserved_count()
        self.total_count = rckey.total_count()
        # If there is no old state, create a state dict from scratch
        if old_state is None:
            sizes = rckey.index_space()
            self.state = {}
            self.state["keyspace_offset"] = offset
            self.state["keyspace_end_offset"] = offset + kssize -1
            self.state["heap_offset"] = offset + sizes[0]
            self.state["reserved_index"] = 0
            self.state["regular_index"] = self.reserved_count
            self.state["heap_pointer"] = self.state["heap_offset"]
            self.state["parent_sign_index"] = parent_sign_index
            self.state["node"] = rckey.node
        else:
            # If there is old_state, use the old state
            self.state = old_state
            # If there is blockchain state to consider (if multiple clients use the same key) use the highest values.
            if blockchain_state is not None:
                if blockchain_state["reserved_index"] > self.state["reserved_index"]:
                    self.state["reserved_index"] = blockchain_state["reserved_index"]
                if blockchain_state["regular_index"] > self.state["regular_index"]:
                    blockchain_state["regular_index"] = self.state["regular_index"]
                if blockchain_state["heap_pointer"] > self.state["heap_pointer"]:
                    blockchain_state["heap_pointer"] = self.state["heap_pointer"]
        # set the sync functor
        self.sync = sync
        if self.sync is not None:
            self.sync(self.state)

    def __getitem__(self, key):
        """Actively get a sub key and take full responsibility"""
        rckey = self.rckey[key]
        if self.state["regular_index"] < self.total_count:
            myindex = self.state["regular_index"]
            self.state["regular_index"] += 1
        elif self.state["reserved_index"] < self.reserved_count:
            myindex = self.state["reserved_index"]
            self.state["reserved_index"] += 1
        else:
            raise RuntimeError("Exausted reserved key index")
        myoffset = self.state["heap_pointer"]
        mysize = sum(rckey.index_space())
        if self.state["heap_pointer"] + mysize - 1 > self.state["keyspace_end_offset"]:
            raise RuntimeError("Ran out of keyspace heap")
        self.state["heap_pointer"] += mysize
        if self.sync is not None:
            self.sync(self.state)
        return KsSubKey(rckey, myoffset, mysize, parent_sign_index=myindex, sync=self.sync)

    def set_sync(self,sync):
        """Set the sync functor"""
        self.sync = sync
        self.sync(self.state)

    def set_petname(self, petname):
        self.sync.set_petname(petname, self.state["parent_sign_index"])

    def signing_index(self):
        """Actively get a signing index"""
        if self.state["regular_index"] < self.total_count:
            myindex = self.state["regular_index"]
            self.state["regular_index"] += 1
            if self.sync is not None:
                self.sync(self.state)
            return myindex
        raise RuntimeError("Exausted main key index")

class FileState:
    def __init__(self, path):
        self.path = path
        try:
            with open(self.path) as statefile:
                self.state = dict(json.load(statefile))
        except:
            self.state = {}
            self.state["keys"] = {}
            self.state["petnames"] = {}
            self.state["petnames"]["OWNER"] = 0
    def __call__(self, obj):
        self.state["keys"][str(obj["parent_sign_index"])] = obj
        with open(self.path,"w") as statefile:
            json.dump(self.state, statefile, indent=1)
    def set_petname(self, index, petname):
        self.state["petnames"][index] = petname
        with open(self.path,"w") as statefile:
            json.dump(self.state, statefile, indent=1)



with open("etc/coinzdense.d/hiveish.yml", encoding="utf8") as apprc:
    data = load(apprc, Loader=Loader)

fs = FileState("state.json")
owner_key = KsSubKey(RcSubKey(data, minimum=20.0), sync=fs)
print(owner_key.signing_index())
print(owner_key.signing_index())
print(owner_key.signing_index())
print(owner_key.signing_index())
print(owner_key.signing_index())
active1 = owner_key["ACTIVE"]
active1.set_petname("ACTIVE")
active2 = owner_key["ACTIVE"]
active2.set_petname("SPARE_ACTIVE")

