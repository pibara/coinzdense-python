#!/usr/bin/python3
"""Experimental code for the Web3 Entropy management layer (Wen3) YAML based application-RC app config"""
import json
import os
import asyncio
from concurrent.futures import ProcessPoolExecutor
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

def _params_to_chunk_count(hashlen, otsbits):
    """Calculate how many one-time signature chunks are needed for a whole one-time signature"""
    return (hashlen * 8 + otsbits -1) // otsbits

def _params_to_per_signature_index_space(hashlen, otsbits):
    """Calculate how much WEN3 enropy key space is needed for a single signature"""
    # Twice the number of one-time signature chunks plus a transaction salt plus misc entropy with diverse uses.
    return _params_to_chunk_count(hashlen, otsbits) *2 + 2

def _params_to_index_space(hashlen, otsbits, heights):
    """Calculate how much WEN3 entropy key space is needed for a whole multi-level signing key"""
    # The WEN3 entropy key space needed for the currently lowest level of the multi-level signing key.
    #  This is the max number of signatures times the amount of WEN3 entopy key space for a single signature.
    lowest_level_signing_space = (1 << sum(heights)) * _params_to_per_signature_index_space(hashlen, otsbits)
    if len(heights) > 1:
        # If _params_to_index_space was invoked at a non-root level-key level, we calculate how many level-key
        #  salts we need at the lowest level.
        lowest_level_level_key_salts = 1 << sum(heights[:-1])
        # The return value is the WEN3 entropy kay-space for the lowest level level-keys plus the result of invoking
        #  _params_to_index_space for all the higer level level-keys.
        return lowest_level_signing_space + \
                lowest_level_level_key_salts + \
                _params_to_index_space(hashlen, otsbits, heights[:-1])
    # If _params_to_index_space was invoked on the root level layer key of the signing key, return one (level salt)
    #  plus the amount needed for signatures at the root leval.
    return lowest_level_signing_space + 1

def _params_to_level_offset_and_size(offset, hashlen, otsbits, heights):
    if len(heights) > 1:
        offset2, rval = _params_to_level_offset_and_size(offset, hashlen, otsbits, heights[:-1])
    else:
        offset2 = offset
        rval = []
    lowest_level_signing_space = (1 << sum(heights)) * _params_to_per_signature_index_space(hashlen, otsbits)
    if len(heights) > 1:
        lowest_level_level_key_salts = 1 << sum(heights[:-1])
    else:
        lowest_level_level_key_salts = 1
    lowest_level_onekey_signing_space = (1 << heights[-1]) * _params_to_per_signature_index_space(hashlen, otsbits) + 1
    next_level_offset = offset2 + lowest_level_signing_space + lowest_level_level_key_salts
    rval.append([offset2, lowest_level_onekey_signing_space])
    return next_level_offset, rval

def _main_index_to_levelkey_indices(index, heights, top=True):
    if len(heights) == 1:
        if index >= 1 << heights[0]:
            raise RuntimeError("index out of range: " + str(index) + " > " + str(1 << sum(heights)))
        return []
    firstval = index // (1 << sum(heights[1:]))
    rest = _main_index_to_levelkey_indices(index, [heights[0] + heights[1]] + heights[2:], False)
    rval = [firstval] + rest
    if top:
        return [0] + rval
    return rval

def _heights_to_prealocate_constant(heights):
    if len(heights) == 2:
        return 1 << heights[0]
    return _heights_to_prealocate_constant(heights[:-1]) + (1 << heights[-2])

def _heights_to_prealocate_forward(heights, eagerness=1.0):
    return int(_heights_to_prealocate_constant(heights)*eagerness)

def _main_index_to_levelkey_indices_full(index, heights, eagerness=1.0):
    rval_done = []
    rval1 = _main_index_to_levelkey_indices(index, heights)
    if index > 0:
        rval0 = _main_index_to_levelkey_indices(index-1, heights)
        for fromval, toval in zip(rval0, rval1):
            subrval = []
            for val in range(fromval, toval):
                subrval.append(val)
            rval_done.append(subrval)
    extra = _heights_to_prealocate_forward(heights, eagerness)
    maxindex = index+extra
    if maxindex >= (1 << sum(heights)):
        maxindex = (1 << sum(heights)) -1
    rval2 = _main_index_to_levelkey_indices(maxindex, heights)
    rval = []
    for fromval, toval in zip(rval1, rval2):
        subrval = []
        for val in range(fromval, toval+1):
            subrval.append(val)
        rval.append(subrval)
    return list(zip(rval, rval_done)), False

def _heights_index_to_indexlist(heights, index):
    if len(heights) == 0:
        return []
    return [index // (1 << sum(heights[1:]))] + _heights_index_to_indexlist(heights[1:], index % (1 << sum(heights[1:])))

def _heights_index_to_lkindex(heights, rindex, index, rdif, idif, nr):
    rval = [[],[]]
    if rindex == 0:
        rval[0].append([])
    else:
        rval[0].append([0] + _heights_index_to_indexlist(heights, rindex-1)[:-1])
    if index == nr:
        rval[1].append([])
    else:
        rval[1].append([0] + _heights_index_to_indexlist(heights, index-1)[:-1])
    rval[0].append([0] + _heights_index_to_indexlist(heights, rindex)[:-1])
    rval[1].append([0] + _heights_index_to_indexlist(heights, index)[:-1])
    rval[0].append([0] + _heights_index_to_indexlist(heights, rindex + rdif)[:-1])
    rval[1].append([0] + _heights_index_to_indexlist(heights, index + idif)[:-1])
    return rval

def _check_heights(val):
    """Assertion type chacks for application-RC heights data"""
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
    """Assertion type checks for application-RC subkeys data"""
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
    # pylint: disable=too-many-branches
    """Assertion type chacks for a authority attenuation level node"""
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
    # pylint: disable=too-many-instance-attributes
    """Application RC data abstraction for top and sub keys"""
    def __init__(self, obj, parent=None, default=None, minimum=0.0):
        # pylint: disable=too-many-branches
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
        # pylint: disable=too-many-branches
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
                 parent_sign_index=-1,
                 statedir=None,
                 account=None,
                 seed=None):
        # pylint: disable=too-many-arguments, too-many-branches
        # The rckey could be the actual rckey or one of its ancestors
        self.rckey = rckey
        self.statedir = statedir
        self.account = account
        self.seed = seed
        self.wcache = WalletCacheFile(statedir, rckey.node[0], account, parent_sign_index, seed)
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
        if self.sync is None and statedir is not None and account is not None:
            self.sync = KsFileState(statedir, account, self.rckey)
        if self.sync is not None:
            self.sync(self.state)
        if len(self.state["node"]) == 1:
            self.sync.set_petname(self.state["node"][0], self.state["parent_sign_index"])
        else:
            self.sync.set_petname(self.state["node"][-1] + "-" + str(self.state["parent_sign_index"]),
                                  self.state["parent_sign_index"])
        if old_state is None:
            self.initialize_reserved_and_regular()
            # self.wcache.anounce(parent_sign_index, offset, rckey.hashlen, rckey.otsbits, rckey.heights[0])
            # FIXME: add all levels both for regular and reserved.
        self.init_await_set = set()

    def initialize_reserved_and_regular(self):
        pass

    def increment_reserved(self):
        self.state["reserved_index"] += 1

    def increment_regular(self):
        self.state["regular_index"] += 1

    async def await_reserved_and_regular(self):
        pass

    async def init(self):
        pass
        # FIXME: add all levels, both for regular and reserved.
        #await self.wcache.require(self.state["parent_sign_index"])
        #self.wcache.set_levelkey(0, self.state["parent_sign_index"])
        # FIXME: anounce a few extra

    def __getitem__(self, key):
        """Actively get a sub key and take full responsibility"""
        rckey = self.rckey[key]
        if self.state["regular_index"] < self.total_count:
            myindex = self.state["regular_index"]
            self.state["regular_index"] += 1
            # FIXME: Announce if nececary
        elif self.state["reserved_index"] < self.reserved_count:
            myindex = self.state["reserved_index"]
            self.state["reserved_index"] += 1
            # FIXME: anounce if needed
        else:
            raise RuntimeError("Exausted reserved key index")
        myoffset = self.state["heap_pointer"]
        mysize = sum(rckey.index_space())
        if self.state["heap_pointer"] + mysize - 1 > self.state["keyspace_end_offset"]:
            raise RuntimeError("Ran out of keyspace heap")
        self.state["heap_pointer"] += mysize
        if self.sync is not None:
            self.sync(self.state)
        return KsSubKey(rckey, myoffset, mysize, parent_sign_index=myindex, sync=self.sync, statedir=self.statedir, account=self.account, seed=self.seed)

    def set_sync(self,sync):
        """Set the sync functor"""
        self.sync = sync
        self.sync(self.state)

    def set_petname(self, petname):
        """Set a convenient petname for this key"""
        self.sync.set_petname(petname, self.state["parent_sign_index"])

    async def signing_index(self):
        """Actively get a signing index"""
        if self.state["regular_index"] < self.total_count:
            myindex = self.state["regular_index"]
            self.state["regular_index"] += 1
            # FIXME: anounce if needed
            if self.sync is not None:
                self.sync(self.state)
            return myindex
        raise RuntimeError("Exausted main key index")

class KsFileState:
    """Persistent state for the Wen3 layer."""
    def __init__(self, statedir, accountname, rckey):
        if not os.path.exists(statedir):
            os.mkdir(statedir)
        chaindir = os.path.join(statedir, rckey.node[0])
        if not os.path.exists(chaindir):
            os.mkdir(chaindir)
        wen3dir = os.path.join(chaindir,"wen3")
        if not os.path.exists(wen3dir):
            os.mkdir(wen3dir)
        self.path = os.path.join(wen3dir, accountname + ".json")
        if os.path.exists(self.path):
            with open(self.path, encoding="utf8") as statefile:
                self.state = dict(json.load(statefile))
        else:
            self.state = {}
            self.state["keys"] = {}
            self.state["petnames"] = {}
            self.state["petnames"]["OWNER"] = -1
    def __call__(self, obj):
        """Invoking will update the WEN3 state for one key and write all WEN3 state for the key hyrarchy to disk"""
        self.state["keys"][str(obj["parent_sign_index"])] = obj
        with open(self.path,"w", encoding="utf8") as statefile:
            json.dump(self.state, statefile, indent=1)
    def set_petname(self, petname, index):
        """Set a WEN3 petname for a specific key instance"""
        to_delete = set()
        for key,val in self.state["petnames"].items():
            if str(val) == str(index):
                to_delete.add(key)
        for key in to_delete:
            _ = self.state["petnames"].pop(key)
        self.state["petnames"][petname] = str(index)
        with open(self.path,"w", encoding="utf8") as statefile:
            json.dump(self.state, statefile, indent=1)

class WalletCacheFile:
    """Dummy wallet-cache File"""
    def __init__(self, statedir, chain, accountname, keyindex, seed):
        self.seed = seed
        if not os.path.exists(statedir):
             os.mkdir(statedir)
        chaindir = os.path.join(statedir, chain)
        if not os.path.exists(chaindir):
            os.mkdir(chaindir)
        walletsdir = os.path.join(chaindir,"wallet")
        if not os.path.exists(walletsdir):
            os.mkdir(walletsdir)
        walletdir =os.path.join(walletsdir,accountname)
        if not os.path.exists(walletdir):
            os.mkdir(walletdir)
        if keyindex == -1:
            self.path = os.path.join(walletdir,"cache-main.json")
        else:
            self.path = os.path.join(walletdir,"cache-sub-" + str(keyindex) + ".json")
        if os.path.exists(self.path):
            with open(self.path, encoding="utf8") as statefile:
                self.state = dict(json.load(statefile))
        else:
            self.state = {}
            self.state["cache"] = {}
            self.state["res"] = []
            self.state["reg"] = []
            self.flush()
        self.pending = {}
        self.executor = ProcessPoolExecutor(max_workers=4)

    def flush(self):
        with open(self.path, "w", encoding="utf8") as statefile:
            json.dump(self.state, statefile, indent=1)

    def set_levelkey(self, level, keyid):
        while len(self.state["reg"]) < level + 1:
            self.state["reg"].append(None)
        self.state["reg"][level] = str(keyid)
        self.flush()

    def set_reserved_levelkey(self, level, keyid):
        while len(self.state["res"]) < level + 1:
            self.state["res"].append(None)
        self.state["res"][level] = str(keyid)
        self.flush()

    def anounce(self, keyid, spaceoffset, hashlen, otsbits, height):
        self.pending[str(keyid)] = asyncio.get_event_loop().run_in_executor(self.executor, make_levelkey, spaceoffset, hashlen, otsbits, height, self.seed)

    async def require(self, keyid):
        self.state["cache"][str(keyid)] = await self.pending[str(keyid)]
        del(self.pending[str(keyid)])
        self.flush()

    def release(self, keyid):
        del(self.state["cache"][str(keyid)])
        self.flush()

def make_levelkey(spaceoffset, hashlen, otsbits, height, seed):
    # FIXME: Bind to the level-key layer.
    return {"offset": spaceoffset, "hashlen": hashlen, "otsbits": otsbits, "height": height, "seed": seed}

        
async def main():
    owndir = os.path.join(os.path.expanduser("~"), ".coinzdense")
    if not os.path.exists(owndir):
        os.mkdir(owndir)
    vardir = os.path.join(owndir,"var")
    with open("etc/coinzdense.d/hiveish.yml", encoding="utf8") as apprc:
        data = load(apprc, Loader=Loader)
    owner_key = KsSubKey(RcSubKey(data, minimum=20.0), statedir=vardir, account="silentbot", seed="xxxxxxxx")
    await owner_key.init()
    print(await owner_key.signing_index())
    print(await owner_key.signing_index())
    print(await owner_key.signing_index())
    print(await owner_key.signing_index())
    print(await owner_key.signing_index())
    active1 = owner_key["ACTIVE"]
    await active1.init()
    active2 = owner_key["ACTIVE"]
    await active2.init()
    active2.set_petname("SPARE_ACTIVE")

offset = 80000
hashlen = 16
otsbits = 10

num = 34567
heights = [7,5,6,4]
# print(_heights_index_to_lkindex(heights, 0, num, 32, 512, 32))
#_, os_params = _params_to_level_offset_and_size(offset, hashlen, otsbits, heights)
#print(os_params)
#res = _main_index_to_levelkey_indices(1234567, heights)
#print(res)
#prealoc_extra = _heights_to_prealocate_forward(heights, 1.0)
#print(prealoc_extra)
#res = _main_index_to_levelkey_indices(1234567+prealoc_extra, heights)
#print(res)
prealoc_all, release_all = _main_index_to_levelkey_indices_full(1234567, heights, 1.0)
print(prealoc_all)
print(release_all)
#asyncio.run(main())
