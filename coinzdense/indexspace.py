#!/usr/bin/python3

class IndexSpace:
    def __init__(self, offset=0, size=1<<64, reserved=0, state=None):
        if state is None:
            if reserved == 0:
                self.has_reserved = False
                self.main_offset = offset
                self.main_heap = offset
                self.reserved_offset = offset
                self.reserved_heap = offset
            else:
                self.has_reserved = True
                self.reserved_offset = offset
                self.reserved_heap = offset
                self.main_offset = reserved + offset
                self.main_heap = reserved + offset
            self.stack = size + offset
        else:
            self.has_reserved = state[0]
            self.reserved_offset = state[1]
            self.reserved_heap = state[2]
            self.main_offset = state[3]
            self.main_heap = state[4]
            self.stack = state[5]
    def key_allocate(self, index_chunk_size):
        if self.main_heap + index_chunk_size > self.stack:
            raise RuntimeError("Index-apce non-reserved heap exausted")
        offset = self.main_heap
        self.main_heap += index_chunk_size
        return offset
    def subkey_allocate(self, index_chunk_size, subkey_keyspace):
        offset2 = self.stack - subkey_keyspace
        if offset2 < self.main_heap:
            raise RuntimeError("Index-space stack exausted")
        if self.reserved_heap + index_chunk_size > self.main_offset:
            if self.main_heap + index_chunk_size > offset2:
                raise RuntimeError("Index-space full heap exausted")
            offset = self.main_heap
            self.main_heap += index_chunk_size
        else:
            offset = self.reserved_heap
            self.reserved_heap += index_chunk_size
        return [offset, offset2]


