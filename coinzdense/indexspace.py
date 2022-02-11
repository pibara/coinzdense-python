#!/usr/bin/python3

class IndexSpace:
    def __init__(self, offset=0, exponent=64, reserved_exp=0, state=None):
        assert isinstance(offset, int)
        assert offset >= 0
        assert offset < 1 << 64 - 1024
        assert isinstance(exponent, int)
        assert exponent >= 10
        assert exponent <= 64
        assert isinstance(reserved_exp, int)
        assert reserved_exp == 0 or reserved_exp >= 6
        assert reserved_exp <= exponent - 16
        self.heap = offset + 1 << exponent
        assert self.heap <= 1 << 64
        self.offset = offset
        self.has_reserved = False
        self.stack = 0
        self.stack_reserved = 0
        if reserved_exp:
            self.stack = 1 << reserved_exp
            self.has_reserved = True
        if state not is None:
            assert isinstance(state, list)
            assert len(state) == 3
            self.heap = state[0]
            self.stack = state[1]
            self.stack_reserved = state[2]
            assert isinstance(self.heap, int)
            assert self.heap
            assert isinstance(self.stack, int)
            assert isinstance(self.stack_reserved, int)
            assert self.heap <= offset + 1 << exponent
            assert self.heap > self.stack
            assert not self.has_reserved or self.stack_reserved < self.stack
    



