
from ctypes import c_uint32

class Interval:
    def __init__(self,
                _start: c_uint32 = 0,
                _end: c_uint32 = 0):
        self._start = _start
        self._end   = _end
    
    def __iadd__(self, _val: c_uint32):
        self._start += _val
        self._end += _val
        return self

    def __str__(self):
        return f'({hex(self._start)}, {hex(self._end)})'

    @property
    def start(self):
        return self._start
    
    @start.setter
    def start(self, _val: c_uint32):
        self._start = _val

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, _val: c_uint32):
        self._end = _val

    @staticmethod
    def overlaps(_interval1, _interval2) -> bool:
        return _interval1.end >= _interval2.start and _interval2.end > _interval1.start
    
    @staticmethod
    def intersect(_interval1, _interval2):
        _start = max(_interval1.start, _interval2.start)
        _end = min(_interval1.end, _interval2.end)

        return Interval(_start, _end)
        