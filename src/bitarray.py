BITS_PER_BYTE = 8

class BitBuffer:

    def __init__(self, content=b""):
        """ BitBuffer manage a buffer bit per bit.
        _content: any objects which can be passed to bytes or bytearray.
        _wpos: always indicating the last next bit position.
        _rpos: indicating the bit position to be read for get_bits().

                     _rpos      _wpos
                       v          v
                  bit# 01234567 01234567
                      :--------:--------:  --> _content : bytearray()
           bits added  01011110 001
                       |----------|        --> count_added_bits() = 11
                                  |----|   --> count_padding_bits() = 5
                       |----------|        --> count_remaining_bits() = 11

        once get_bits(3) is called.  the variables will change like below.

                        _rpos   _wpos
                          v       v
                  bit# 01234567 01234567
                      :--------:--------:
                       01011110 001.....
                       |----------|        --> count_added_bits() = 11
                                  |----|   --> count_padding_bits() = 5
                          |-------|        --> count_remaining_bits() = 8

        XXX proposed the expecting behavior. need to be considered.
        set_*(): _wpos doesn't change. except when it add a bit at the tail.
        add_*(): _wpos doesn't change. except when it add a bit at the tail.
        get_*(): increment _rpos()
        copy_*(): _rpos doesn't change.

        """
        self._content = bytearray(content)
        self._wpos = len(content)*8  # write position
        self._rpos = 0  # read position

    def set_bit(self, bit, position=None):
        """ if bit is not 0, set a bit on at the specified position.
        Otherwise, set a bit off.
        if position is not specified, the target bit is the bit specified by
        _wpos, i.e. at the end of buffer, and as the result, _wpos is
        incremented. """
        # XXX needs to check whether it works as defined above.
        if position == None:
            byte_index = (self._wpos >> 3)
            offset = 7 - (self._wpos & 7)

            if len(self._content) < (byte_index + 1):
                self._content.append(0)

            if bit != 0:
                self._content[byte_index] |= (1 << offset)

            self._wpos += 1
        else:
            if position > self._wpos:
                for k in range (0, position - self._wpos):
                    self.set_bit (0)
                self.set_bit(bit)
            else:
                byte_index = (position >> 3)
                offset = 7 - (position & 7)

                msk = 0xFF ^ (0x01 << offset)

                self._content[byte_index] = self._content[byte_index] & msk

                if bit != 0:
                    self._content[byte_index] |= (1 << offset)

    def add_bits(self, bits_as_long, nb_bits, position=None):
        """ write a nb_bits less significant bits of an integer in the buffer.
        if position is not specified, the nb_bits are added at the end of the
        buffer.  if position is specified the nb_bits are set at the buffer
        position. Position defines the position if the most significant bit. """

        if position == None:
            for i in range(nb_bits, 0, -1):
                self.set_bit(bits_as_long & (0x01 << (i-1)))
        else:
            for i in range(0, nb_bits):
                self.set_bit(bits_as_long & (0x01 << (nb_bits-i -1)), position=position+i)

# to be rewritten
    def add_bytes(self, raw_data, position=None):
        for raw_byte in raw_data:
            self.add_bits(raw_byte, BITS_PER_BYTE, position=position)

    def get_bits(self, nb_bits=1, position=None):
        """ return an integer containinng nb_bits from the position.
        The most left bit is 0.
        if position is not specified, _rpos is incremented so that next
        calling get_bits() without position automatically takes the next bit."""

        value = 0x00

        if position == None:
            if self._rpos + nb_bits > self._wpos:
                # go after buffer # XXX: > or >=?
                raise ValueError ("data out of buffer")

            for i in range(0, nb_bits):
                value <<=1
                byte_index = self._rpos >> 3
                offset     = 7 - (self._rpos & 7)

                bit = self._content[byte_index] & (0x01 << offset)

                if (bit != 0):
                    value |= 0x01

                self._rpos += 1

            return value
        else:
            if position + nb_bits > self._wpos:  # go after buffer
                raise ValueError ("data out of buffer")

            for pos in range(position, position + nb_bits):
                value <<=1
                byte_index = pos >> 3
                offset = 7 - (pos & 7)

                bit = self._content[byte_index] & (0x01 << offset)

                if (bit != 0):
                    value |= 0x01

            return value

#to be optimized
    def get_bits_as_buffer(self, nb_bits):
        """ _rpos does change. """
        result = BitBuffer()
        for bit_index in range(nb_bits):
            result.add_bits(self.get_bits(1), 1)
        return result

    def ensure_padding(self):
        count = self.count_padding_bits()
        self.add_bits(0, count)
        return count

    def _old_get_content(self):
        return self._content

    def get_content(self):
        """ return a bytearray containing the remaining bits in _content aligned
        to the byte boundary.
        Note that the number of remaining bits will be lost.
        """
        assert self._rpos % BITS_PER_BYTE == 0
        #nb_bits = self.count_remaining_bits()
        #assert nb_bits % BITS_PER_BYTE == 0
        return self._content[self._rpos // BITS_PER_BYTE:]

    # Renamed because of bad ambiguity:
    #def count_bits(self):
    #    return self._wpos

    def count_remaining_bits(self):
        """return the number of the remaining bits from
        the position of self._rpos to _wpos. """
        #return len(self._content)*BITS_PER_BYTE - self._rpos
        return self._wpos - self._rpos

    def count_padding_bits(self):
        return (BITS_PER_BYTE-self._wpos) % BITS_PER_BYTE

    def count_added_bits(self):
        """return the number of significant bits from the most left bit."""
        return self._wpos

    def display(self):
        print ("{}/{}".format(self._content, self._wpos))

    def copy(self, position=None):
        """ return BitBuffer like get_bits_as_buffer(),
        but _rpos doesn't change. """
        new_buf = BitBuffer()
        if position is None:
            for bit_index in range(self._rpos, self._wpos):
                new_buf.add_bits(self.get_bits(1, bit_index), 1)
            return new_buf
        else:
            if self.count_added_bits() < position:
                return new_buf
            for bit_index in range(position, self._wpos):
                new_buf.add_bits(self.get_bits(1, bit_index), 1)
            return new_buf

    def __repr__(self):
        return "b'{}'/{}".format("".join([ "\\x{:02x}".format(i) for i in
                                       self._content ]), self._wpos)

    def __add__(self, other):
        new_buf = self.copy()
        for bit_index in range(other.count_added_bits()):
            new_buf.add_bits(other.get_bits(1, bit_index), 1)
        return new_buf

if __name__ == "__main__":
    bb = BitBuffer()
    for i in range(0,32):
        bb.set_bit(1)
    bb.set_bit(1, position=80 )
    bb.display()
    bb.set_bit(0, position=7 )
    bb.display()

    bb.add_bits(0x01, 4)
    bb.display()

    bb.add_bits(0x01, 3, position=100)
    bb.display()

    bb.add_bits(1, 2)
    bb.ensure_padding()

    bb.display()

    for i in range(0, 13):
        print(bb.get_bits(8))

#---------------------------------------------------------------------------
