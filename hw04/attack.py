#!/usr/bin/env python

import urllib2
import sys

def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
        except urllib2.HTTPError, e:
            # print "We got: %d" % e.code       # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding

    def attack(self, st):
        st = SecretString(st)
        blocks = st.blocks()

        result = [0] * len(st)

        for j in [1]: #reversed(xrange(0, len(blocks))): ???
            print "Trying block #%d" % (len(blocks)-j-1)
            block = blocks[len(blocks)-1-j]
            real_block_start = 16 * j

            for i in [0,1,2]: #xrange(0, len(block)-1):
                pad_index = len(block) - i - 1
                print "Trying char #%d block #%d" % (pad_index, len(blocks)-j-1)

                char = block[pad_index]
                found = None

                for offset in xrange(0, i):
                    ix = pad_index + offset + 1
                    block[ix] ^= result[16 * j + ix] ^ (i+1)
                    print "padding in %d: %d" % (ix, block[ix])

                for guess in xrange(0, 256):
                    block[pad_index] = char ^ guess ^ (i + 1)
                    print "%d) Trying %d" % (guess, block[pad_index])

                    attempt = SecretString.from_blocks(blocks)
                    # print "Attempting %s" % attempt.value
                    if self.query(str(attempt)):
                        print "It was %d (in %d)!" % (guess, 16*j+pad_index)
                        found = guess
                        break

                if found:
                    result[16 * j + pad_index + len(block)] = found
                else:
                    print "Couldn't find :("
                    return

        print "final result: %s" % result
        print "ASCII decoding: \"%s\"" % \
                ''.join(map(chr, result))

class SecretString(object):
    BLOCK_SIZE = 16

    def __init__(self, value):
        if isinstance(value, str):
            from_hex = lambda s: int(s, 16)
            value = map(from_hex, chunks(value, 2))

        elif isinstance(value, SecretString):
            value = value.value

        self.value = value

    def blocks(self):
        return map(SecretString,
                chunks(self.value, self.BLOCK_SIZE))

    @staticmethod
    def from_blocks(blocks):
        concat = lambda a, b: a + b.value
        val = reduce(concat, blocks, [])
        return SecretString(val)

    def __repr__(self):
        to_hex = lambda x: ("%x" % x).zfill(2)
        return ''.join(map(to_hex, self.value))

    def __len__(self):
        return len(self.value)

    def __getitem__(self, ind):
        return self.value.__getitem__(ind)

    def __setitem__(self, ind, val):
        return self.value.__setitem__(ind, val)

    def __eq__(self, other):
        return self.value == other.value

if __name__ == "__main__":
    po = PaddingOracle()
    # po.query(sys.argv[1])       # Issue HTTP query with the given argument
    # po.attack("f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb1")
    po.attack(sys.argv[1])
