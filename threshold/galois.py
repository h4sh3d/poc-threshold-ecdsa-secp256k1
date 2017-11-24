#!/usr/bin/env python
import itertools

class GF():
    def __init__(self, p, m, px=None):
        self.p = p
        self.m = m
        if px:
            assert len(px) == self.m + 1
            F = GF(self.p, self.m + 1)
            self.px = Poly(F, px)
        else:
            self.px = None

    def list(self):
        perms = list(itertools.product(range(self.p), repeat=self.m))
        for perm in perms:
            yield Poly(self, perm)

    def __eq__(self, other):
        return self.p == other.p and self.m == other.m

    def __lt__(self, other):
        return self.p == other.p and self.m < other.m

    def __gt__(self, other):
        return self.p == other.p and self.m > other.m

    def __str__(self):
        if self.px:
            return 'GF(%d^%d) [%s]' % (self.p, self.m, self.px)
        else:
            return 'GF(%d^%d)' % (self.p, self.m)


class Poly():
    def __init__(self, *args, **kwargs):
        self.gf = args[0]
        if len(args[1:]) == 1:
            vec = args[1]
        else:
            vec = args[1:]
        assert len(vec) <= self.gf.m
        if len(vec) < self.gf.m:
            pad = [0] * (self.gf.m - len(vec))
            vec = tuple(pad) + tuple(vec)
        self.vec = vec

    def __add__(self, p2):
        assert self.gf.p == p2.gf.p
        if self.gf > p2.gf:
            p2 = p2.expand(self.gf)
        elif self.gf < p2.gf:
            self = self.expand(p2.gf)
        rv = []
        for a, b in zip(self.vec, p2.vec):
            alpha = (a + b) % self.gf.p
            rv.append(alpha)
        return Poly(self.gf, tuple(rv))

    def __sub__(self, p2):
        if self.gf.p == 2:
            return self.__add__(p2)
        else:
            assert self.gf == p2.gf
            rv = []
            for a, b in zip(self.vec, p2.vec):
                alpha = (a - b) % self.gf.p
                rv.append(alpha)
            return Poly(self.gf, tuple(rv))

    def __pmul(self, p2):
        assert self.gf == p2.gf
        l = len(self.vec)
        # Mul two tuples mod P(x)
        res = [0] * l**2
        for pos1, i1 in enumerate(self.vec):
            for pos2, i2 in enumerate(p2.vec):
                val = (i1 * i2) % self.gf.p
                pos = (l-pos1-1) + (l-pos2-1)
                res[pos] += val
                res[pos] %= self.gf.p
        return Poly(GF(self.gf.p, l**2), res[::-1]).compress()

    def __mul__(self, p2):
        r = self.__pmul(p2)
        return r % self.gf.px

    def __mod__(self, p2):
        red = Poly(self.gf, self.vec)
        div = Poly(p2.gf, (0, 0))
        p2 = p2.expand(self.gf)
        l = self.gf.m
        for _ in range(2):
            red = red.expand(p2.gf)
            res = [0] *  l
            for pos1, i1 in enumerate(red.vec):
                if i1 == 1:
                    msb1 = l-pos1
                    break
            for pos2, i2 in enumerate(p2.vec):
                if i2 == 1:
                    msb2 = l-pos2
                    break
            pos = msb1 - msb2
            res[l-pos-1] = 1
            ii = Poly(self.gf, res)
            div += ii
            red += ii.__pmul(p2)
            red = red.compress()
            if red.gf < p2.compress().gf:
                break
        return red

    def __str__(self):
        s = ''
        j = 1
        zero = True
        for i in self.vec:
            if i > 0:
                zero = False
                p = self.gf.m - j
                if p == 0:
                    s += '%d + ' % i
                elif p == 1:
                    if i > 1:
                        s += '%dx + ' % i
                    else:
                        s += 'x + '
                else:
                    if i > 1:
                        s += '%dx^%d + ' % (i, p)
                    else:
                        s += 'x^%d + ' % p
            j += 1
        if zero:
            s += "0   "
        return "%s in %s" % (s[:-3], self.gf)

    def expand(self, gf):
        if self.gf < gf:
            return Poly(gf, self.vec)
        else: 
            return self

    def compress(self):
        switch = False
        r = []
        for _ in self.vec:
            if not switch:
                switch = _ == 1
            if switch:
                r.append(_)
        return Poly(GF(self.gf.p, len(r)), r)


# F = GF(3, 5)
# print Poly(F, 1, 0, 0, 1, 0)
# print Poly(F, 1, 1, 1, 1, 0)
# print Poly(F, 1, 0, 1, 0, 1)
# print Poly(F, 0, 0, 1, 1, 0)

F = GF(2, 3, (1, 0, 1, 1))
for _ in GF(2, 3).list():
    print _
print "====="
# print Poly(F, 0, 1, 0)
# print Poly(F, 1, 1, 1)
# print Poly(F, 1, 0, 1)
# print Poly(F, 1, 1, 0)

print "\n(x^2 + x) + (x^2 + 1)"
print Poly(F, (1, 1, 0)) + Poly(F, (1, 0, 1))

print "\n(x^2 + x) - (x^2 + 1)"
print Poly(F, (1, 1, 0)) - Poly(F, (1, 0, 1))

print "\n(x^2 + x + 1) * (x^2 + 1)"
print Poly(F, (1, 1, 1)) * Poly(F, (1, 0, 1))

# GF(3^3)
print ""
F3 = GF(3, 3, (2, 1, 0, 1))
print F3
print Poly(F3, (1, 2, 0)) + Poly(F3, (1, 0, 2))

# print "\n(x^2 + x) - (x^2 + 1)"
# print Poly(F, (1, 1, 0)) - Poly(F, (1, 0, 1))

