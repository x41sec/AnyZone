#!/usr/bin/env python3
# should also work in pypy but ⁻\_(ü)_/⁻

"""
Bursty rate limiting inspired by the token bucket algorithm from
https://stackoverflow.com/a/668327/1201863

Usage:

    import ratelimit

    fullyautomatedratelimiter = ratelimit.FARL()
    # not to be confused with the fully automated rail layer

    while True:
        task, fromuser = network.recv_packet()
        status = fullyautomatedratelimiter.status(fromuser)
        if status.ok:
            run_task(task)
        else:  # status.reason is only set if ok==False
            if status.reason == ratelimit.REASON_TABLEFULL:
                inform_sysadmin()
            else:
                fromuser.reply("FOR TWENTY'S SAKE, ENHANCE YOUR CALM!")

"""

import time, random

REASON_TABLEFULL = 1
REASON_NEWLYADDED = 2
REASON_ALLOWANCE = 3

class FARL:
    def __init__(self, rate=30, per=15, maxEntries=9000, cleanupEvery=10):
        """
          - rate: how many queries may the client perform?
          - per: per how many seconds?
          - maxEntries: how many clients may be in the rate limiting table?
                Prevents memory exhaustion. Empirically, each entry uses <0.33 bytes of RAM
                which is impossible so... idk, but it seems the limit can be quite relaxed.
          - cleanupEvery: every how many status calls should we do table pruning on average?
                Clients that are full on allowance can be safely forgotten.
                Use False to disable. Use only if there is a limited set of possible clients.
        """
        self.rate = rate
        self.per = per
        self.table = {}
        self.maxEntries = maxEntries
        self.cleanupEvery = cleanupEvery


    def status(self, who):
        if self.cleanupEvery != False and random.randrange(self.cleanupEvery) == 1:
            stale = []
            for key in self.table:
                if self._check_allowance(self.table[key], purgeCheck=True):
                    stale.append(key)
            for key in stale:
                del self.table[key]

        if who not in self.table:
            if len(self.table) >= self.maxEntries:
                return Status(ok=False, reason=REASON_TABLEFULL)

            # allowance=rate initially, minus one for this status call
            self.table[who] = [self.rate, self.per, self.rate - 1, time.time()]
            return Status(obj=self.table[who], ok=True, reason=REASON_NEWLYADDED)

        if self._check_allowance(self.table[who]):
            return Status(obj=self.table[who], ok=True)

        return Status(obj=self.table[who], ok=False, reason=REASON_ALLOWANCE)


    def _check_allowance(self, obj, purgeCheck=False):
        """
            Returns whether the call is within the limit.
            Updates the passed object to reflect the new situation.

            If `purgeCheck` is set, it returns whether the allowance is full
            instead. Having a full allowance means that forgetting about the object
            and re-creating it upon the next call would have no impact, so it can
            safely be forgotten (purged from memory).
        """
        # obj is a list instead of dict for memory usage reasons, though I did not
        # actually check that it is more efficient. That's just my assumption about
        # a hashtable with a hash space and keys with values, versus a contiguous
        # array with a few integers. It makes assignments later in this function a
        # little ugly, but with only two assignments, it's not horrible.

        rate, per, allowance, last_check = obj

        now = time.time()
        time_passed = now - last_check;
        tmp_allowance = allowance + time_passed * (self.rate / self.per)

        if purgeCheck:
            return tmp_allowance > rate

        allowance = tmp_allowance

        if allowance > self.rate:
            allowance = self.rate

        allowed = allowance >= 1

        obj[3] = now

        if allowance >= 1:
            obj[2] = allowance - 1
            return True

        return False


class Status:
    def __init__(self, ok, reason=None, obj=None):
        self.ok = ok
        if not ok:
            self.reason = reason
        if obj is not None:
            self.allowance = obj[2]
            self.last_check = obj[3]


