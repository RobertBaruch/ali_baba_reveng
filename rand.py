"""Simulates Ali Baba's psuedo-random number generator."""

from absl import app


def asl(value: int) -> int:
    """8-bit arithmetic shift left."""
    return ((value & 0x7F) << 1) | (value & 0x80)


class Rand:
    """Implements Ali Baba's psuedo-random number generator.

    rand:
        LDA      RANDSTATE
        ASL      A
        ASL      A
        STA      RAND_TMP
        ASL      A
        ASL      A
        ASL      A
        ASL      A
        CLC
        ADC      RAND_TMP
        CLC
        ADC      RANDSTATE
        CLC
        ADC      #$53
        STA      RANDSTATE
        LSR      A
        STA      RAND
        RTS
    """

    _randstate: int
    _rand_tmp: int
    _rand: int

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Resets the random number generator to its initial state."""
        self._randstate = 0xCC

    def update(self) -> int:
        """Updates the random number and returns it."""
        a = asl(asl(self._randstate))
        self._rand_tmp = a
        a = asl(asl(asl(asl(a))))
        a = (a + self._rand_tmp) & 0xFF
        a = (a + self._randstate) & 0xFF
        a = (a + 0x53) & 0xFF
        self._randstate = a
        self._rand = a >> 1
        return self._rand

    def memoize(self) -> list[int]:
        """Returns a list of randstate to next randstate."""
        memo = []
        for i in range(256):
            self._randstate = i
            self.update()
            memo.append(self._randstate)
        return memo

    def values(self) -> list[int]:
        """Returns a list of randstate to rand value."""
        vs = []
        for i in range(256):
            self._randstate = i
            vs.append(self.update())
        return vs

    def cycle(self) -> list[int]:
        """Returns all the numbers in the cycle of the generator."""
        cycle = set()
        self.reset()
        while self._randstate not in cycle:
            cycle.add(self._randstate)
            self.update()
        print(f"{len(cycle)} states in cycle")
        state_values = self.values()
        value_set = {state_values[state] for state in cycle}
        values = list(value_set)
        values.sort()
        print(f"{len(values)} values in cycle")
        return values


def main(argv: list[str]) -> None:
    if len(argv) > 1:
        raise app.UsageError("Too many command-line arguments.")
    states = Rand().memoize()

    reachable: list[bool] = [False] * 256
    for state in states:
        reachable[state] = True
    unreachable: list[int] = [x for x in range(256) if not reachable[x]]
    print(f"Unreachable states: {unreachable}")

    print("==========")
    # Any unreachable values?
    values = Rand().values()
    reachable = [False] * 256
    for value in values:
        reachable[value] = True
    unreachable: list[int] = [x for x in range(256) if not reachable[x]]
    print(f"Unreachable values: {unreachable}")

    print("==========")
    print("Values in cycle:")
    print(Rand().cycle())


if __name__ == "__main__":
    app.run(main)
