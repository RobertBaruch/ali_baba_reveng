import binascii

# Frequencies across 3 octaves.
FREQS = {
    "A3": 220.0,
    "Bb3": 233.08,
    "B3": 246.94,
    "C4": 261.63,
    "Db4": 277.18,
    "D4": 293.66,
    "Eb4": 311.13,
    "E4": 329.63,
    "F4": 349.23,
    "Gb4": 369.99,
    "G4": 392.0,
    "Ab4": 415.3,

    "A4": 440.0,
    "Bb4": 466.16,
    "B4": 493.88,
    "C5": 523.25,
    "Db5": 554.37,
    "D5": 587.33,
    "Eb5": 622.25,
    "E5": 659.25,
    "F5": 698.46,
    "Gb5": 739.99,
    "G5": 783.99,
    "Ab5": 830.61,

    "A5": 880.0,
    "Bb5": 932.33,
    "B5": 987.77,
    "C6": 1046.5,
    "Db6": 1108.73,
    "D6": 1174.66,
    "Eb6": 1244.51,
    "E6": 1318.51,
    "F6": 1396.91,
    "Gb6": 1479.98,
    "G6": 1567.98,
    "Ab6": 1661.22,

    "A6": 1760.0,
    "Bb6": 1864.66,
    "B6": 1975.53,
    "C7": 2093.0,
    "Db7": 2217.46,
    "D7": 2349.32,
    "Eb7": 2489.02,
    "E7": 2637.02,
    "F7": 2793.83,
    "Gb7": 2959.96,
    "G7": 3135.96,
    "Ab7": 3322.44,
}

if __name__ == "__main__":
    lows = {}
    highs = {}
    print("Note : lo   hi")
    print("--------------")
    for note, f in FREQS.items():
        low = ((510204.0 / f) - 31) / 10
        high = ((510204.0 / f) - 12) / 5
        # Round low and high to nearest integer
        low = round(low)
        high = round(high)
        lows[low] = note
        lows[high] = note
        print(f"{note:5s}: {low:02X} - {high:02X}")

    for note, f in FREQS.items():
        low = ((510204.0 / f) - 31) / 10
        high = ((510204.0 / f) - 12) / 5
        # Round low and high to nearest integer
        low = round(low)
        high = round(high)
        lows[low] = note
        lows[high] = note
        f1 = 510204.0 / (31 + 10 * low)
        f2 = 510204.0 / (12 + 5 * high)
        print(f"[[{note}]] & [[{FREQS[note]:.1f}]] & "
              f"[[{low:02X}]] & [[{f1:.1f}]] & "
              f"[[{high:02X}]] & [[{f2:.1f}]] \\\\")
