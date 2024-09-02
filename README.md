# ali_baba_reveng
> [!NOTE]
> This is a work in progress.

Reverse engineering of Ali Baba for the Apple II (1982)

[main.pdf](main.pdf) is the literate programming document for this project. This means the explanatory text is interspersed with source code. The source code can be extracted from the document and compiled.

The goal is to provide all the source code necessary to reproduce a binary identical to the one found on the Internet Archive's [Ali Baba and the Forty Thieves (4am and san inc crack).dsk](https://archive.org/details/AliBabaAndTheFortyThieves4amCrack) disk image.
This may or may not be feasible, since there is Electronic Arts encryption that has to take place for that, and it's not really of interest.

The assembly code is assembled using [`dasm`](https://dasm-assembler.github.io/).

The document doesn't explain every last detail. It's assumed that the reader can find enough details on the 6502 processor and the Apple II series of computers to fill in the gaps.

## Useful 6502 and Apple II resources:

* [Beneath Apple DOS](https://archive.org/details/beneath-apple-dos), by Don Worth and Pieter Lechner, 1982.
* [Apple II Computer Graphics](https://archive.org/details/williams-et-al-1983-apple-ii-computer-graphics), by Ken Williams, Bob Kernaghan, and Lisa Kernaghan, 1983.
* [6502 Assembly Language Programming](https://archive.org/details/6502alp), by Lance A. Leventhal, 1979.
* [Beagle Bros Apple Colors and ASCII Values](https://archive.org/details/Beagle_Bros-Poster_1), Beagle Bros Micro Software Inc, 1984.
* [Hi-Res Graphics and Animation Using Assembly Language, The Guide for Apple II Programmers](https://archive.org/details/hi-res-graphics-and-animation-using-assembly-language), by Leanard I. Malkin, 1985.

## License

This work is licensed under a
[Creative Commons Attribution-ShareAlike 4.0 International License][cc-by-sa].

[![CC BY-SA 4.0][cc-by-sa-image]][cc-by-sa]

[cc-by-sa]: http://creativecommons.org/licenses/by-sa/4.0/
[cc-by-sa-image]: https://licensebuttons.net/l/by-sa/4.0/88x31.png
[cc-by-sa-shield]: https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg
