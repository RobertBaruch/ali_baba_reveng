# Based off https://www.stat.auckland.ac.nz/~ihaka/software/Rnoweb

import base64
import dataclasses
import hashlib
from io import TextIOWrapper
import itertools
import pathlib
import pprint
import re
from typing import Sequence

from absl import app
from absl import flags


# TODO: Handle '@<<' as an escape in code chunks.

DOCCHUNKSTART = re.compile(r"(^@ )|(^@$)")
CODECHUNKEND = re.compile(r"\s*>>.*$")
CODECHUNKSTART = re.compile(r"^.*<<\s*")
# Note that <<A>>= appends to chunk A, or starts chunk A if it doesn't already exist.
CHUNKSTART = re.compile(r"(^<<[-. 0-9A-Za-z]*>>=)|(^@ )|(^@$)")
CHUNKREF = re.compile(r"<<([-. 0-9A-Za-z]*)>>")
# A chunk ref with optional leading whitespace before
# the ref and optional leading whitespace before the name.
SPACECHUNKREF = re.compile(r"\s*<<\s*([-. 0-9A-Za-z]*)>>")
LABELPREFIXSTART = "PYNW"
ISDEF = re.compile(r"^@\s+%def.*$")
DEFPREFIX = re.compile(r"^@\s+%def\s+")
IDENT = re.compile(r"\b[a-zA-Z_]\w*\b")
FILENAME = re.compile(r"[A-Za-z0-9.]+")


@dataclasses.dataclass
class ChunkInfo:
    # The names of the chunks referenced in this chunk.
    names_used: set[str]
    # The sublabels of the chunks referenced in this chunk.
    labels_used: set[str]
    # The sublabels of chunks that this chunk is used in. Ordered.
    sublabels_used_in: list[str]
    # The identifiers defined in this chunk.
    defines: set[str]
    # The identifiers defined in other chunks that are used in this chunk.
    defines_used: set[str]

    # The sequence number of the chunk.
    number: int = 0
    # The (canonicalized) name of the chunk.
    name: str = ""
    # The kind is "doc" for documentation chunks and "code" for code chunks.
    kind: str = ""
    # The chunk label. There is a 1-1 correspondence between names and labels.
    label: str = ""
    # The chunk sublabel. Each chunk has a unique sublabel.
    sublabel: str = ""
    # The first line of the chunk (includes the header).
    start: int = 0
    # The last line of the chunk.
    end: int = 0
    # If this chunk continues a previous chunk, the sublabel of the previous chunk.
    prev_sublabel: str = ""
    # If this chunk is continued by a subsequent chunk, the sublabel of the subsequent
    # chunk.
    next_sublabel: str = ""
    # The label prefix for this chunk.
    prefix: str = ""

    def __init__(self) -> None:
        self.names_used = set()
        self.labels_used = set()
        self.sublabels_used_in = []
        self.defines = set()
        self.defines_used = set()


class Weaver:
    found_first_marker: bool = False
    index: int = 0
    fragments: dict[str, str]
    sections: dict[str, list[str]]

    def __init__(self) -> None:
        self.fragments = {}
        self.sections = {}

    def add_fragment(self, name: str, body: str) -> None:
        self.fragments[name] = body

    def add_nwbegin(self) -> str:
        self.index += 1
        if self.index % 2 == 1:
            return r"\nwbegindocs{" + str(self.index) + r"}"
        return r"\nwbegincode{" + str(self.index) + r"}"

    def extract_chunk_name(self, header: str) -> str:
        if DOCCHUNKSTART.search(header):
            return ""
        # Get rid of opening << and closing >>
        header = re.sub(CODECHUNKSTART, "", header)
        header = re.sub(CODECHUNKEND, "", header)
        # Get rid of leading whitespace
        return header.lstrip()

    def prefix_for_chunk_name(self, name: str, filename: str, fileno: int) -> str:
        """Produces a label prefix for a chunk, used in cross-referencing.

        The label prefix consists of "PYNW" followed by a psuedohash of the filename and
        (its unique) filenumber, followed by -, followed by a base32-encoded md5 hash of
        the name. We don't care that it's not human-readable, just that the characters
        in it are acceptable in a LaTeX label with one dash in it.
        """
        if not name:
            return ""
        name_hash = hashlib.md5(name.encode()).digest()
        encoded_hash = base64.b32encode(name_hash).decode().replace("=", "0")
        return (
            f"{LABELPREFIXSTART}{filename.replace(' ', '')[:3]}{fileno}-{encoded_hash}"
        )

    def chunk_used_names(self, lines: Sequence[str], type: str) -> set[str]:
        """Returns the set of names used in a chunk."""
        if type == "doc":
            return set()
        names = set()
        for line in lines:
            names.update(re.findall(CHUNKREF, line))
        return names

    def chunk_defines_used(
        self,
        lines: Sequence[str],
        chunk: ChunkInfo,
        chunks_by_defines: dict[str, ChunkInfo],
    ) -> set[str]:
        """Returns the identifiers defined in other chunks that are used in a chunk.

        Finding identifiers is highly language-specific, so we just do the bare minimum
        here. This function assumes that an identifier is simply a consecutive sequence
        of alphanumeric characters and underscores, separated by whitespace.

        In addition, identifiers are assumed to be global. This means that if a chunk
        uses an identifier locally that happens to match a global identifier, it will be
        treated as a use of the global identifier.
        """
        if chunk.kind == "doc":
            return set()

        idents: list[str] = []
        for line in lines[chunk.start + 1 : chunk.end]:
            # Remove any chunk references so we don't think there's identifiers in them.
            line = re.sub(CHUNKREF, "", line)
            idents.extend(re.findall(IDENT, line))
        return set(
            ident
            for ident in idents
            if ident in chunks_by_defines and ident not in chunk.defines
        )

    def extract_chunk_info(
        self, lines: list[str], filename: str, fileno: int
    ) -> list[ChunkInfo]:
        """Extracts information about the chunks in an nw file."""
        # An nw file is a sequence of chunks, each of which is either a code chunk or a
        # documentation chunk. Each chunk ends at the start of the next chunk, except
        # for the last chunk, which ends at the end of the file.
        starts: list[int] = []
        for lineno, line in enumerate(lines):
            if CHUNKSTART.search(line):
                starts.append(lineno)

        ends = starts[1:] + [len(lines)]

        chunks = [ChunkInfo() for _ in range(len(starts))]

        # The number of chunks with the same label so far.
        label_counts: dict[str, int] = {}
        # The most recent sublabel for each label.
        curr_sublabel_by_label: dict[str, str] = {}

        for i, (chunk, start, end) in enumerate(zip(chunks, starts, ends)):
            chunk.number = i + 1
            chunk.start = start
            chunk.end = end

            # Each chunk starts with a header. Code chunk headers contain a name, while
            # documentation chunks do not. It's possible for names to appear multiple
            # times in a file, which corresponds to appending to a chunk.
            chunk.name = self.extract_chunk_name(lines[start])
            chunk.kind = "code" if chunks[i].name else "doc"
            chunk.prefix = self.prefix_for_chunk_name(chunk.name, filename, fileno)

            # prefix-1 is the unique label for a code chunk name. Doc chunks don't have
            # names, so they don't get prefixes.
            chunk.label = f"{chunk.prefix}-1" if chunk.name else ""
            label_counts[chunk.label] = label_counts.get(chunk.label, 0) + 1

            # prefix-N is the unique label for the subchunks in a code chunk, N >= 1.
            # Thus, the first subchunk of a code chunk is prefix-1, the second is
            # prefix-2, etc. But all such subchunks share the same label.
            chunk.sublabel = (
                f"{chunk.prefix}-{label_counts[chunk.label]}" if chunk.name else ""
            )

            # The previous sublabel is the sublabel of the previous chunk with the same
            # label.
            chunk.prev_sublabel = curr_sublabel_by_label.get(chunk.label, "")
            curr_sublabel_by_label[chunk.label] = chunk.sublabel

        for i, chunk in enumerate(chunks):
            # The next sublabel is the sublabel of the next chunk with the same label.
            for j in range(i + 1, len(chunks)):
                if chunks[j].label == chunk.label:
                    chunks[i].next_sublabel = chunks[j].sublabel
                    break

        prefixes_by_name = {chunk.name: chunk.prefix for chunk in chunks}
        labels_by_name = {chunk.name: chunk.label for chunk in chunks}

        # Find the chunk names that each chunk uses.
        for chunk in chunks:
            chunk.names_used = self.chunk_used_names(
                lines[chunk.start + 1 : chunk.end], chunk.kind
            )

        # Ensure that each chunk name used is defined (in the same nw file).
        for chunk in chunks:
            for name in chunk.names_used:
                if name not in prefixes_by_name:
                    raise ValueError(
                        f"Reference to chunk <<{name}>> in chunk <<{chunk.name}>> not "
                        "found in defined chunks."
                    )
                chunk.labels_used.add(labels_by_name[name])

        chunks_by_label = {chunk.label: chunk for chunk in chunks}

        # Find the sublabels of the chunks that each chunk is used in. If a chunk's
        # label is in another chunk's labels_used, then add the sublabel of that
        # other chunk to this chunk's sublabels_used_in.
        for chunk in chunks:
            for chunk2 in chunks:
                if chunk.label in chunk2.labels_used:
                    chunk.sublabels_used_in.append(chunk2.sublabel)

        # Find the identifiers defined in each chunk. The @ %def line actually starts a
        # doc chunk, so the defines in it apply to the previous code chunk. This also
        # means we should skip the first chunk, which doesn't have a previous chunk.
        chunks_by_defines: dict[str, ChunkInfo] = {}
        for i, chunk in enumerate(chunks):
            if i == 0 or chunk.kind != "doc" or chunks[i - 1].kind != "code":
                continue
            header = lines[chunk.start]
            m = re.search(DEFPREFIX, header)
            if not m:
                continue
            code_chunk = chunks[i - 1]
            code_chunk.defines = set(header[m.end() :].split())
            for d in code_chunk.defines:
                if d in chunks_by_defines:
                    if chunks_by_defines[d].name == code_chunk.name:
                        raise ValueError(
                            f"Identifier {d} defined in multiple chunks in the same "
                            f"name: {code_chunk.name}."
                        )
                    raise ValueError(
                        f"Identifier {d} defined in multiple chunks: "
                        f"{chunks_by_defines[d].name} and {code_chunk.name}."
                    )
                chunks_by_defines[d] = code_chunk

        for chunk in chunks:
            chunk.defines_used = self.chunk_defines_used(
                lines, chunk, chunks_by_defines
            )

        # An nw file always starts with a documentation chunk, but we don't represent
        # it as a ChunkInfo.
        return chunks

    def weave_begin_doc_chunk(
        self, chunk_num: int, initial_line: str, f: TextIOWrapper
    ) -> None:
        f.write(r"\nwbegindocs{")
        f.write(str(chunk_num))
        f.write("}")
        if not initial_line:
            f.write(r"\nwdocspar")
            f.write("\n")
        else:
            self.weave_doc_line(initial_line, f)

    def weave_end_doc_chunk(self, f: TextIOWrapper) -> None:
        f.write(r"\nwenddocs{}")

    def make_safe_string(self, s: str) -> str:
        """Replaces special characters with LaTeX-safe versions."""
        trans_table = str.maketrans(
            {
                "\\": r"{\textbackslash}",
                "{": r"\{",
                "}": r"\}",
                "_": r"{\_}",
                "$": r"{\$}",
                " ": r"\ ",
                "&": r"{\&}",
                "#": r"{\#}",
                "%": r"{\%}",
                "~": r"{\textasciitilde}",
                "^": r"{\textasciicircum}",
            }
        )
        return s.translate(trans_table)

    def tt(self, m: re.Match[str]) -> str:
        return r"{\Tt{}" + self.make_safe_string(m.group(1)) + r"\nwendquote}"

    def weave_doc_line(self, line: str, f: TextIOWrapper) -> None:
        """Handles code fragments quoted with double brackets.

        This is just a crude approximation to noweb's behaviour. It uses a non-greedy
        regular expression to match the quotation delimiters. This means that such code
        fragments may not contain either of the code quotation delimiters. It is also
        not permissible to have newlines within quoted code. These restrictions could be
        eliminated by properly parsing the documentation lines. I'm just not sure that
        it is worth the effort.
        """
        line = re.sub(r"\[\[(.*?)\]\]", self.tt, line)
        f.write(line + "\n")

    def weave_doc_chunk(
        self, lines: Sequence[str], chunk: ChunkInfo, f: TextIOWrapper
    ) -> None:
        initial_line = lines[chunk.start]
        if initial_line == "@" or re.search(ISDEF, initial_line):
            initial_line = ""
        initial_line = re.sub(r"^@ ", "", initial_line)
        self.weave_begin_doc_chunk(chunk.number, initial_line, f)
        for line in lines[chunk.start + 1 : chunk.end]:
            self.weave_doc_line(line, f)
        self.weave_end_doc_chunk(f)

    def weave_begin_code_chunk(
        self,
        chunk_num: int,
        chunk_name: str,
        chunk_label: str,
        chunk_sublabel: str,
        f: TextIOWrapper,
    ) -> None:
        f.write(r"\nwbegincode{")
        f.write(str(chunk_num))
        f.write(r"}")
        f.write(r"\sublabel{")
        f.write(chunk_sublabel)
        f.write(r"}")
        f.write(r"\nwmargintag{{\nwtagstyle{}\subpageref{")
        f.write(chunk_sublabel)
        f.write(r"}}}")
        f.write(r"\moddef{")
        f.write(chunk_name)
        f.write(r"~{\nwtagstyle{}\subpageref{")
        f.write(chunk_label)
        f.write(r"}}}")
        f.write(r"\plusendmoddef" if chunk_sublabel != chunk_label else r"\endmoddef")

    def weave_defline_markup(self, chunk: ChunkInfo, f: TextIOWrapper) -> None:
        f.write(r"\nwstartdeflinemarkup")
        # \nwusesondefline{
        #   \\{NW1Xx3lK-4LS3IC-1}
        # }
        # List out the sublabels of the chunks that this chunk is used in.
        if chunk.sublabels_used_in:
            f.write(r"\nwusesondefline{")
            for label in chunk.sublabels_used_in:
                f.write(r"\\{")
                f.write(label)
                f.write(r"}")
            f.write(r"}")
        # \nwprevnextdefs{NW1Xx3lK-4HM41N-1}{NW1Xx3lK-4HM41N-3}
        if chunk.prev_sublabel or chunk.next_sublabel:
            f.write(r"\nwprevnextdefs{")
            f.write(chunk.prev_sublabel if chunk.prev_sublabel else r"\relax")
            f.write(r"}{")
            f.write(chunk.next_sublabel if chunk.next_sublabel else r"\relax")
            f.write(r"}")
        f.write(r"\nwenddeflinemarkup")

    def weave_not_used_chunk(self, name: str, f: TextIOWrapper) -> None:
        f.write(r"\nwnotused{")
        f.write(name)
        f.write(r"}")

    def weave_insert(
        self, line: str, name_to_label: dict[str, str], f: TextIOWrapper
    ) -> None:
        while re.search(CHUNKREF, line):
            # Consert pre-text
            pre_text = re.search(r"^(.*)<<.*$", line)
            if not pre_text:
                break
            f.write(pre_text.group(1))
            line = line[len(pre_text.group(1)) :]
            # Ignore post-text
            text = re.search(CHUNKREF, line)
            if not text:
                break
            name = text.group(1).strip()
            line = line[text.end() :]
            label = name_to_label[name]
            f.write(r"\LA{}")
            f.write(name)
            f.write(r"~{\nwtagstyle{}\subpageref{")
            f.write(label)
            f.write(r"}}\RA{}")
        f.write("\n")

    def weave_code_line(
        self, line: str, ident_to_chunk: dict[str, ChunkInfo], f: TextIOWrapper
    ) -> None:
        r"""Maps special chars, and adds indentifier references."""
        line = re.sub("@<<", "<<", line)
        line = re.sub("\\\\", "\\\\\\\\", line)
        line = re.sub("\\}", "\\\\}", line)
        line = re.sub("\\{", "\\\\{", line)
        matches = list(re.finditer(IDENT, line))
        matches.reverse()
        # Replace identifiers back to front so match positions don't get invalidated.
        for match in matches:
            ident = match.group(0)
            if ident not in ident_to_chunk:
                continue
            line = (
                line[: match.start()]
                + r"\nwlinkedidentc{"
                + ident
                + r"}{"
                + ident_to_chunk[ident].sublabel
                + r"}"
                + line[match.end() :]
            )
        f.write(line + "\n")

    def weave_defines(
        self, chunk: ChunkInfo, ident_to_chunk: dict[str, ChunkInfo], f: TextIOWrapper
    ) -> None:
        if not chunk.defines:
            return
        sorted_defines = list(chunk.defines)
        sorted_defines.sort()
        for ident in sorted_defines:
            # \nwindexdefn{\nwixident{ROM{\_}INIT}}{ROM:unINIT}{NW1Xx3lK-3dXxNE-1}
            f.write(r"\nwindexdefn{\nwixident{")
            f.write(ident.replace("_", r"{\_}"))
            f.write(r"}}{")
            f.write(ident.replace("_", ":un"))
            f.write(r"}{")
            f.write(ident_to_chunk[ident].sublabel)
            f.write(r"}")
        f.write(r"\eatline")
        f.write("\n")

        # \nwidentdefs{
        #   \\{{\nwixident{ROM{\_}INIT}}{ROM:unINIT}}
        #   \\{{\nwixident{ROM{\_}SETKBD}}{ROM:unSETKBD}}
        #   \\{{\nwixident{ROM{\_}SETVID}}{ROM:unSETVID}}
        # }
        f.write(r"\nwidentdefs{")
        for ident in sorted_defines:
            f.write(r"\\{{\nwixident{")
            f.write(ident.replace("_", r"{\_}"))
            f.write(r"}}{")
            f.write(ident.replace("_", ":un"))
            f.write(r"}}")
        f.write(r"}")

    def weave_define_uses(
        self, chunk: ChunkInfo, ident_to_chunk: dict[str, ChunkInfo], f: TextIOWrapper
    ) -> None:
        if not chunk.defines_used:
            return
        sorted_defines = list(chunk.defines_used)
        sorted_defines.sort()
        # \nwidentuses{
        #   \\{{\nwixident{BOOT1{\_}SECTOR{\_}NUM}}{BOOT1:unSECTOR:unNUM}}
        #   \\{{\nwixident{BOOT1{\_}WRITE{\_}ADDR}}{BOOT1:unWRITE:unADDR}}
        # }
        # \nwused{\\{NW1Xx3lK-4LS3IC-1}}
        # \nwidentuses{
        #   \\{{\nwixident{BOOT1{\_}SECTOR{\_}NUM}}{BOOT1:unSECTOR:unNUM}}
        #   \\{{\nwixident{BOOT1{\_}WRITE{\_}ADDR}}{BOOT1:unWRITE:unADDR}}
        #   \\{{\nwixident{IWMDATAPTR}}{IWMDATAPTR}}
        #   \\{{\nwixident{IWMSLTNDX}}{IWMSLTNDX}}
        # }
        f.write(r"\nwidentuses{")
        for ident in sorted_defines:
            f.write(r"\\{{\nwixident{")
            f.write(ident.replace("_", r"{\_}"))
            f.write(r"}}{")
            f.write(ident.replace("_", ":un"))
            f.write(r"}}")
        f.write(r"}")
        # \nwindexuse{\nwixident{BOOT1{\_}SECTOR{\_}NUM}}{BOOT1:unSECTOR:unNUM}{NW1Xx3lK-4HM41N-3}
        # \nwindexuse{\nwixident{BOOT1{\_}WRITE{\_}ADDR}}{BOOT1:unWRITE:unADDR}{NW1Xx3lK-4HM41N-3}
        # \nwindexuse{\nwixident{IWMDATAPTR}}{IWMDATAPTR}{NW1Xx3lK-4HM41N-3}
        # \nwindexuse{\nwixident{IWMSLTNDX}}{IWMSLTNDX}{NW1Xx3lK-4HM41N-3}
        # \nwendcode{}
        # Output the defines sorted alphanumerically.
        for ident in sorted_defines:
            f.write(r"\nwindexuse{\nwixident{")
            f.write(ident.replace("_", r"{\_}"))
            f.write(r"}}{")
            f.write(ident.replace("_", ":un"))
            f.write(r"}{")
            f.write(chunk.sublabel)  # this chunk
            f.write(r"}")

    def weave_end_code_chunk(self, f: TextIOWrapper) -> None:
        f.write(r"\nwendcode{}")

    def weave_code_chunk(
        self,
        lines: Sequence[str],
        name_to_label: dict[str, str],
        ident_to_chunk: dict[str, ChunkInfo],
        chunk: ChunkInfo,
        f: TextIOWrapper,
    ) -> None:
        unused = not chunk.sublabels_used_in
        self.weave_begin_code_chunk(
            chunk.number, chunk.name, chunk.label, chunk.sublabel, f
        )
        self.weave_defline_markup(chunk, f)
        f.write("\n")

        for line in lines[chunk.start + 1 : chunk.end]:
            if re.search(CHUNKREF, line) is not None:
                self.weave_insert(line, name_to_label, f)
            else:
                self.weave_code_line(line, ident_to_chunk, f)
            if chunk.number == 1:
                f.write(r"\nosublabel{")
                f.write(chunk.sublabel)
                f.write("-u4}")  # ???

        self.weave_defines(chunk, ident_to_chunk, f)
        if unused:
            self.weave_not_used_chunk(chunk.name, f)
        self.weave_define_uses(chunk, ident_to_chunk, f)
        self.weave_end_code_chunk(f)

    def weave_chunk_index(self, chunks: Sequence[ChunkInfo], f: TextIOWrapper) -> None:
        labels_by_name = {chunk.name: chunk.label for chunk in chunks}
        # Construct a dict of chunk names to a list of sublabels for chunks with that
        # name.
        sublabels_by_name: dict[str, list[str]] = {}
        for chunk in chunks:
            if chunk.name:
                sublabels_by_name.setdefault(chunk.name, []).append(chunk.sublabel)
        # Construct a dict of chunk names to a list of labels for chunks where the chunk
        # is used.
        uses_by_name: dict[str, list[str]] = {}
        for chunk in chunks:
            for name in chunk.names_used:
                uses_by_name.setdefault(name, []).append(chunk.label)

        chunk_names = list(set([chunk.name for chunk in chunks if chunk.name]))
        chunk_names.sort()
        for name in chunk_names:
            f.write(r"\nwixlogsorted{c}{{")
            f.write(name)
            f.write(r"}{")
            f.write(labels_by_name[name])
            f.write(r"}{")
            for use in uses_by_name.setdefault(name, []):
                f.write(r"\nwixu{")
                f.write(use)
                f.write(r"}")
            for sublabel in sublabels_by_name[name]:
                f.write(r"\nwixd{")
                f.write(sublabel)
                f.write(r"}")
            f.write(r"}}%")
            f.write("\n")

    def weave_ident_index(self, chunks: Sequence[ChunkInfo], f: TextIOWrapper) -> None:
        idents = list(set([ident for chunk in chunks for ident in chunk.defines]))
        idents.sort()
        for ident in idents:
            f.write(r"\nwixlogsorted{i}{{\nwixident{")
            f.write(ident.replace("_", r"{\_}"))
            f.write(r"}}{")
            f.write(ident.replace("_", ":un"))
            f.write(r"}}%")
            f.write("\n")

    def weave(
        self,
        lines: Sequence[str],
        chunks: Sequence[ChunkInfo],
        output_dir: str,
        filename: str,
    ) -> None:
        """Weaves an nw file into a LaTeX file."""
        last_doc = 0
        for chunk in chunks:
            if not chunk.name:
                last_doc = chunk.number

        name_to_label = {chunk.name: chunk.label for chunk in chunks}
        # A dict of ident to chunk where defined.
        ident_to_chunk: dict[str, ChunkInfo] = {}
        for chunk in chunks:
            for ident in chunk.defines:
                ident_to_chunk[ident] = chunk

        texpath = pathlib.Path(output_dir, filename).with_suffix(".tex")
        with open(texpath, mode="w") as f:
            # Write the first (unrepresented) documentation chunk.
            if chunks[0].start > 0:
                for line in lines[: chunks[0].start]:
                    self.weave_doc_line(line, f)

            for chunk in chunks:
                if chunk.number == last_doc:
                    f.write("\n\n")
                    self.weave_chunk_index(chunks, f)
                    self.weave_ident_index(chunks, f)
                if chunk.number == 1:
                    # Sets the name of the file being processed.
                    f.write(r"\nwfilename{" + filename + "}")
                if not chunk.name:
                    self.weave_doc_chunk(lines, chunk, f)
                else:
                    self.weave_code_chunk(
                        lines, name_to_label, ident_to_chunk, chunk, f
                    )

            f.write("\n")

    def expand_chunk(
        self,
        name: str,
        indent: str,
        code_content: dict[str, list[str]],
        parent_chunk_names: set[str],
        f: TextIOWrapper,
    ) -> None:
        """Expands a chunk into a file.

        We do not indent the first line of a chunk. When we encounter a chunk reference,
        we ignore anything on the line other than the reference.

        leading spaces prior to the reference and trailing spaces after the reference,
        and concatenate the referenced chunks lines (recursively), except that the
        last line in the referenced content has its newline removed. So if the content
        of <<ref>> is:

            ref1
            ref2

        and the content of this chunk is

            line1
            line2  <<ref>>  trailing
            line3

        then the output will be:

            line1
            line2ref1
            ref2trailing
            line3

        When there are multiple references in a line, for example:

            line1
            line2  <<ref>>  <<ref>>  trailing
            line3

        then the output will be:

            line1
            line2ref1
            ref2ref1
            ref2trailing
            line3

        """
        lines = code_content[name]
        for i, line in enumerate(lines):
            if i > 0:
                f.write(indent)

            match = re.search(r"^(\s*)(.*)", line)
            if not match:
                if i != len(lines) - 1:
                    f.write("\n")
                continue

            space = match.group(1)
            line = match.group(2)
            f.write(space)

            while True:
                match = re.search(SPACECHUNKREF, line)
                if not match:
                    break
                ref_name = match.group(1)
                if ref_name in parent_chunk_names:
                    raise ValueError(
                        f"Chunk <<{ref_name}>> in chunk "
                        f"<<{name}>> would result in a reference cycle."
                    )
                self.expand_chunk(
                    ref_name,
                    indent + space,
                    code_content,
                    parent_chunk_names | {name},
                    f,
                )
                line = line[match.end() :]

            f.write(line)
            if i != len(lines) - 1:
                f.write("\n")

    def tangle(self, lines: Sequence[str], chunks: Sequence[ChunkInfo],
               output_dir: str, filename: str):
        """Tangles an nw file into a code file."""
        code_content: dict[str, list[str]] = {}
        for chunk in chunks:
            if chunk.name:
                content = lines[chunk.start + 1 : chunk.end]
                if chunk.name in code_content:
                    code_content[chunk.name].extend(content)
                else:
                    code_content[chunk.name] = list(content)

        unused_chunk_names = set(
            chunk.name for chunk in chunks if not chunk.sublabels_used_in
        )
        for name in unused_chunk_names:
            if FILENAME.fullmatch(name):
                print(f"Writing chunk <<{name}>> to file.")
                codepath = pathlib.Path(output_dir, name)
                with open(codepath, mode="w") as f:
                    self.expand_chunk(name, "", code_content, set(name), f)
            else:
                print(
                    f"Warning: unreferenced chunk <<{name}>> not output "
                    "because it is not a valid filename."
                )

    def run(
        self,
        files: Sequence[str],
        output_dir: str,
        weave: bool = True,
        tangle: bool = True,
    ) -> None:
        for fileno, filename in enumerate(files):
            with open(filename, mode="r") as f:
                lines = [line.replace("\n", "") for line in f.readlines()]
            info = self.extract_chunk_info(lines, filename, fileno)
            pprint.pp(info)
        if weave:
            self.weave(lines, info, output_dir, filename)
        if tangle:
            self.tangle(lines, info, output_dir, filename)


def main(argv: Sequence[str]) -> None:
    del argv
    weaver = Weaver()
    weaver.run(["main.nw"], output_dir = "output", weave=True, tangle=True)


if __name__ == "__main__":
    app.run(main)
