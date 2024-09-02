from collections.abc import Sequence

from absl import app
from absl import flags

FLAGS = flags.FLAGS
flags.DEFINE_integer("first", None, "First sector to read")
flags.DEFINE_integer("last", None, "Last sector to read")
flags.DEFINE_integer("nsectors", None, "Number of sectors to read", short_name="n")
flags.DEFINE_string("infile", None, "Input file (dsk image)", short_name="i")
flags.DEFINE_string("outfile", None, "Output file", short_name="o")
flags.DEFINE_bool("skew", False, "Translate sectors to DOS ordering", short_name="s")

# You can create a file with a sector translation table. Such a table consists of
# two-character case-insensitive hex digits. You can put whitespace whereever you want.
# The table's first value is where to find logical sector 0, the second value is where
# to find logical sector 1, and so on. The table should have 16 entries.
flags.DEFINE_string("table", "", "Use table to translate sectors", short_name="t")

flags.mark_flag_as_required("first")
flags.mark_flag_as_required("infile")
flags.mark_flag_as_required("outfile")


def skew_physical_sector(logical_sector: int) -> int:
    translate_table = [
        0x00,
        0x0D,
        0x0B,
        0x09,
        0x07,
        0x05,
        0x03,
        0x01,
        0x0E,
        0x0C,
        0x0A,
        0x08,
        0x06,
        0x04,
        0x02,
        0x0F,
    ]

    track = logical_sector // 16
    sector = logical_sector % 16
    return track * 16 + translate_table[sector]


def main(argv: Sequence[str]) -> None:
    del argv
    if FLAGS.last is not None and FLAGS.nsectors is not None:
        print("You may specify either --last or --nsectors, but not both.")
        return
    if FLAGS.last is None and FLAGS.nsectors is None:
        print("You must specify either --last or --nsectors.")
        return

    first = FLAGS.first
    if FLAGS.nsectors is None:
        last = FLAGS.last
    else:
        last = FLAGS.first + FLAGS.nsectors - 1

    if FLAGS.table:
        everything = ""
        with open(FLAGS.table, 'r') as tablefile:
            print(f"Reading table from {FLAGS.table}")
            everything = (
                "".join(tablefile.readlines())
                .replace(" ", "")
                .replace("\n", "")
                .replace("\r", "")
                .replace("\t", "")
                .replace("\f", "")
                .replace("\v", "")
            )
        if len(everything) != 32:
            print("Table must have 16 entries.")
            return
        translate_table = [int(everything[2 * i : 2 * i + 2], 16) for i in range(16)]

    with (
        open(FLAGS.infile, mode="rb") as infile,
        open(FLAGS.outfile, mode="wb") as outfile,
    ):
        for sector in range(first, last + 1):
            print(f"Read sector {sector}")
            if FLAGS.skew:
                sector = skew_physical_sector(sector)
                print(f"  Translated to image sector {sector}")
            elif FLAGS.table:
                track = sector // 16
                sector = sector % 16
                sector = track * 16 + translate_table[sector]
                print(f"  Translated to image sector {sector}")
            infile.seek(sector * 256)
            data = infile.read(256)
            outfile.write(data)


if __name__ == "__main__":
    app.run(main)
