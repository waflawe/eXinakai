import secrets
import string
from dataclasses import dataclass
from optparse import OptionParser
from typing import NamedTuple


@dataclass
class Sumbols:
    l: str
    u: str
    d: str
    p: str


class Options(NamedTuple):
    length: int
    characters: str


def generate_random_password(options_: Options) -> str:
    sumbols = ""
    s = Sumbols(
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation
    )

    for character in options_.characters:
        sumbols += getattr(s, character)

    return "".join(secrets.choice(sumbols) for i in range(int(options_.length)))


if __name__ == "__main__":
    def parse_options() -> Options:
        parser = OptionParser()
        parser.add_option("-l", "--length", dest="length", default=16, help="Len of the password")
        parser.add_option("-c", "--characters", dest="characters", default="ludp",
                          help="Characters that can be used when generating a password")
        options_, args = parser.parse_args()

        if len(options_.characters) > 4:
            raise IOError("The length of the characters option can't be > 4")

        return Options(options_.length, options_.characters)

    options = parse_options()
    print(generate_random_password(options))
