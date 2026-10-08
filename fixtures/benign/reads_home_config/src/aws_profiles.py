"""List profile names from ~/.aws/credentials. The file is only read."""

import configparser
import os


def list_profiles(path="~/.aws/credentials"):
    parser = configparser.ConfigParser()
    parser.read(os.path.expanduser(path))
    return parser.sections()
