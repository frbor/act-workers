#!/usr/bin/env python3

"""
Act export worker
"""

import argparse
import json
import re
import sys
import traceback
from collections import MutableMapping
from logging import error, info, warning
from typing import Any, Dict, List, Text, cast

import dateparser

import act
from act.workers.libs import worker


class UnknownResult(Exception):
    """UnknownResult is used in API request (not 200 result)"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


# https://stackoverflow.com/questions/3405715/elegant-way-to-remove-fields-from-nested-dictionaries
def delete_keys_from_dict(dictionary: Dict, keys: List[Text]) -> Dict:
    """ Delete keys from dictionary (nested) """
    modified_dict = {}
    for key, value in dictionary.items():
        if key not in keys:
            if isinstance(value, list):
                modified_dict[key] = [
                    delete_keys_from_dict(entry, keys) for entry in value]
            elif isinstance(value, MutableMapping):
                modified_dict[key] = delete_keys_from_dict(value, keys)
            else:
                # or copy.deepcopy(value) if a copy is desired for non-dicts.
                modified_dict[key] = value
    return modified_dict


def comma_split(values: Text) -> List[Text]:
    """ Split comma separated list and return trimmed non-empty values """

    if not values:
        return []

    return [opt.strip() for opt in values.split(",") if opt.strip()]


def ts_format(ts: Text) -> Text:
    """
    Parse date with dateparser and return as YY-MM-DDTHH:MM:SSZ which is used in act
    """
    return cast(Text, dateparser.parse(ts).strftime("%Y-%m-%dT%H:%M:%SZ"))


def parseargs() -> argparse.Namespace:
    """ Parse arguments """
    parser = worker.parseargs('Export worker')

    parser.add_argument("--remove-id", action="store_true", default=False,
                        help="Remove IDs (id, objectID)")
    parser.add_argument("--object-type",
                        help="Limit query by object type (comma separated list of OR values)")
    parser.add_argument("--object-value",
                        help="Limit query by object value (comma separated list of OR values)")
    parser.add_argument("--fact-type",
                        help="Limit query by fact type (comma separated list of OR values)")
    parser.add_argument("--exclude-object-value-re",
                        help="Exclude object values matching regular expression (client-side)")
    parser.add_argument("--start", required=True,
                        help="Stream from timestamp " +
                        "(dateparser format: https://dateparser.readthedocs.io)")
    parser.add_argument("--end", default="now",
                        help="Stream to timestamp (default=now)" +
                        "(dateparser format: https://dateparser.readthedocs.io)")
    parser.add_argument("--limit", default=10000, type=int,
                        help="Limit size of result. You will need the permission unlimitedSearch to get more than 10000 facts")
    parser.add_argument("--filename", dest="filename",
                        help="Output filename (use stdout if not set)")

    args = parser.parse_args()

    args.object_type = comma_split(args.object_type)
    args.object_value = comma_split(args.object_value)
    args.fact_type = comma_split(args.fact_type)
    args.limit = int(args.limit)

    args.start = ts_format(args.start)
    args.end = ts_format(args.end)

    return args


def process(actapi: act.api.Act, args: argparse.Namespace) -> None:
    """
    Execute search and write result to file
    """

    if args.filename:
        fhandle = open(args.filename, "w")

    else:
        fhandle = sys.stdout

    info("Query start: {}".format(args.start))
    info("Query stop : {}".format(args.end))
    info("Object types: {}".format(args.object_type))
    info("Object values: {}".format(args.object_value))
    info("Fact types: {}".format(args.fact_type))

    count = 0

    for fact in actapi.fact_search(
            limit=args.limit,
            after=ts_format(args.start),
            before=ts_format(args.end),
            fact_type=args.fact_type,
            object_type=args.object_type,
            object_value=args.object_value):

        count += 1

        serialized_fact = fact.serialize()

        if args.exclude_object_value_re:
            if fact.source_object and re.search(
                    args.exclude_object_value_re,
                    fact.source_object.value):
                continue
            if fact.destination_object and re.search(
                    args.exclude_object_value_re,
                    fact.destination_object.value):
                continue

        if args.remove_id:
            serialized_fact = delete_keys_from_dict(serialized_fact, ["id", "objectID"])

        fhandle.write(json.dumps(serialized_fact, sort_keys=True) + "\n")

    if count == args.limit:
        warning("Recieved {} facts (same number as limit). ".format(count) +
                "You have most likely hit the limit")

    if args.filename:
        fhandle.close()


def main_log_error() -> None:
    "Main function. Log all exceptions to error"
    # Look for default ini file in "/etc/actworkers.ini" and ~/config/actworkers/actworkers.ini
    # (or replace .config with $XDG_CONFIG_DIR if set)
    args = parseargs()

    actapi = worker.init_act(args)
    try:
        process(actapi, args)
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
