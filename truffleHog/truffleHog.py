#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import math
import argparse
import tempfile
import os
import re
import stat
from git import Repo
import dulwich.repo as dRepo
from StringIO import StringIO

try:
    from defaultRegexes.regexChecks import regexes
    from presenters import print_json

except ImportError:
    from truffleHog.defaultRegexes.regexChecks import regexes
    from truffleHog.presenters import print_json


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json list file")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="The max commit depth to go back when searching for secrets")
    parser.add_argument("--local-checkout", dest="local_checkout", action="store_true", help="Check out a repo from a local path instead of cloning")
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    parser.set_defaults(regex=False)
    parser.set_defaults(rules={})
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    args = parser.parse_args()
    rules = {}
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")
        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]
    do_entropy = str2bool(args.do_entropy)
    find_strings(
            args.git_url,
            print_json,
            local_checkout=args.local_checkout)


def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def flatten_changes(changes):
    added_shas = []
    removed_shas = set()

    for change in changes:
        if isinstance(change, list):
            for merge_change in change:
                if merge_change.type == 'delete':
                    removed_shas.add(merge_change.old.sha)
                else:
                    added_shas.append(merge_change)
        else:
            if change.type == 'delete':
                removed_shas.add(change.old.sha)
            else:
                added_shas.append(change)

    return [change for change in added_shas if change.new.sha not in removed_shas]


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

base64_regex = re.compile("(?P<entropy>[0-9A-Za-z+/=]+)")
hex_regex = re.compile("(?P<entropy>[0-9A-Fa-f]+)")


def detect_shannon_entropy(line):
    issues = []
    for match in base64_regex.finditer(line):
        if len(match.group(0)) > 19 and shannon_entropy(match.group(0), BASE64_CHARS) > 4.5:
            issues.append(match)

    for match in hex_regex.finditer(line):
        if len(match.group(0)) > 19 and shannon_entropy(match.group(0), HEX_CHARS) > 3:
            issues.append(match)

    return issues


def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
            if entropy > 4.5:
                return entropy

    return entropy


named_regexes = []
for exp_name, exp in regexes.iteritems():
    named_regexes.append(
            "(?P<{key}>{value})".format(key=exp_name, value=exp))

compiled_expr = re.compile('|'.join(named_regexes))


def detect_regex(line):
    return compiled_expr.finditer(line)


def scan_blob(blob_lines):
    issues = []
    for idx, line in enumerate(blob_lines):
        issues.extend([(idx, match) for match in detect_regex(line)])
        issues.extend([(idx, match) for match in detect_shannon_entropy(line)])

    return issues


def find_strings(git_url, print_issues, local_checkout=False):
    project_path = ''
    if local_checkout:
        repo = dRepo.Repo(git_url)
    else:
        project_path = clone_git_repo(git_url)
        repo = dRepo.Repo(project_path)

    visited = set()

    for rev in repo.get_refs().values():
        history_entries = repo.get_walker(rev)

        for entry in history_entries:
            if entry.commit.id in visited:
                break
            else:
                visited.add(entry.commit.id)

            changes = flatten_changes(entry.changes())

            for change in changes:
                if change.new.sha in repo:
                    blob = repo.get_object(change.new.sha)
                else:
                    next
                blob_lines = StringIO(blob.as_raw_string())
                issues = scan_blob(blob_lines)
                if issues:
                    print_issues(issues, blob_lines, change, entry.commit, repo)

    if project_path:
        shutil.rmtree(project_path, onerror=del_rw)


if __name__ == "__main__":
    main()
