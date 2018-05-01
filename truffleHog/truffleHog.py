#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import math
import argparse
import tempfile
import os
import re
import json
import stat
from git import Repo, NULL_TREE
import dulwich.repo as dRepo
from git.objects import Commit
from git.util import hex_to_bin
from StringIO import StringIO
from dulwich.objects import Blob
import pdb

try:
    from defaultRegexes.regexChecks import regexes
except ImportError:
    from truffleHog.defaultRegexes.regexChecks import regexes


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json list file")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="The max commit depth to go back when searching for secrets")
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
    output = find_strings(
            args.git_url,
            args.since_commit,
            args.max_depth,
            args.output_json,
            args.do_regex,
            do_entropy)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)


def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


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
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def blobs_for_commit(commit):
    blobs_not_in_parents = []
    if commit.parents:
        for parent in commit.parents:
            diff_blobs = [diff.a_blob for diff in commit.diff(parent) if diff.a_blob]
            blobs_not_in_parents.append(diff_blobs)
    else:
        diff_blobs = [diff.b_blob for diff in commit.diff(NULL_TREE) if diff.b_blob]
        blobs_not_in_parents.append(diff_blobs)

    return set().union(*blobs_not_in_parents)


def flatten_blobs(changes):
    added_shas = set()
    removed_shas = set()

    for change in changes:
        if isinstance(change, list):
            for merge_change in change:
                if merge_change.type == 'delete':
                    removed_shas.add(merge_change.old.sha)
                else:
                    added_shas.add(merge_change.new.sha)
        else:
            if change.type == 'delete':
                removed_shas.add(change.old.sha)
            else:
                added_shas.add(change.new.sha)

    return added_shas - removed_shas


def detect_shannon_entropy(line):
    for word in line.split():
        base64_strings = get_strings_of_set(word, BASE64_CHARS)
        hex_strings = get_strings_of_set(word, HEX_CHARS)
        for string in base64_strings:
            b64Entropy = shannon_entropy(string, BASE64_CHARS)
            if b64Entropy > 4.5:
                return True
        for string in hex_strings:
            hexEntropy = shannon_entropy(string, HEX_CHARS)
            if hexEntropy > 3:
                return True


named_regexes = []
for exp_name, exp in regexes.iteritems():
    named_regexes.append(
            "(?P<{key}>{value})".format(key=exp_name, value=exp))

compiled_expr = re.compile('|'.join(named_regexes))


def detect_regex(line):
    return compiled_expr.finditer(line)


def scan_blob(blob_chunks):
    issues = []
    for idx, line in enumerate(blob_chunks):
        issues.extend([(idx, match) for match in detect_regex(line)])
        #  issues.extend([(idx, match) for match in detect_shannon_entropy(line)])

    return issues


def find_strings(git_url, since_commit=None, max_depth=1000000, printJson=False, do_regex=False, do_entropy=True, custom_regexes={}):
    project_path = clone_git_repo(git_url)
    gp_repo = Repo(project_path)
    repo = dRepo.Repo(project_path)
    output_dir = tempfile.mkdtemp()

    visited = set()

    count = 0
    for ref in repo.get_refs().values():
        history_entries = repo.get_walker(ref)

        for entry in history_entries:
            if entry.commit.sha in visited:
                break
            else:
                visited.add(entry.commit.sha)

            blobs = flatten_blobs(entry.changes())

            for blob_sha in blobs:
                blob_chunks = repo.get_object(blob_sha).as_raw_chunks()
                issues = scan_blob(blob_chunks)
                count += len(issues)
                if issues:
                    print_issues(issues, blob_chunks)

    print(str(count) + "issues found.")
    return {"project_path": project_path}


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_issues(issues, blob_text):
    pass
    #  for issue in issues:
        #  idx, match = issue
        #  print("------------------")
        #  chunk = blob_text[idx]
        #  first_part = chunk[:match.start()]
        #  highlighted = bcolors.WARNING + match.group(0) + bcolors.ENDC
        #  last_part = chunk[match.end():]
        #  formatted = first_part + highlighted + last_part
        #  print(formatted)
        #  print(blob_text[idx+1:idx+2])
        #  print("------------------")

if __name__ == "__main__":
    main()
