from urlparse import urlparse
import json
from datetime import datetime


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_json(issues, lines, change, commit, repo):
    #  url = repo.get_config().get(('remote', 'origin'), 'url')
    #  if 'git@' in url:
        #  repo_string = 'git.liveramp.net/' + url.split(':')[1].split('.')[0]
    #  else:
        #  repo_string = 'git.liveramp.net/' + urlparse(url).path.split('.')[0]

    for idx, match in issues:
        #  url = repo_string + "/blob/{commit_sha}/{blob_path}#L{line_no}".format(
                #  commit_sha=commit.id, blob_path=change.new.path, line_no=idx+1)
        json_issues = {
            #  "git_url": url,
            "violating_text": match.group(0),
            "starting_column": match.start(),
            "ending_column": match.end(),
            "commit": commit.id,
            "blob_path": change.new.path,
            "commit_time": datetime.fromtimestamp(commit.commit_time).isoformat(),
            "reason": match.lastgroup
        }
        print(json.dumps(json_issues))


def match_string(match):
    start_index = max(match.start()-10, 0)
    leading_chars = match.string[start_index:match.start()]
    highlighted_match = bcolors.WARNING + match.group(0) + bcolors.ENDC
    trailing_chars = match.string[match.end():match.end()+10]
    return leading_chars + highlighted_match + trailing_chars
