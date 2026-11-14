"""Scores CargoScope and cargo-machete against the compiler verdicts."""
import glob
import json
import os
import re

O = os.path.dirname(os.path.abspath(__file__))


def machete_findings(path):
    findings, current = set(), None
    for line in open(path, errors="ignore"):
        header = re.match(r"^(\S+) -- \./(.+):$", line.rstrip())
        if header:
            current = header.group(2)
        elif line.startswith("\t") and current:
            findings.add((current, line.strip()))
        elif not line.strip():
            current = None
    return findings


def truth_for(verdicts, manifest, dependency, section=None):
    keys = [k for k in verdicts if k.startswith(f"{manifest}|") and k.endswith(f"|{dependency}")]
    if section:
        keys = [k for k in keys if k == f"{manifest}|{section}|{dependency}"]
    values = {verdicts[k] for k in keys}
    if not values or "unknown" in values:
        return "unknown"
    return "used" if "used" in values else "unused"


def score(name, reported, verdicts_by_repo, sure=frozenset()):
    tp = fp = unknown = 0
    found_sure = 0
    wrong = []
    for repo, manifest, dependency, section in reported:
        verdict = truth_for(verdicts_by_repo[repo], manifest, dependency, section)
        if verdict == "unused":
            tp += 1
            if (repo, manifest, dependency) in sure:
                found_sure += 1
        elif verdict == "used":
            fp += 1
            wrong.append(f"{repo} {manifest} {dependency}")
        else:
            unknown += 1
    return {"tool": name, "reported_judged": tp + fp, "correct": tp, "wrong": fp, "not_judged": unknown, "wrong_list": wrong, "found_sure": found_sure}


def all_feature_repos():
    """Repositories compiled with --all-features: with default features only,
    code behind features is not compiled and the lint over-reports."""
    repos = set()
    for line in open(f"{O}/judge/status.txt"):
        parts = line.split()
        if parts[1] == "all-features":
            repos.add(parts[0])
    for line in open(f"{O}/judge/retry-status.txt"):
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "no-benches" and parts[2] == "all-features":
            repos.add(parts[0])
    return repos


def mentioned(repo, manifest, dependency):
    """Whether the dependency's name appears anywhere in the package's Rust
    files (code, comments, docs): such uses may be platform-specific or in
    doctests, which the lint does not see."""
    directory = os.path.join(O, "repos", repo, os.path.dirname(manifest))
    pattern = re.compile(r"\b" + re.escape(dependency.replace("-", "_")) + r"\b")
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ("target", ".git")]
        for name in files:
            if name.endswith(".rs"):
                with open(os.path.join(root, name), errors="ignore") as handle:
                    if pattern.search(handle.read()):
                        return True
    return False


def main():
    verdicts_by_repo = {}
    keep = all_feature_repos()
    for path in glob.glob(f"{O}/judge/*.verdicts.json"):
        repo = os.path.basename(path)[: -len(".verdicts.json")]
        if repo in keep:
            verdicts_by_repo[repo] = json.load(open(path))

    sure = set()
    for repo, verdicts in verdicts_by_repo.items():
        for key, verdict in verdicts.items():
            if verdict == "unused":
                manifest, _, dependency = key.split("|")
                if not mentioned(repo, manifest, dependency):
                    sure.add((repo, manifest, dependency))
    truth_unused = len(sure)
    judged = sum(v != "unknown" for verdicts in verdicts_by_repo.values() for v in verdicts.values())

    cs_likely, cs_all, machete = [], [], []
    for repo in verdicts_by_repo:
        report = json.load(open(f"{O}/tools/cs-{repo}.json"))
        for finding in report["unused"]:
            if finding.get("ignored_reason"):
                continue
            item = (repo, finding["manifest"], finding["dependency"], finding["section"])
            cs_all.append(item)
            if finding["confidence"] == "likely-unused":
                cs_likely.append(item)
        for manifest, dependency in machete_findings(f"{O}/tools/machete-{repo}.txt"):
            machete.append((repo, manifest, dependency, None))

    results = [
        score("CargoScope (likely-unused, default output)", cs_likely, verdicts_by_repo, sure),
        score("CargoScope (likely + possibly, --show-uncertain)", cs_all, verdicts_by_repo, sure),
        score("cargo-machete (default)", machete, verdicts_by_repo, sure),
    ]
    for result in results:
        judged_reported = result["reported_judged"]
        result["precision"] = result["correct"] / judged_reported if judged_reported else None
        result["recall"] = result["found_sure"] / truth_unused if truth_unused else None
    summary = {
        "repositories_judged": len(verdicts_by_repo),
        "dependencies_judged": judged,
        "unused_according_to_rustc": truth_unused,
        "results": results,
    }
    json.dump(summary, open(f"{O}/evaluation.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=1))
    for result in results:
        print(
            f"{result['tool']}: judged {result['reported_judged']}, correct {result['correct']}, "
            f"wrong {result['wrong']}, not judged {result['not_judged']}, "
            f"precision {result['precision']:.1%}, recall {result['recall']:.1%} ({result['found_sure']}/{truth_unused})"
        )
        for item in result["wrong_list"]:
            print("    wrong:", item)


if __name__ == "__main__":
    main()
