#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np
import json
import os
import statistics

plt.rcParams.update({'figure.autolayout': True})
ALL_METRICS = [
    "lines",
    "nodes",
    "casts",
    "variables",
    "glueFunc",
    "typedVariables",
]
DISPLAY_METRIC = {
    "variables": "Variables",
    "lines": "Lines",
    "casts": "Casts",
    "glueFunc": "Glue functions",
    "nodes": "Nodes",
    "typedVariables": "typedVariables",
}
OUT_DIR = "graphs"
DISPLAY_EXTENSION = {
    "cyberkaida": "Cyberkaida",
    "vanilla_10_3": "Ghidra 10.3",
    "monoidic": "Monoidic",
    "mooncat": "Mooncat",
    "vanilla_10_2_3": "Ghidra 10.2.3",
    "our_extension": "Our extension",
}
DISPLAY_PHASE = {
    "initial":                    "Initial",
    "GoFunctionRenamer":          "Func. renamer",
    "GoNonReturningFunctions":    "Non-ret. funcs.",
    "GoMoreStackNOP":             "Stack growth", # Better name?
    "GoDuffsDevice":              "Duff's device",
    "GoDataTypeRecovery":         "Data types",
    "GoLibrarySignatureImporter": "Lib. sig. import",
    "GoPolymorphicAnalyzer":      "Poly. analyzer",
}

class PhaseDiff:
    def __init__(self, name1, name2, data):
        self.name1 = name1
        self.name2 = name2
        self.data = data

class Phase:
    def __init__(self, name, data):
        self.name = name
        self.data = data
        self.funcs = set(data.keys())

    def aggregate(self, funcs):
        metric_data = {metric:[] for metric in ALL_METRICS}
        for f in funcs:
            for metric in ALL_METRICS:
                metric_data[metric].append(self.data[f][metric])
        max_data = {}
        avg_data = {}
        median_data = {}
        for metric, mdata in metric_data.items():
            max_data[metric] = max(mdata)
            avg_data[metric] = int(statistics.mean(mdata))
            median_data[metric] = int(statistics.median(mdata))
        return median_data, avg_data, max_data

    def sub(self, other):
        return PhaseDiff(self.name, other.name, {
            fname: {
                metric:
                    self.data.get(fname, {metric: 0})[metric] -
                    other.data.get(fname, {metric: 0})[metric]
                for metric in ALL_METRICS
            }
            # TODO: union or intersection?
            for fname in self.funcs.union(other.funcs)
        })

class Run:
    def __init__(self, suite, binary, extension, phases):
        self.reversing_suite = suite
        self.binary = binary
        self.extension = extension
        self.phases = phases
        self.n = len(phases)
        self.funcs_intersection = None

        self.phase_diffs = [
            phases[i+1].sub(phases[i])
            for i in range(self.n - 1)
        ]

    def functions_gained_and_lost(self):
        self.funcs_intersection = old_funcs = self.phases[0].funcs
        print(f"{len(old_funcs)} functions")
        for p in self.phases:
            self.funcs_intersection = self.funcs_intersection.intersection(p.funcs)
            new_funcs = p.funcs - old_funcs
            lost_funcs = old_funcs - p.funcs
            print(f"{p.name:30} {len(p.funcs)} +{len(new_funcs):<4} -{len(lost_funcs):<4}")
            old_funcs = p.funcs
        print(f"{len(self.funcs_intersection)} functions in common")

    def boxplot_all_phases(self):
        for metric in ALL_METRICS:
            self.boxplot_all_phases_metric(metric)

    def boxplot_all_phases_metric(self, metric):
        data = [[phase.data[fname][metric] for fname in self.funcs_intersection] for phase in self.phases]
        # Want the phases chronologically from top to bottom
        data = data[::-1]
        fig, ax = plt.subplots()
        ax.set_xlabel(f"Distribution of {DISPLAY_METRIC[metric].lower()} per function over all functions")
        ax.set_ylabel("Phase")
        ax.boxplot(data, vert=False, showfliers=False)
        ax.set_yticks(
            list(range(self.n, 0, -1)),
            labels=[DISPLAY_PHASE[p.name] if p.name in DISPLAY_PHASE else p.name for p in self.phases]
        )

        ax.set_title(f"{self.binary.replace('_', '.')} {DISPLAY_METRIC[metric]}")
        fig.savefig(os.path.join(OUT_DIR, f"boxplots.{self}.{metric}.png"))
        plt.close()

    def increase_decrease_bar(self):
        for metric in ALL_METRICS:
            self.increase_decrease_bar_metric(metric)

    def increase_decrease_bar_metric(self, metric):
        minus = []
        plus = []
        for i, diff in enumerate(self.phase_diffs):
            plus.append(0)
            minus.append(0)
            for fname in self.funcs_intersection:
                v = diff.data[fname][metric]
                if v > 0:
                    plus[-1] += v
                else:
                    minus[-1] += v

        fig, ax = plt.subplots()
        y = list(range(self.n - 1))
        ax.set_xlabel(f"Total increase (green) and decrese (red) of {metric}.")
        ax.set_ylabel("Phase")
        ax.set_yticks(y, [d.name1 for d in self.phase_diffs])
        ax.barh(y, plus, color="lightgreen")
        ax.barh(y, minus, color="tomato")

        ax.set_title(f"{self} {metric}")
        fig.savefig(os.path.join(OUT_DIR, f"inc_dec_bar.{self}.{metric}.png"))
        plt.close()

    def total_bar(self):
        for metric in ALL_METRICS:
            self.total_bar_metric(metric)

    def total_bar_metric(self, metric):
        total = []
        for i, phase in enumerate(self.phases):
            total.append(sum([phase.data[fname][metric] for fname in self.funcs_intersection]))

        fig, ax = plt.subplots()
        y = list(range(self.n))
        ax.set_xlabel(f"Total {metric}")
        ax.set_ylabel("Phase")
        ax.set_yticks(y, [p.name for p in self.phases])
        ax.barh(y, total)

        ax.set_title(f"{self} {metric}")
        fig.savefig(os.path.join(OUT_DIR, f"total_bar.{self}.{metric}.png"))
        plt.close()

    def __str__(self):
        return f"{self.reversing_suite}.{self.binary}.{self.extension}"

def load_runs():
    fnames = os.listdir("results")
    run_names = set()
    for fname in fnames:
        assert fname.endswith(".json"), "Doesn't end with .json"
        parts = fname.split(".")
        assert len(parts) == 6, "Must be 6 parts"
        run_names.add(".".join(parts[:3]))

    runs = []
    for run_name in run_names:
        phases = sorted([f for f in fnames if f.startswith(run_name)])
        # Exclude first phase since it is not interesting
        #phases = phases[1:]
        phases = [
            Phase(phase.split(".")[4], json.load(open("results/" + phase)))
            for phase in phases
        ]
        suite, binary, extension = run_name.split(".")
        runs.append(Run(suite, binary, extension, phases))
    return runs

def run_boxplot(binary, runs, intersect):
    for metric in ALL_METRICS:
        print(binary, metric)
        run_boxplot_metric(binary, runs, intersect, metric)

def sorting_tuple(items):
    return tuple(np.percentile(items, [75, 50, 25]))

def run_boxplot_metric(binary, runs, intersect, metric):
    data = [
        ([run.phases[-1].data[fname][metric] for fname in intersect],
         run.extension)
        for run in runs
    ]

    data.sort(key=lambda t: sorting_tuple(t[0]))

    for (i, (d, ext)) in enumerate(data):
        print(f"{i} {ext:<15} {sorting_tuple(d)}")
    print()

    fig, ax = plt.subplots()
    ax.set_xlabel(f"Distribution of {DISPLAY_METRIC[metric].lower()} per function over all in-common functions")
    ax.set_ylabel("Candidate")
    ax.boxplot([d[0] for d in data], vert=False, showfliers=False)
    ax.set_yticks(
        list(range(1, len(data) + 1)),
        #labels=[r.reversing_suite + " " + r.extension for r in runs]
        labels=[DISPLAY_EXTENSION[d[1]] for d in data]
    )

    ax.set_title(f"{binary.replace('_', '.')} {DISPLAY_METRIC[metric]}")
    fig.savefig(os.path.join(OUT_DIR, f"run_boxplots.{binary}.{metric}.png"))
    plt.close()

def run_total_bar(binary, runs, intersect):
    for metric in ALL_METRICS:
        run_total_bar_metric(binary, runs, intersect, metric)

def run_total_bar_metric(binary, runs, intersect, metric):
    total = []
    for run in runs:
        total.append(sum([run.phases[-1].data[fname][metric] for fname in intersect]))

    fig, ax = plt.subplots()
    y = list(range(len(runs)))
    ax.set_xlabel(f"Total {metric}")
    ax.set_ylabel("Extension")
    ax.set_yticks(y, [r.reversing_suite + " " + r.extension for r in runs])
    ax.barh(y, total)

    ax.set_title(f"{binary} {metric}")
    fig.savefig(os.path.join(OUT_DIR, f"run_total_bar.{binary}.{metric}.png"))
    plt.close()

def graph_runs(binary, runs):
    print(f"Run: {binary}")
    intersect = runs[0].funcs_intersection
    for r in runs:
        print(f"{r.reversing_suite:6} {r.extension:15}: {len(r.funcs_intersection)}")
        intersect = intersect.intersection(r.funcs_intersection)
    print(f"{len(intersect)} functions in common.")
    print()

    run_total_bar(binary, runs, intersect)
    run_boxplot(binary, runs, intersect)

def no_underscore(s):
    return s.replace("_", "\\_")

def table(runs):
    for metric in ALL_METRICS:
        table_metric(runs, metric)

def table_metric(runs, metric):
    binaries = sorted(list({r.binary for r in runs}))
    intersect_funcs = {}
    for b in binaries:
        bruns = [r for r in runs if r.binary == b]
        bs = bruns[0].funcs_intersection
        for r in bruns[1:]:
            bs = bs.intersection(r.funcs_intersection)
        intersect_funcs[b] = bs

    print(f"% Table for {metric}")
    print("\\begin{sidewaystable}")
    print("\t\\centerline{\\begin{tabular}{l" + "|r:r:r"*5 + "}")
    spacer = "\t\t" + " "*14
    print(spacer + "".join(["& \\multicolumn{3}{|c}{\\textbf{%s}} " % b.replace("_", ".") for b in binaries]) + "\\\\")
    print("\t\t\\cline{2-16}")
    print(spacer + "& \\textbf{Med} & \\textbf{Avg} & \\textbf{Max} "*5 + "\\\\")
    print("\t\t\\hline")
    for suite, ext in {(r.reversing_suite, r.extension) for r in runs}:
        cand_runs = {r.binary:r for r in runs if r.reversing_suite == suite and r.extension == ext}
        print(f"\t\t{DISPLAY_EXTENSION[ext]:14}", end="")
        for b in binaries:
            r = cand_runs[b]
            p = r.phases[-1]
            median_data, avg_data, max_data = p.aggregate(intersect_funcs[b])
            print(f" & {median_data[metric]} & {avg_data[metric]} & {max_data[metric]}", end="")
        print(" \\\\")
    print("\t\\end{tabular}}")
    print(f"\t\\caption{{Shows the median, average, and maximum number of {DISPLAY_METRIC[metric]}, over all test binaries.}}")
    print(f"\t\\label{{tbl:{metric}}}")
    print("\\end{sidewaystable}")
    print()

def main():
    # Clear old graphs
    for f in os.listdir(OUT_DIR):
        if f.endswith(".png"):
            os.remove(os.path.join(OUT_DIR, f))

    runs = load_runs()

    for r in runs:
        print(r)
        r.functions_gained_and_lost()
        r.boxplot_all_phases()
        r.increase_decrease_bar()
        r.total_bar()
        print()

    for b in {r.binary for r in runs}:
        graph_runs(b, [r for r in runs if r.binary == b])

    table(runs)

if __name__ == "__main__":
    main()
