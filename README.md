# Swarm Forensics

Recovering coordination from the **redacted** Swarm Traces dump of the July 2026 Hugging Face agent-swarm incident.
Made for the Apart Research Swarm Alignment Hackathon (6–8 Nov 2026), track 4 "Multi-Agent Oversight and Control".

The tool does three things:

1. **Coding-style families.** Each payload (plus the code recovered from it) becomes a code skeleton. Every
   redacted label is replaced by its type (`[CREDENTIAL 170]` → `§C`) and the skeleton is clustered with
   MinHash + LSH. 128,454 documents end up in 24,672 families.
2. **Artifact graph.** The redaction keeps stable labels (`[CREDENTIAL 707]` is the same secret everywhere), so
   we can see which families used the same secret, service or repo.
3. **Validation without ground truth.** Families are built blind to the labels, so label sharing is an
   independent check. Two payloads from the same family share a secret 26× more often than two random payloads.
   That is about twice the lift of exact-match or hand-made-trait baselines, and it stays above 14× across a
   threshold sweep.

Results are in `report/report.pdf` and in an interactive page, `out/explorer.html`.

## Run it

Python 3.10+ and NumPy. Download `https://swarmtraces.org/data/final/redacted.jsonl.gz` (about 15 MB), then run:

```bash
python -m swarmforensics.analyze redacted.jsonl.gz out      # families, graph, validation (~4 min)
python -m swarmforensics.sensitivity redacted.jsonl.gz out  # threshold sweep, staged-loader census
python -m swarmforensics.explorer out/results.json out/explorer.html
python report/make_report.py                                # report/report.html (print to PDF with Chrome)
```

Every number in the report is read from `out/results.json` and `out/sensitivity.json`.

## Files

- `swarmforensics/load.py`: loads the dump, folds child rows into their payload, extracts labels.
- `swarmforensics/style.py`: skeletons, MinHash/LSH families, descriptive traits.
- `swarmforensics/analyze.py`: artifact index, cross-family reuse, secret graph, self-chosen names, validation.
- `swarmforensics/sensitivity.py`: threshold sweep and staged-loader census.
- `swarmforensics/explorer.py`: writes the self-contained HTML explorer.
- `report/make_report.py`: builds the report from the result files.

## Ethics

The tool works only on the public redacted release. It shows labels, never secret values, and it makes no attempt
to reverse the redaction. A family is a *code lineage*, not an agent, so do not use it to blame a model, an operator
or a person without independent evidence. See Appendix A of the report.

## Prior work note

Before the sprint, on 4 Nov 2026, two small throw-away scripts were used only to check that the dataset opens and to
count label types. They are not part of this repository. All code here was written during the hackathon weekend.

## License

MIT
