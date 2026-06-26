# docs

Put a dashboard screenshot here named **`dashboard.png`** — the main README
references it as the hero image.

How to capture one:
1. Run the app (`./run.sh` or `CTI_LLM=0 python3 -m cti_agent.server`), open
   http://127.0.0.1:8077, and click **Run Intelligence Sweep**.
2. Take a screenshot of the three populated sector panels (macOS: ⌘⇧4).
3. Save it as `docs/dashboard.png`, then commit:
   `git add docs/dashboard.png && git commit -m "Add dashboard screenshot" && git push`

For a short demo GIF, record the "Run Intelligence Sweep" → panels-populate
flow (macOS: ⌘⇧5, or a tool like Kap), save as `docs/demo.gif`, and reference
it in the README the same way.
