# Provider Evidence

Provider API availability and forensic completeness are separate questions.

For every provider source record:

- collector and workload identity;
- exact query/window;
- request/provider correlation IDs;
- pagination/continuation behavior;
- page/event count;
- collection completion state;
- provider retention/feature limitations;
- raw response hash;
- normalized derivative hash/lineage.

If an expected source was not enabled or retention expired, report it as a gap.
Do not write "no event" when the source could not answer the question.
