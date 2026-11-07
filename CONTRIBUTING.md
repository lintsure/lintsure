# Contributing to Lintsure

Thanks for helping. The full guide is in the docs: **[lintsure.com/docs/contributing](https://lintsure.com/docs/contributing)**. The essentials:

## Set up

```bash
npm install
npm test            # build all packages, run the tests and the MCP smoke test
npm run scan:sample # run the CLI on the sample app
```

## Adding a rule

1. Add it to `packages/core/src/rules/index.ts` with every field: id, title, status (`gap` or `partial`, never `met`), severity, controls, fix, note, extensions, `test` or `fileTest`, `mappedBy`, `reviewedAt`.
2. Plant one example in `fixtures/sample-app` and a near miss in `fixtures/clean-app`.
3. Link it from at least one obligation in `packages/core/src/knowledge/`.
4. Run `npm test`.

## Wording rules

- Plain words, short sentences.
- Never write that a user is compliant, certified, approved or ready. Lintsure informs; people decide. `FORBIDDEN_CLAIMS` in `packages/core/src/guidance.ts` is checked by the tests.
- Framework summaries must be in our own words. Don't paste text from laws, standards or guides. ISO/IEC and AICPA texts are licensed: reference IDs only.

## Sign-off

Sign off every commit (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/). By contributing you agree your work is licensed under [Apache-2.0](LICENSE).

## Be kind

Be respectful in issues and reviews. Report anything unacceptable to [support@lintsure.com](mailto:support@lintsure.com).
