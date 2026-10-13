## Summary

<!-- What changes, and why. Link the issue if one applies. -->

## Checks

- [ ] `npm test` passes
- [ ] For changes to how dnstwist runs: tried a real scan of example.com, or explain why not

## Checklist

- [ ] No shell: commands run with `execFile` and an argument array (a test enforces this).
- [ ] Every new argument is validated in `src/validate.ts` and can't start with `-`.
- [ ] No real scan results for domains from private investigations in code, docs, tests or this description.
- [ ] README, `docs/` and `CHANGELOG.md` are updated where tools, parameters or requirements changed.
