# License options

No license is applied. This is a comparison to decide from, not a decision; nothing here changes what license governs this repository. See [`docs/CLI_RELEASE_CHECKLIST.md`](CLI_RELEASE_CHECKLIST.md) for where this sits in the release checklist.

## The three realistic options for this project

**MIT.** Shortest, most permissive, most widely recognized. Anyone can use, modify, and redistribute the code, including in closed-source or commercial products, as long as the original copyright notice stays attached. No patent grant, no copyleft requirement. This is what most single-maintainer CLI tools and portfolio projects use, because it imposes the least friction on anyone who wants to try the tool or build on it.

**Apache-2.0.** Similarly permissive to MIT (commercial and closed-source use allowed), but adds an explicit patent grant from contributors to users, and requires that changes to the licensed files be noted if redistributed. The patent grant matters more for projects with active corporate contributors who might hold relevant patents; for a solo security tool, it's a reasonable extra layer of protection for users but adds a bit more license text to carry around.

**A source-available or "all rights reserved" posture** (no open-source license, or a restrictive one like a non-commercial clause). This keeps control over commercial use but actively works against the stated goal of this project: a publicly installable tool that a technical reviewer can freely try, and a portfolio piece meant to be looked at and run by others. A restrictive license here would contradict the README's own framing.

## What copyleft licenses (GPL/AGPL) would mean here

Worth naming since they're common in security tooling: GPL/AGPL would require anyone distributing a modified version of WebGuard to also release their modifications under the same license. For a single-file-output CLI tool with no server component, the practical effect of AGPL's network-use clause doesn't really apply (there's no hosted service to trigger it), and GPL's copyleft would mostly just make the tool less attractive to pull into other projects (including commercial ones) without buying this project much in return, since there's no competing commercial fork this project needs to defend against.

## Recommendation

MIT. It matches what this project actually is (a tool meant to be tried, forked, and learned from, not a product being protected from competitors) and it's the default expectation for a CLI utility in this space. Apache-2.0 is a reasonable second choice if the patent grant feels worth the extra text; it would not change how approachable the project feels to a user or reviewer.

This is a recommendation, not an application. Nothing in this repository is licensed until a `LICENSE` file is actually added and the license classifier is added to each `pyproject.toml`.
