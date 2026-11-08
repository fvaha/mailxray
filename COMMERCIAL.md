# Commercial licensing

`mailxrayd` is licensed under **AGPL-3.0-only**. For most deployments that is
free and unproblematic — but the AGPL has one obligation a closed product cannot
meet, and that is what a commercial license removes.

`mailxray-core` is **MIT** and never needs a commercial license.

## When you do **not** need one

- personal use, home mail servers, study, hobby projects;
- running `mailxrayd` inside your own company for your own mail, with no
  third-party users of the service — AGPL does not require publication for
  private, internal use;
- charities, schools, public research, government;
- modifying it and running the modified version yourself, as long as users of
  that service are offered the corresponding source (AGPL §13) — which
  self-hosting naturally satisfies;
- anything built on `mailxray-core` alone, in any kind of project, closed or
  open.

## When you do

- **shipping `mailxrayd` inside a product** you distribute, where you cannot or
  will not publish your deployment's source under the AGPL;
- **offering `mailxrayd` as a hosted service** to third parties while keeping
  your modifications closed — AGPL §13 requires that network users are offered
  the corresponding source;
- **embedding the daemon in an appliance or managed platform** whose source you
  do not publish;
- **OEM / rebranding**, or any case where the AGPL notice would have to be
  stripped.

If you can live with the AGPL, do: it is a real license for real deployments,
not a demo.

## What a commercial license gives you

- use, modify and distribute `mailxrayd` **without** the AGPL source-offer
  obligation;
- no requirement to publish your integration, your modifications, or your
  surrounding deployment;
- terms per legal entity, covering that entity and its affiliates;
- optional integration support, priced by scope;
- the choice to keep your changes private.

It does **not** grant trademark rights, and it does not change the license of
`mailxray-core` — that stays MIT for everybody, including your competitors.

## How to get one

Open an issue titled `commercial license` in this repository, or contact the
licensor directly. Include: legal entity, what you intend to run or ship, rough
scale (hosts / mailboxes / volume / tenants), whether you need support, and why
the AGPL does not fit.

Terms are agreed in writing; this page is a summary, not an offer.

---

*Nothing here is legal advice. The license text in [LICENSE](LICENSE) is the
authority.*
