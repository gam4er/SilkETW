# AGENTS.md — Working agreement for AI agents and human contributors

This document is the **canonical contract** for any agent (human or AI) that adds, modifies, or reorganises files in this repository. It complements — but does not replace — `README.md`, `README-ru.md`, and `Changelog.txt`.

If you are an AI coding agent reading this on first contact with the repo: **read this file in full before touching `SilkETW/ConfigTemplates/`**.

---

## 1. Repository layout (the parts that matter for this contract)

```
SilkETW/
  ConfigTemplates/
    SilkETWConfig_*.xml      # SilkETW collector configuration templates
    SilkETWConfig_*.md       # Paired bilingual provider documentation (EN + RU)
    *_manifest.xml           # Raw ETW manifest dumps — OUT OF SCOPE for this contract
    ETW/                     # Misc ETW reference material — out of scope
  *.cs                       # SilkETW source
BlueHammer/                  # C++ tooling — out of scope for this contract
docs/                        # Hand-authored research notes
Import-NdjsonToElastic/      # PowerShell ingest pipeline
README.md / README-ru.md     # User-facing project intro
Changelog.txt                # Human-curated changelog
AGENTS.md                    # ← this file
```

---

## 2. The Invariant

> **Any new or modified `SilkETWConfig_*.xml` MUST be accompanied by a paired `SilkETWConfig_*.md` file with the exact same base name, sitting next to it in `SilkETW/ConfigTemplates/`.**
>
> The Markdown file MUST contain:
>
> 1. An **English** section first.
> 2. A horizontal rule `---`.
> 3. A **Russian** section under the heading `## Russian version / Русская версия`, mirroring the English structure.

This invariant is non-negotiable. A pull request / commit that adds or changes an XML template without the paired MD update is considered incomplete.

### Naming

- XML: `SilkETWConfig_<Name>.xml`
- MD: `SilkETWConfig_<Name>.md`
- `<Name>` uses `PascalCase` or `Snake_Case`, no spaces.

---

## 3. Best practices — XML templates

1. **Schema.** Root is `<SilkETWConfig>`. Each provider is one `<ETWCollector>` block containing `<Guid>`, `<CollectorType>`, `<ProviderName>`, `<UserTraceEventLevel>`, `<UserKeywords>`, and optionally `<EventIdFilter>`.
2. **Per-collector `<Guid>`.** Every `<ETWCollector>` must carry a **unique GUID** in `<Guid>` (this is the collector instance identifier, not the provider GUID). Generate with `[guid]::NewGuid()` in PowerShell. Lowercase, no braces.
3. **`<ProviderName>`.** Lowercase GUID, no braces. Verify with `logman query providers "<Name>"` before committing.
4. **No long inline descriptions.** Do not put multi-paragraph `<!-- ... -->` blocks inside the XML. The only allowed comment is a short header pointer of the form:
   ```xml
   <!--
     See SilkETWConfig_<Name>.md for provider descriptions (EN/RU).
   -->
   ```
   All provider/event/keyword discussion lives in the paired `.md` file.
5. **Level guidance (`<UserTraceEventLevel>`).** Pick the lowest level that yields the events you need:
   - `Critical` (1), `Error` (2), `Warning` (3), `Informational` (4), `Verbose` (5).
   - For broad investigation/forensics templates: `Verbose` is acceptable.
   - For production/long-running monitoring templates: prefer `Informational` or `Warning` and document the choice in the MD.
6. **Keywords (`<UserKeywords>`).** `0xffffffffffffffff` enables everything — fine for investigation templates, expensive for production. When narrowing, document the chosen keyword bitmap and its meaning in the MD.
7. **`<EventIdFilter>`.** Use only when you genuinely need source-side filtering. Document every filter (which IDs, why) in the MD.
8. **Output path.** Use a relative path under `./Logs/` matching the template name in lower snake case, e.g. `./Logs/network_telemetry.ndjson`.
9. **Encoding & header.** Always start with `<?xml version="1.0" encoding="utf-8"?>`.
10. **No secrets, no machine-specific paths.** Templates are committed to source control.

---

## 4. Best practices — paired Markdown documentation

Required structure (English section, then divider `---`, then Russian section with the same structure):

1. **Purpose** — one paragraph: what this template captures and the intended use case.
2. **Provider catalog** — a table listing every provider in the XML with name, GUID, group, and `NEW (YYYY-MM-DD)` marker if the provider was not already referenced by an existing `SilkETWConfig_*.xml` in the repo.
3. **Per-provider deep-dives** — grouped logically (e.g. by purpose). For each provider include: what it instruments, typical event IDs / keywords, investigation value, noise level, links to MS Learn or the relevant manifest.
4. **Comparative notes** — call out tricky distinctions (e.g. `WinHttp` vs `WinHttp-Pca`, `Winsock-Sockets` vs `Winsock-AFD`, `Microsoft-Quic` ↔ HTTP/3, etc.).
5. **Operational notes** — volume expectations, privilege requirements, recommended downstream filtering.

### `NEW (YYYY-MM-DD)` rule

- A provider is **NEW** if it has not appeared in any other `SilkETWConfig_*.xml` template in this repository at the time of authoring.
- The date in `NEW (YYYY-MM-DD)` is the date the provider was first introduced into the repo, in ISO format.
- Once the provider has been introduced, subsequent templates referencing the same provider should **not** mark it `NEW`.

### References

Prefer linking to:

- Microsoft Learn ETW provider pages.
- The relevant manifest file in this repo or in `%SystemRoot%\System32\winevt\publishers`.
- Authoritative third-party research only when MS docs are absent.

---

## 5. Verification checklist

Before committing changes to `SilkETW/ConfigTemplates/`:

- [ ] **GUIDs verified.** Run `logman query providers "<Provider Name>"` (or `Get-WinEvent -ListProvider <name>`) on a target Windows build for every new `<ProviderName>`. If the provider does not exist, document the substitution in the MD.
- [ ] **Collector GUIDs unique.** No two `<Guid>` values inside the file collide; ideally globally unique across all templates.
- [ ] **XML well-formed.** Open in VS Code (XML extension) or run `[xml](Get-Content path\to\file.xml)` in PowerShell — no parse errors.
- [ ] **Smoke test.** Optionally run `SilkETW.exe -t user -ot file -p path\to\template.xml` from an elevated shell on a representative host and confirm NDJSON output is produced.
- [ ] **Paired MD present.** File exists, has both EN and RU sections separated by `---`, and the provider catalog matches the XML one-to-one.
- [ ] **`NEW (...)` markers correct.** No false positives (provider already used in another template) and no false negatives (genuinely new provider not marked).
- [ ] **No long inline XML comments.** Only the short header pointer to the MD.

---

## 6. How to add a new template (walkthrough)

1. **Pick a name.** `SilkETWConfig_<Name>.xml`.
2. **Decide the provider set.** For each provider:
   - Look up the canonical name and GUID (MS Learn, manifest dump, or `logman query providers`).
   - Confirm the provider exists on the target Windows version(s).
   - Decide level + keywords + (optional) event ID filter.
3. **Generate collector GUIDs.** One fresh `[guid]::NewGuid()` per `<ETWCollector>` block.
4. **Write the XML.** Header + short comment pointer + `<OutputPath>` + collector blocks. **No inline descriptions.**
5. **Write the paired MD.** Purpose → catalog → per-provider deep-dives → comparative notes → operational notes. Add `NEW (YYYY-MM-DD)` markers where applicable.
6. **Add the Russian mirror.** Below `---` and `## Russian version / Русская версия`, replicate the English structure verbatim in Russian. Translate, do not paraphrase loosely — keep section headings and tables structurally identical.
7. **Run the verification checklist** above.
8. **Update `Changelog.txt`** with a one-line entry describing the new template (optional but recommended).

---

## 7. How to modify an existing template

Same rules as above, plus:

- If you change the provider set, update the paired MD's catalog and per-provider sections in **both** EN and RU.
- If you remove a provider that was the _only_ reference in the repo and another template re-introduces it later, that future re-introduction is **not** `NEW` — the historical date stands. Track first-introduction dates carefully.
- Never delete the paired MD without removing the XML in the same change.

---

## 8. Out of scope for this contract

- `*_manifest.xml` files in `SilkETW/ConfigTemplates/` (they are raw `wevtutil gp ... /ge /gm` dumps, not SilkETW configs).
- Files under `BlueHammer/`, `docs/`, `Import-NdjsonToElastic/`.
- Changes to `SilkETW/*.cs` source.

These areas have their own conventions; this contract does not constrain them.

---

## 9. Russian summary / Русское резюме

Любой новый или изменённый `SilkETWConfig_*.xml` ОБЯЗАН сопровождаться парным `SilkETWConfig_*.md` с тем же базовым именем, рядом, в `SilkETW/ConfigTemplates/`. MD должен содержать сначала английскую секцию, затем разделитель `---`, затем русскую секцию под заголовком `## Russian version / Русская версия` с зеркальной структурой.

Длинных описаний внутри XML — не размещать (только короткий header-комментарий-указатель на MD). Каждый `<ETWCollector>` имеет уникальный `<Guid>`. Каждый `<ProviderName>` — проверенный GUID (lowercase, без скобок). Провайдеры, ранее не встречавшиеся в проекте, помечаются в MD как `NEW (YYYY-MM-DD)` (ISO-дата первого появления в репо).

Полные правила, чек-лист верификации и пошаговое руководство — выше по тексту.
