# Fern documentation site

APF uses [Fern](https://buildwithfern.com/) to validate, preview, and publish the documentation at [docs.nvidia.com/agent-policy-fabric](https://docs.nvidia.com/agent-policy-fabric/). This directory contains the site configuration, and the NVIDIA global theme supplies the shared presentation. The documentation content lives in `docs/`.

## Repository layout

| Path | Purpose |
|---|---|
| `docs/` | MDX pages and the navigation in `docs/index.yml`. |
| `fern/docs.yml` | Site, theme, and version configuration. The `dev` version points at `docs/index.yml`. |
| `fern/fern.config.json` | Fern organization and pinned CLI version. |
| `scripts/check_docs_nav.py` | Navigation check run by `mise run docs`. |

The `nvidia` global theme, selected by `global-theme: nvidia` in `fern/docs.yml`, owns the logos, favicon, colors, typography, layout, footer, CSS, and JavaScript integrations. Do not copy or override shared presentation here. This repository owns its title, content, navigation, versions, redirects, and instances.

## Prerequisites

| Tool | Used for |
|---|---|
| [mise](https://mise.jdx.dev/) | Runs the tasks defined in the repository's `mise.toml`. |
| Node.js | Runs the Fern CLI. The tasks fetch the version pinned in `fern/fern.config.json` through `npx`, so no global install is needed. |
| [uv](https://docs.astral.sh/uv/) | Runs `scripts/check_docs_nav.py` with its Python dependencies. |

With Homebrew, `brew install mise node uv` installs all three. Otherwise install mise from its [getting started](https://mise.jdx.dev/getting-started.html) guide and run `mise use --global node@24 uv`. The first time you run a task, mise asks you to trust the repository's `mise.toml`.

## Local development

Start a local Fern server from the repository root:

```shell
mise run docs:serve
```

Validate the configuration, links, and navigation without starting a server:

```shell
mise run docs
```

`mise run docs` runs `fern check` and `scripts/check_docs_nav.py`. `fern check` fails on links that do not resolve to a page, through the `broken-links` rule in `fern/docs.yml`. The navigation check fails when a page URL differs from its file path, when a navigation label differs from the page's sidebar title, when a page is missing from the navigation, or when a page links to a site path such as `/about/architecture` instead of a relative `.mdx` file path such as `../about/architecture.mdx`. `mise run docs:clean` removes the local Fern cache. See [docs/CONTRIBUTING.mdx](../docs/CONTRIBUTING.mdx) for the authoring and style guide.

## Continuous integration

The same checks run in CI on every change to `docs/`, `fern/`, or the navigation check script.

| Workflow | Trigger | What it does |
|---|---|---|
| `.github/workflows/docs-check.yml` | Pull requests and pushes to `main` that change docs | Runs `scripts/check_docs_nav.py` and `fern check`. Uses no secrets. |
| `.github/workflows/docs-preview.yml` | Pull requests from branches in this repository, pushes to `main`, and manual runs | Builds the branch into one shared preview and comments the URL on the pull request. Needs the `FERN_TOKEN_PREVIEW` secret and is skipped without it, which includes pull requests from forks. The preview shows the most recent build. |
| `.github/workflows/docs-publish.yml` | Manual runs from `main` | Publishes the site to the instance URL in `fern/docs.yml` with the `FERN_TOKEN` secret for the `nvidia` Fern organization. |

The workflows install the Fern CLI with `npm install -g fern-api`; Fern then uses the version pinned in `fern/fern.config.json`, so no CLI version is duplicated in CI.

## Publishing

The production site is `docs.nvidia.com/agent-policy-fabric`. Review content through a pull request preview, then run `docs-publish.yml` from `main`. The custom domain in `fern/docs.yml` stays configured while routing is set up.
