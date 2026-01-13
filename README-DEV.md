# Development guide

## Workspace layout

```
sis-pdf/
  Cargo.toml
  crates/
    sis-pdf-core/      Core scan pipeline, models, reporting
    sis-pdf-pdf/       PDF parsing, object graph, decoding
    sis-pdf-detectors/ Detection rules
    sis-pdf-ml-graph/  Graph ML inference utilities
    sis-pdf/           CLI front-end
    js-analysis/       JavaScript static and dynamic analysis
  docs/                Specifications and analysis documentation
  scripts/
    test_helpers/      Development test fixtures and helper code
```

## Build

```
cargo build
```

To enable JavaScript sandboxing for runtime behaviour analysis:

```
cargo build --features js-sandbox
```

To enable graph ML inference:

```
cargo build --features ml-graph
```

## Tests

```
cargo test
```

## Fuzzing

Install cargo-fuzz:

```
cargo install cargo-fuzz
```

List targets:

```
cd fuzz
cargo fuzz list
```

Run a target (examples):

```
cargo +nightly fuzz run lexer
cargo +nightly fuzz run parser
cargo +nightly fuzz run graph
cargo +nightly fuzz run objstm
cargo +nightly fuzz run decode_streams
```

To use a custom corpus, pass a directory path:

```
cargo +nightly fuzz run parser fuzz/corpus/parser
```

## Status

This is a working implementation aligned to the spec in `docs/sis-pdf-spec.md`. It focuses on parsing correctness, evidence spans, and a practical rule set.

JavaScript malware detection includes comprehensive static analysis across 22 malware categories with ~95% coverage of known PDF JavaScript malware patterns. See `docs/js-detection-roadmap.md` for implementation details and future enhancements.

Expect iterative hardening and expansion.

## GitHub Pages Documentation

The project documentation is published via GitHub Pages at https://michiel.github.io/sis-pdf/

### Repository Setup (One-Time Configuration)

#### 1. Enable GitHub Pages

1. Go to your GitHub repository: https://github.com/michiel/sis-pdf
2. Click **Settings** (top navigation)
3. Click **Pages** (left sidebar under "Code and automation")
4. Under "Build and deployment":
   - **Source**: Select "Deploy from a branch"
   - **Branch**: Select `main`
   - **Folder**: Select `/docs`
5. Click **Save**

#### 2. Wait for Deployment

GitHub Pages will automatically build and deploy your site:
- First deployment takes 1-2 minutes
- You'll see a green checkmark when ready
- A URL will appear: `https://michiel.github.io/sis-pdf/`

#### 3. Verify Deployment

Visit your documentation site:
- **Production URL**: https://michiel.github.io/sis-pdf/
- Check that the index page loads correctly
- Verify all documentation links work

### Custom Domain (Optional)

If you want to use a custom domain like `docs.sis-pdf.com`:

1. In GitHub Pages settings, add your custom domain
2. Create a `docs/CNAME` file with your domain:
   ```
   docs.sis-pdf.com
   ```
3. Configure DNS with your domain provider:
   - Add a `CNAME` record pointing to `michiel.github.io`
   - Or add `A` records for GitHub Pages IPs

See: https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site

### Local Preview

To preview documentation changes locally before pushing:

```bash
# Install dependencies (first time only)
cd docs
bundle install

# Start local Jekyll server
bundle exec jekyll serve

# View at: http://localhost:4000/sis-pdf/
# Auto-reloads when you edit files
```

Press `Ctrl+C` to stop the server.

### Updating Documentation

#### Adding New Pages

1. Create a new `.md` file in `docs/`
2. Add front matter (optional):
   ```yaml
   ---
   title: "Page Title"
   layout: default
   ---
   ```
3. Update `docs/index.md` to link to the new page
4. Commit and push to `main`
5. GitHub Pages rebuilds automatically

#### Editing Existing Pages

1. Edit the `.md` file directly
2. Commit and push to `main`
3. GitHub Pages rebuilds automatically (1-2 minutes)

### Theme Customization

The current theme is `jekyll-theme-cayman`. To change it:

1. Edit `docs/_config.yml`
2. Change the `theme:` value to one of:
   - `jekyll-theme-minimal`
   - `jekyll-theme-architect`
   - `jekyll-theme-slate`
   - `jekyll-theme-cayman` (current)
   - `jekyll-theme-hacker`
   - `jekyll-theme-leap-day`
   - And others...

See: https://pages.github.com/themes/

### Troubleshooting

#### Site Not Building

Check the **Actions** tab in GitHub:
- Look for "pages-build-deployment" workflows
- Click on failed runs to see error messages
- Common issues:
  - Invalid YAML in `_config.yml`
  - Missing dependencies
  - Malformed markdown

#### 404 Errors

- Ensure branch is `main` and folder is `/docs`
- Check that `docs/index.md` exists
- Verify links use relative paths
- Allow 1-2 minutes after pushing for rebuild

#### Local Preview Issues

```bash
# Update dependencies
bundle update

# Clear Jekyll cache
bundle exec jekyll clean

# Rebuild
bundle exec jekyll serve
```

### GitHub Actions (Advanced)

For more control, you can use GitHub Actions workflows instead of the built-in Pages deployment. Create `.github/workflows/pages.yml`:

```yaml
name: Deploy GitHub Pages

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/configure-pages@v3
      - uses: actions/jekyll-build-pages@v1
        with:
          source: ./docs
      - uses: actions/deploy-pages@v2
```

### Resources

- [GitHub Pages Documentation](https://docs.github.com/en/pages)
- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [GitHub Pages Themes](https://pages.github.com/themes/)
- [Markdown Guide](https://www.markdownguide.org/)
