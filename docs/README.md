# sis-pdf Documentation

This directory contains the documentation for **Smiley Is Suspicious (sis-pdf)**, a PDF analyzer for detecting suspicious constructs and attack surface.

## View Documentation

- **GitHub Pages**: https://michiel.github.io/sis-pdf/
- **Index**: [index.md](index.md)
- **Setup Guide**: See GitHub Pages section in [../README-DEV.md](../README-DEV.md)

## Documentation Contents

### Getting Started
- [Main README](../README.md) - Installation and quick start
- [Usage Guide](../USAGE.md) - Comprehensive command reference
- [Configuration Guide](configuration.md) - Configuration files and profiles
- [Glossary](glossary.md) - Terminology and concepts

### Core Documentation
- [Technical Specification](sis-pdf-spec.md)
- [Findings Catalog](findings.md) - All 72+ detection rules
- [JavaScript Extraction](JS_EXTRACTION_README.md)
- [JavaScript Analysis Engine](js-analysis-engine.md) - Sandbox architecture, stages, and countermeasures
- [Risk Profiling](risk-profiling.md)

### Machine Learning
- [ML Runtime](ml-runtime.md)
- [ML Modeling](modeling.md)
- [Training Pipeline](training-pipeline.md)

### Testing & Evaluation
- [Corpus Analysis](corpus-analysis.md)
- [Corpus Benchmarking](corpus-benchmarking.md)
- [Test Results](testing-20260111-corpus-2022.md)

### Research
- [PDF State of the Art](pdf-state-of-the-art.md)
- [Datasets](datasets.md)

## Building Documentation Locally

The documentation is built automatically by GitHub Pages when pushed to the `main` branch.

To preview locally, you can use Jekyll:

```bash
cd docs
bundle install
bundle exec jekyll serve
```

Then visit http://localhost:4000/sis-pdf/

## Contributing

To add or update documentation:

1. Create or edit markdown files in the `docs/` directory
2. Update the index.md navigation if adding new pages
3. Commit and push to the `main` branch
4. GitHub Pages will automatically rebuild

## License

See [LICENSE](../LICENSE) in the repository root.
