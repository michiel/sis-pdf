# Clean samples for baselining

The files in `in/` are the inputs for PDF generation flows.
This files in `out/` are the outputs

| Renderer | Input | Output |
|---------------|----------|---------------|
| Google Chrome (Linux) | `in/empty.html` | 'out/chrome-linux-empty.pdf' |
| Google Chrome (Linux) | `in/basic.html` | 'out/chrome-linux-basic.pdf' |
| pandoc 3.6.4 | `in/empty.md` | 'out/pandoc-empty.pdf' |
| pandoc 3.6.4 | `in/basic.md` | 'out/pandoc-basic.pdf' |

These samples are generated to be "known good".
