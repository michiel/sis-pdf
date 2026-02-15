# egui UI plan for sis

## Startup

 - Keep the start screen as-is (drop/upload PDF)
 - Show a progress bar for uploading/processing

## Main UI

 - The egui.rs website that demonstrates the capabilities is the template for this app
 - There is a top bar (top-bar) that has a theme icon (this moves to the far right and has a settings icon next to it)
 - Far left of the top-bar is the "File.." menu that has a drop-down with "Open file.." this opens a dialog for dropping/uploading a pdf
 - Each PDF has its own window context, we can switch between them, each open pdf adds a navigation item to the top-bar (max 5)
 - Each window context is the workspace under the top-bar
 - The workspace has a narrow workspace-top-bar that has the file name, bytes, objects, findings (h/m/l/i), chains
 - There is a narrow left column with buttons to start navigating the PDF (metadata, findings, etc)
 - Each button opens a resizeable window in the workspace
   - metadata : table (clickable for details)
   - findings : table (sortable, filterable, clickable for details)
   - query: REPL window with capabilities adjusted or limited (e.g. | to shell is non-existent for web but we might have built-in commands)
   - org : visualised directed graph of the graph 'org' in a 'scene' view
   - etc
 - Windows are resizable, closeable
 - Clicking a top-bar shortened pdf name label switches the workspace to that context


