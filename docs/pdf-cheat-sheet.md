# PDF structure cheat sheet

This guide assumes you are exploring the raw code of a PDF file through the `sis` scan and query tools.

---

## Quick query tips

```bash
# Stream results for pipelines
sis query js.count file.pdf --format jsonl

# Extract raw or hexdump payloads
sis query js file.pdf --extract-to /tmp/out --raw
sis query embedded file.pdf --extract-to /tmp/out --hexdump

# Find what references a specific object
sis query file.pdf ref 52 0
```

---

## 1. High-Level File Structure

A PDF file is read from the **bottom up**. It consists of four main sections.

### A. The Header

This is the very first line of the file. It specifies the PDF version.

```text
%PDF-1.7

```

* **Vocabulary:** The `%` sign usually denotes a comment, but in the header, it acts as a magic number indicating the file type.

### B. The Body

This contains the **Objects** that make up the document (text, images, fonts, navigation). Each object is numbered.

### C. The Cross-Reference Table (`xref`)

This is a directory that tells the PDF reader the byte offset of every object in the file. It allows the reader to jump randomly to specific data without reading the whole file.

### D. The Trailer

Located at the very end of the file. It tells the reader:

1. Where the `xref` table starts.
2. Which object is the **Root** (Catalog) of the document.
3. Metadata about the file (ID, encryption).

**Example Trailer:**

```text
trailer
<< /Size 15 /Root 1 0 R >>
startxref
4560
%%EOF

```

* `startxref`: The byte offset of the Xref table.
* `%%EOF`: End of File marker.

---

## 2. The PDF Object System

PDFs are built using a specific set of data types called **Objects**.

### Basic Objects

* **Booleans:** `true` or `false`
* **Numerics:** Integers (`123`) or Reals (`123.45`)
* **Strings:** Enclosed in parentheses `(Hello World)` or hex brackets `<48656c6c6f>`
* **Names:** Identifiers that start with a forward slash. They are used as keys in dictionaries.
* *Example:* `/Type`, `/Pages`, `/Kids`


* **Null:** The null object `null`

### Complex Objects

#### 1. Arrays

Ordered lists of objects enclosed in square brackets.

```text
[54 0 0 12 /Name (String)]

```

#### 2. Dictionaries

The most common structure. It is a collection of key-value pairs enclosed in double angle brackets `<< ... >>`. The key is always a **Name** object.

```text
<<
  /Type /Page
  /Parent 3 0 R
  /MediaBox [ 0 0 612 792 ]
>>

```

#### 3. Indirect Objects

Objects that are labeled so they can be referenced elsewhere. They are wrapped in `obj` and `endobj` keywords.

* **Structure:** `[Object Number] [Generation Number] obj ... endobj`
* **Reference:** To use this object elsewhere, you refer to it using `R`.

**Definition:**

```text
10 0 obj
  (I am object 10)
endobj

```

**Reference:**

```text
/Title 10 0 R

```

#### 4. Streams

Used for large data (images, massive text blocks). A stream consists of a Dictionary (describing the data, e.g., length, compression) followed by the raw byte stream.

```text
5 0 obj
<< /Length 45 /Filter /FlateDecode >>
stream
...[binary garbage data]...
endstream
endobj

```

---

## 3. The Document Structure (The Hierarchy)

To render a PDF, the reader follows a specific tree structure starting from the Trailer.

### Step 1: The Trailer -> The Catalog (Root)

The trailer points to the Root object (The Catalog).

```text
/Root 1 0 R

```

### Step 2: The Catalog -> The Page Tree

Object 1 (The Catalog) tells the reader where the tree of pages begins.

```text
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R  % Points to the root of the page tree
>>
endobj

```

### Step 3: The Page Tree -> Page Objects

Object 2 is usually a "Node" in the tree. It lists its children (which can be more nodes or actual pages).

```text
2 0 obj
<<
  /Type /Pages
  /Kids [ 3 0 R 4 0 R ] % Array of Page Objects
  /Count 2
>>
endobj

```

### Step 4: The Page Object

This describes a single page. It holds the content (text/images) and resources (fonts).

```text
3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [ 0 0 612 792 ] % The physical size of the page
  /Contents 5 0 R % The stream containing the actual text commands
>>
endobj

```

---

## 4. Understanding Actions and Destinations (/D, /S, /Fit, /GoTo)

When you asked about `/D` and `/S`, you are referring to **Actions** (interactive features like links or bookmarks) and **Destinations**.

These usually appear inside **Annotation dictionaries** (for links on a page) or the **Outline dictionary** (for bookmarks).

### The Action Dictionary

If you click a link, the PDF executes an "Action".

* **/S:** Stands for **Subtype**. It defines *what kind* of action occurs.
* **/D:** Stands for **Destination**. It defines *where* the view jumps to.

### Common Action Types (/S)

1. **/GoTo**: Go to a destination within the current document.
```text
<<
  /Type /Action
  /S /GoTo
  /D [ 3 0 R /Fit ]
>>

```


2. **/GoToR**: Go to a destination in a **Remote** file (another PDF).
3. **/URI**: Open a URL in a web browser.
```text
<<
  /Type /Action
  /S /URI
  /URI (http://www.google.com)
>>

```



### Common Destinations (/D)

The `/D` key usually takes an array. The first element is the Page Object reference, and the second is the **View Mode**.

#### 1. /Fit (Fit Page)

Fits the entire page within the window.

* **Syntax:** `[ page /Fit ]`
* *Example:* `[ 3 0 R /Fit ]` (Jump to Page 3 and zoom to fit the whole page).

#### 2. /XYZ (Explicit Coordinates)

Keeps the zoom/position exactly as specified.

* **Syntax:** `[ page /XYZ left top zoom ]`
* **Nulls:** You can use `null` to mean "keep current value".
* *Example:* `[ 3 0 R /XYZ null null null ]` (Go to Page 3 but keep current zoom and scroll position).

#### 3. /FitH (Fit Horizontal)

Fits the width of the page to the window; usually allows scrolling down.

* **Syntax:** `[ page /FitH top ]`
* *Example:* `[ 3 0 R /FitH 800 ]` (Jump to Page 3, scroll to vertical position 800, and fit width).

#### 4. /FitR (Fit Rectangle)

Zooms into a specific rectangle on the page.

* **Syntax:** `[ page /FitR left bottom right top ]`

---

## 5. Summary Cheat Sheet

| Key | Meaning | Context |
| --- | --- | --- |
| **<< >>** | Dictionary | Container for key/values |
| **[ ]** | Array | List of items |
| **R** | Reference | `1 0 R` links to `1 0 obj` |
| **/Type** | Object Type | e.g., `/Page`, `/Catalog`, `/Font` |
| **/Subtype** | Specific Type | e.g., `/Image`, `/Type1` |
| **/S** | Action Subtype | Used in links (e.g., `/GoTo`, `/URI`) |
| **/D** | Destination | Where a link jumps to |
| **/Kids** | Children | Used in Page Trees |
| **/Parent** | Parent | Used in Pages to point up the tree |
| **/Contents** | Content Stream | Points to the raw drawing commands |
