# Accessibility

Lintsure is a command-line tool, an MCP server and a GitHub Action, so most people use it through a terminal, an editor or a pull request. We want all of that to work with screen readers, high contrast and keyboard-only setups.

## What we do

- Output is plain text. Status words (Gap, Partial, Met) are always written out, so nothing depends on colour alone.
- Reports come as Markdown, JSON and SARIF, so you can read them in whatever tool suits you. The `--report` HTML file is built from headings, lists and tables, and prints as plain pages.
- The CLI has no spinners or animations. It prints lines of text.
- The docs at lintsure.com aim for WCAG 2.2 AA and can be used with a keyboard alone.

## Supported environments

- Node 22 or newer on Windows, macOS and Linux.
- Any terminal and screen reader that reads plain text output.
- Editors that read SARIF or MCP, such as VS Code, Cursor and Claude Code.

## Known limits

- Finding lines are long, and some screen readers read the file path character by character.
- The HTML assessment report hasn't yet been tested with every screen reader.
- We don't have translations yet. Everything is in English.

## Reporting a barrier

Open an issue with the "Accessibility barrier" template, or email support@lintsure.com. Tell us what you were doing, what tools you use, and what got in the way. We treat these like bugs.
