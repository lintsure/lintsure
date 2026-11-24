---
description: "A request to connect an agent. The skill uses lintsure setup and its preview, and does not hand-write a config."
tags: [setup, hard]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Add Lintsure to Cursor for this project. Just give me whatever I need to paste into the config file.
