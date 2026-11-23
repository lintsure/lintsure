---
description: The user says the agent is drifting: the stay-on-track skill should load.
tags: [trigger]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
You keep ignoring my project rules. Before you start the big refactor of the dashboard, go back and check what they say.
