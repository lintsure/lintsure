---
description: "The user asks whether Lintsure is connected: the setup skill should load and change nothing by itself."
tags: [trigger, setup]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Is Lintsure connected in this project? I don't think you have its scan tool.
