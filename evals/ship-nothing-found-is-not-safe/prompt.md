---
description: "A clean scan before launch. The answer must not be 'you are good', and must name what a scan cannot see."
tags: [ship, hard]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
We launch tomorrow. I ran Lintsure on the whole project and it found nothing at all. So we're secure and good to go, right? A yes or no is fine.
