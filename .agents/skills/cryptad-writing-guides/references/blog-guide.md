# Technical article style guide

This document defines the rules and conventions for Cryptad technical articles, engineering notes, and deep dives.

There is no dedicated blog folder in this repo. Use these patterns when writing a long-form article for `docs/`, a wiki page, a release highlight section, or an external engineering post about Cryptad.

Prerequisite: read `writing-guide.md` first.

## What these articles are

Technical articles explain how Cryptad solved a concrete problem or why a system behaves the way it does. Good topics usually involve architecture, packaging, updater behavior, privacy-sensitive tradeoffs, or platform-specific work.

## Opening pattern

Start by framing the concrete problem before you explain the solution.

Too abstract:

> How do you build a better updater for a distributed system?

Better:

> Cryptad no longer replaces its core JAR in place. Instead, the updater downloads an OS-specific package and hands installation off to the operating system.

The opening should make the reader think `that changed something real`.

## Structure

Technical articles usually follow this arc:

1. Frame the problem.
2. Show the key idea.
3. Walk through the implementation.
4. Wrap up with tradeoffs, file locations, and open questions.

## Tone

- Explain what we did, not what an imaginary user should do.
- Keep the writing warm but disciplined.
- Use concrete examples from Cryptad's code, packaging, or runtime behavior.
- End with a tradeoff, limitation, or future direction when that helps the reader understand the design.

## Code and command examples

- Show the shortest example that reveals the design.
- Build up complexity only when each step teaches something.
- Point to the real file or subsystem at the end.

## Topics that fit well

- Package-based core updates and why they replaced in-place JAR updates.
- Launcher behavior across Linux, macOS, and Windows.
- App environment detection, sandbox handling, and installer integration.
- Privacy-preserving routing or datastore design choices that have operator-visible effects.
- Build and packaging work that changed the shipped artifacts or deployment model.

## Topics that do not fit well

- Raw feature announcements with no technical insight.
- Pure refactors with no external effect.
- Vague privacy claims that are not backed by the implementation.

## Evaluation checklist

- [ ] The opening frames a concrete problem.
- [ ] The article has a clear technical insight.
- [ ] Examples use real Cryptad components or files.
- [ ] The wrap-up names the relevant files, tradeoffs, or follow-up work.
