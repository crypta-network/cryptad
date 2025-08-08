# Project Configuration

## Development Guidelines

- Primary language: Kotlin/Java
- Code style:
    - Kotlin: Official coding convention described [here](https://kotlinlang.org/docs/coding-conventions.html)
    - Java: Google Java Style Guide described [here](https://google.github.io/styleguide/javaguide.html)
- Testing: JUnit and kotlin-test
- Coverage requirement: 80% minimum

## Repository Etiquette

- Branch naming: main, develop, feature/*, bugfix/*, hotfix/*, release/*
- Merge strategy: GitFlow
- Commit format: Conventional commits
- PR requirements: Tests pass, approved review

## Environment Setup

- Java version: 21 or higher
- Kotlin version: 2.2.0 or higher
- Build: ./gradlew build
- Test: ./gradlew :test --tests [replace with TestClassName]
- Do not use "--no-daemon" for Gradle

## Project-Specific Notes

## Auto-MCP Configuration

# Automatically configures MCP servers based on project type

project_type: full-stack
auto_mcp:

