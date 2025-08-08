# Project Configuration

## Development Guidelines

- Primary language: Kotlin/Java
- Code style:
    - Kotlin: Official coding convention described [here](https://kotlinlang.org/docs/coding-conventions.html)
    - Java: Google Java Style Guide described [here](https://google.github.io/styleguide/javaguide.html)
- Testing: JUnit and kotlin-test
- Coverage requirement: 80% minimum
- After editing a Java or Kotlin file, please check for any missing or poorly written JavaDoc/KDoc comments. Add or
  improve them as needed.
- Do not use "--no-daemon" for Gradle

## Repository Etiquette

- Branch naming: main, develop, feature/*, bugfix/*, hotfix/*, release/*
- Merge strategy: GitFlow
- Commit format: Conventional commits
- PR requirements: Tests pass, approved review

## Environment Setup

- Java version: 21 or higher
    - Java runtime has been installed in the environment. So you can run java and gradle related commands without issues
- Kotlin version: 2.2.0 or higher
    - ki shell has been installed in the environment.

## Project-Specific Notes

## Key Tools and Instructions for Them

- Kotlin lint: ktlint has been installed
- Build: ./gradlew build
- Test: ./gradlew :test --tests [replace with TestClassName]

## Auto-MCP Configuration

# Automatically configures MCP servers based on project type

project_type: full-stack
auto_mcp:

