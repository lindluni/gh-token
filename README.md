# GitHub Token

`gh-token` is a cross-platform [GitHub CLI](https://github.com/cli/cli) extension written in pure Go allowing users to 
generate GitHub API tokens using GitHub App credentials without the need for additional dependencies.

## Installation

To install `gh-token` you must first install the [GitHub CLI](https://github.com/cli/cli) and then run the following
command:

```shell
gh extension install lindluni/gh-token
```

To update `gh-token` you can run the following command:

```shell
gh extension upgrade lindluni/gh-token
```

## Usage

### Generate a token

```shell
$ gh token generate                                                                                                                                          ✔  2.5.5   03:14:59 PM 
NAME:
   gh-token generate - Generate a new GitHub App installation token

USAGE:
   gh-token generate [command options] [arguments...]

OPTIONS:
   --app-id value, -a value           GitHub App ID
   --installation-id value, -i value  GitHub App Installation ID
   --key value, -k value              Path to private key
   --key-base64 value, -b value       A base64 encoded private key
   --api-endpoint value, -o value     GitHub Enterprise Server hostname (default: "api.github.com")
   --export-actions, -e               Export token to the GITHUB_TOKEN environment variable by writing token to the GITHUB_ENV file (default: false)
   --export-var-name value, -v value  Override the default environment variable name to export the token to when using --export-actions (default: "GITHUB_TOKEN")
   --token-only, -t                   Only print the token to stdout, not the full JSON response, useful for piping to other commands (default: false)
   --silent, -s                       Do not print token to stdout (default: false)
   --help, -h                         show help
```
