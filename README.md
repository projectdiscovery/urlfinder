<h1 align="center">URLFinder</h1>

<p align="center">
A high-speed tool for passively gathering URLs, optimized for efficient web asset discovery without active scanning.
</p>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/urlfinder"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/urlfinder"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/urlfinder/pkg/urlfinder"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/urlfinder/releases"><img src="https://img.shields.io/github/release/projectdiscovery/urlfinder"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

## Overview

URLFinder is a high-speed, passive URL discovery tool designed to simplify and accelerate web asset discovery, ideal for penetration testers, security researchers, and developers looking to gather URLs without active scanning.

<h1 align="center">
  <img src="https://github.com/user-attachments/assets/dcd6522c-fe5f-4362-8d08-a2faeef9f725" alt="httpx" width="700px">
  <br>
</h1>

## Features

- **Curated Passive Sources** to maximize comprehensive URL discovery
- Supports multiple output formats (JSON, file, stdout)
- **Optimized for Speed** and resource efficiency
- **STDIN/OUT** support for easy integration into existing workflows

## Installation

URLFinder requires **Go 1.21**. Install it using the following command or download a pre-compiled binary from the [releases page](https://github.com/projectdiscovery/urlfinder/releases).

```sh
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
````

# Usage

```sh
urlfinder -h
```

This command displays help for URLFinder. Below are some common switches and options.

```yaml
A streamlined tool for discovering associated URLs.

Usage:
  ./urlfinder [flags]

Flags:
INPUT:
   -d, -list string[]  target domain or list of domains

SOURCE:
   -s, -sources string[]           specific sources for discovery (e.g., -s alienvault,commoncrawl)
   -es, -exclude-sources string[]   sources to exclude (e.g., -es alienvault,commoncrawl)
   -all                             use all sources (may be slower)
SCOPE:
   -us, -url-scope string[]       in scope url regex to be followed by urlfinder
   -uos, -url-out-scope string[]  out of scope url regex to be excluded by urlfinder
   -fs, -field-scope string       pre-defined scope field (dn,rdn,fqdn) or custom regex (e.g., '(company-staging.io|company.com)') (default "rdn")
   -ns, -no-scope                 disables host based default scope
   -do, -display-out-scope        display external endpoint from scoped crawling

FILTER:
   -m, -match string[]       URLs or list to match (file or comma-separated)
   -f, -filter string[]      URLs or list to filter (file or comma-separated)

RATE-LIMIT:
   -rl, -rate-limit int      max HTTP requests per second (global)
   -rls, -rate-limits value  per-provider HTTP request limits (e.g., -rls waybackarchive=15/m)

UPDATE:
   -up, -update              update URLFinder to the latest version
   -duc, -disable-update-check  disable automatic update checks

OUTPUT:
   -o, -output string       specify output file
   -j, -jsonl               JSONL output format
   -od, -output-dir string  specify output directory
   -cs, -collect-sources    include all sources in JSON output

CONFIGURATION:
   -config string           config file (default "$CONFIG/urlfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "$CONFIG/urlfinder/provider-config.yaml")
   -proxy string            HTTP proxy

DEBUG:
   -silent                  show only URLs in output
   -version                 display URLFinder version
   -v                       verbose output
   -nc, -no-color           disable colored output
   -ls, -list-sources       list all available sources
   -stats                   display source statistics

OPTIMIZATION:
   -timeout int   timeout in seconds (default 30)
   -max-time int  max time in minutes for enumeration (default 10)
```

## Examples

### Basic Usage

```console
urlfinder -d tesla.com
```

This command enumerates URLs for the target domain tesla.com.

Example run:

```console
$ urlfinder -d tesla.com

  __  _____  __   _____         __       
 / / / / _ \/ /  / __(_)__  ___/ /__ ____
/ /_/ / , _/ /__/ _// / _ \/ _  / -_) __/
\____/_/|_/____/_/ /_/_//_/\_,_/\__/_/    										

		projectdiscovery.io

[INF] Current urlfinder version v0.0.1 (latest)
[INF] Enumerating urls for tesla.com
https://www.tesla.com/akam/13/7e68a6e8
https://www.tesla.com/akam/13/pixel_4e07b670
https://www.tesla.com/da_dk/en/node/30788?redirect=no
https://www.tesla.com/de_at/findus/location/charger/dc6290
https://www.tesla.com/akam/13/7ade0a44
https://www.tesla.com/cs_cz/referral/teslaapp23713?redirect=no
https://www.tesla.com/da_dk/findus/location/charger/dc253
https://www.tesla.com/akam/13/pixel_76102729
https://www.tesla.com/da_dk/blog/modules//system/system.messages.js
...
[INF] Found 202435 urls for tesla.com in 2 minutes 37 seconds
```

### Filtering Options

Use the `-m` (match) and `-f` (filter) options to refine results based on URL patterns.

#### Examples

1. **Include URLs Matching Specific Patterns**

   To include only URLs containing "shop" or "model":

   ```sh
   urlfinder -d tesla.com -m shop,model
   ```

2. **Exclude URLs Matching Specific Patterns**

   To exclude URLs containing "privacy" or "terms":

   ```sh
   urlfinder -d tesla.com -f privacy,terms
   ```

3. **Combined Match and Filter**

   To find URLs containing "support" but exclude those with "faq":

   ```sh
   urlfinder -d tesla.com -m support -f faq
   ```

#### Using Files for Matching and Filtering

Provide patterns in files:

```sh
urlfinder -d tesla.com -m include-patterns.txt -f exclude-patterns.txt
```

### JSONL Output Example

Use the `-j` or `--jsonl` flag to output results in JSONL (JSON Lines) format, where each line is a separate JSON object. This format is useful for processing large outputs in a structured way.

#### Command Example

```sh
urlfinder -d tesla.com -j
```

#### Example JSONL Output

```json
{"url":"https://shop.tesla.com/product/model-s-plaid","input":"tesla.com","source":"waybackarchive"}
{"url":"https://www.tesla.com/inventory/used/ms","input":"tesla.com","source":"waybackarchive"}
{"url":"https://forums.tesla.com/discussion/101112/model-3-updates","input":"tesla.com","source":"waybackarchive"}
```

Each JSON object contains:
- `url`: The discovered URL.
- `input`: The target domain (e.g., `tesla.com`).
- `source`: The data source for the URL discovery (e.g., `waybackarchive`).

--------

<div align="center">
  URLFinder is made with ❤️ by the <a href="https://projectdiscovery.io">ProjectDiscovery</a> team and distributed under the <a href="LICENSE.md">MIT License</a>.
</div>
