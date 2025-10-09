# POSIS Multi-Repo Watcher

This variant scans a **root folder** that contains multiple local git repos and watches **all** of the corresponding GitHub repositories for comments matching a **regex** trigger. When a match is found for a given repo, it **cds** to that repo's local working directory and executes your external command (default: `codecs exec --stdin`), then posts the result back to the triggering issue.

## Quick start
