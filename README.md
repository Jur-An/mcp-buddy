# mcp-buddy

Little buddy to simplify key management for MCP services.

## Usage

Run commands with Python:

```bash
python /home/runner/work/mcp-buddy/mcp-buddy/mcp_buddy.py --help
```

### Store a key

```bash
python /home/runner/work/mcp-buddy/mcp-buddy/mcp_buddy.py set cursor OPENAI_API_KEY sk-...
```

### Use a key for a service

```bash
eval "$(python /home/runner/work/mcp-buddy/mcp-buddy/mcp_buddy.py export cursor)"
```

### Other commands

- `get <service> <key> [--reveal]`
- `list [service]`
- `unset <service> <key>`
- `export <service>`

## Tests

```bash
cd /home/runner/work/mcp-buddy/mcp-buddy
python -m unittest discover -s tests
```
