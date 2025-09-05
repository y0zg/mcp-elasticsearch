# Elasticsearch MCP Server

An AI-powered log analysis tool that connects Claude Desktop directly to your Elasticsearch cluster. Ask Claude questions about your logs in plain English and get intelligent insights.

## What it does

Instead of writing complex Elasticsearch queries, just ask Claude things like:
- "Show me all 5xx errors from the last hour"
- "What's causing the slow database queries?"
- "Find unique IPs hitting my API in the last 5 minutes"
- "Is my Elasticsearch cluster healthy?"

Claude will search your logs, analyze patterns, and give you actionable insights.

## Quick setup

### 1. Install dependencies
```bash
cd mcp-elasticsearch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Build the extension
```bash
npm install -g @anthropic-ai/dxt
dxt init  # Use 'mcp-elasticsearch-server.py' as entry point
dxt pack
```

### 3. Install in Claude Desktop
- Double-click the generated `mcp-elasticsearch.dxt` file
- Click "Install" when prompted
- Restart Claude Desktop

That's it! Now you can chat with your logs.

## Real examples

**You:** "Find unique public IPs for ingress traffic in the last 5 minutes"

<img width="826" height="727" alt="SCR-20250905-ryei" src="https://github.com/user-attachments/assets/48932686-c85f-406e-947e-fefbe9cb3a2f" />

## Configuration

The extension connects to `localhost:9200` by default. To change this, edit the `ES_HOST` in `manifest.json`:

```json
"env": {
  "ES_HOST": "your-elasticsearch-host:9200"
}
```

For secured clusters, you can add username/password through environment variables.

## Requirements

- Elasticsearch 7.x or 8.x (tested with v8)
- Python 3.8+
- Claude Desktop (latest version)
- Node.js (for building the extension)

## Troubleshooting

**Extension won't install?**
- Make sure you have the latest Claude Desktop
- Try removing old extensions first

**Connection errors?**
- Check if Elasticsearch is running
- Verify the host/port in your config

**Still having issues?**
```bash
# Test the connection manually
source venv/bin/activate
python -c "from elasticsearch import Elasticsearch; print('Connected:', Elasticsearch(['localhost:9200']).ping())"
```

## What's included

The MCP server gives Claude these tools:
- `search_elasticsearch_logs` - Basic log searching
- `analyze_error_patterns` - Find and categorize errors
- `analyze_performance_issues` - Detect slow operations
- `get_cluster_health` - Monitor Elasticsearch health
- `analyze_index_performance` - Optimize index performance

## Time ranges

Use natural language for time ranges:
- "last 5 minutes", "1 hour", "2 days", "1 week"
- Or shortcuts like "5m", "1h", "2d", "1w"


## License

MIT - use it however you want.

---

**Ready to chat with your logs?** Install the extension and start asking Claude questions about your Elasticsearch data!
