#!/usr/bin/env python3
"""
Elasticsearch MCP Server for root cause analysis and performance optimization.
Provides tools to query Elasticsearch, analyze logs, and suggest improvements.
"""

from fastmcp import FastMCP
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import re
from collections import Counter, defaultdict
from typing import Dict, List, Any, Optional

mcp = FastMCP("Elasticsearch Analysis MCP Server")

# Default Elasticsearch configuration
DEFAULT_ES_HOST = "localhost:9200"
DEFAULT_INDEX_PATTERN = "*"

def get_elasticsearch_client(host: str = DEFAULT_ES_HOST, 
                           username: Optional[str] = None, 
                           password: Optional[str] = None) -> Elasticsearch:
    """Create Elasticsearch client with optional authentication."""
    if username and password:
        return Elasticsearch([host], basic_auth=(username, password))
    return Elasticsearch([host])

@mcp.tool()
def search_elasticsearch_logs(query: str, 
                            index_pattern: str = DEFAULT_INDEX_PATTERN,
                            size: int = 100,
                            time_range: str = "1h",
                            host: str = DEFAULT_ES_HOST) -> str:
    """
    Search Elasticsearch logs with flexible query syntax.
    
    Args:
        query: Elasticsearch query (can be simple text or JSON query)
        index_pattern: Index pattern to search (default: *)
        size: Number of results to return (default: 100)
        time_range: Time range for search (1h, 1d, 1w, etc.)
        host: Elasticsearch host (default: localhost:9200)
    
    Returns:
        JSON formatted search results
    """
    try:
        es = get_elasticsearch_client(host)
        
        # Parse time range
        time_delta = parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_delta
        
        # Build search body
        if query.strip().startswith('{'):
            # JSON query provided
            search_body = json.loads(query)
        else:
            # Simple text query
            search_body = {
                "query": {
                    "bool": {
                        "must": [
                            {"query_string": {"query": query}},
                            {"range": {"@timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        
        response = es.search(index=index_pattern, body=search_body, size=size)
        
        results = {
            "total_hits": response['hits']['total']['value'],
            "results": []
        }
        
        for hit in response['hits']['hits']:
            results["results"].append({
                "timestamp": hit['_source'].get('@timestamp'),
                "index": hit['_index'],
                "message": hit['_source'].get('message', str(hit['_source'])),
                "level": hit['_source'].get('level', 'unknown'),
                "source": hit['_source']
            })
        
        return json.dumps(results, indent=2, default=str)
        
    except Exception as e:
        return f"Error searching Elasticsearch: {str(e)}"

@mcp.tool()
def analyze_error_patterns(index_pattern: str = DEFAULT_INDEX_PATTERN,
                          time_range: str = "1h",
                          host: str = DEFAULT_ES_HOST) -> str:
    """
    Analyze error patterns in logs to identify common issues and root causes.
    
    Args:
        index_pattern: Index pattern to analyze
        time_range: Time range for analysis
        host: Elasticsearch host
    
    Returns:
        Detailed analysis of error patterns and suggested root causes
    """
    try:
        es = get_elasticsearch_client(host)
        time_delta = parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_delta
        
        # Search for error logs
        search_body = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}},
                        {"bool": {
                            "should": [
                                {"match": {"level": "error"}},
                                {"match": {"level": "ERROR"}},
                                {"wildcard": {"message": "*error*"}},
                                {"wildcard": {"message": "*ERROR*"}},
                                {"wildcard": {"message": "*exception*"}},
                                {"wildcard": {"message": "*Exception*"}},
                                {"range": {"status": {"gte": 400}}}
                            ],
                            "minimum_should_match": 1
                        }}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        response = es.search(index=index_pattern, body=search_body, size=1000)
        
        if response['hits']['total']['value'] == 0:
            return "No errors found in the specified time range."
        
        # Analyze patterns
        error_patterns = analyze_log_patterns(response['hits']['hits'])
        
        analysis = {
            "summary": {
                "total_errors": response['hits']['total']['value'],
                "time_range": f"{start_time.isoformat()} to {end_time.isoformat()}",
                "analysis_time": datetime.utcnow().isoformat()
            },
            "top_error_patterns": error_patterns["patterns"][:10],
            "affected_services": error_patterns["services"],
            "error_timeline": error_patterns["timeline"],
            "root_cause_analysis": generate_root_cause_analysis(error_patterns),
            "recommendations": generate_recommendations(error_patterns)
        }
        
        return json.dumps(analysis, indent=2, default=str)
        
    except Exception as e:
        return f"Error analyzing error patterns: {str(e)}"

@mcp.tool()
def analyze_performance_issues(index_pattern: str = DEFAULT_INDEX_PATTERN,
                              time_range: str = "1h",
                              response_time_threshold: int = 1000,
                              host: str = DEFAULT_ES_HOST) -> str:
    """
    Analyze performance issues including slow queries, high response times, and resource usage.
    
    Args:
        index_pattern: Index pattern to analyze
        time_range: Time range for analysis
        response_time_threshold: Response time threshold in ms (default: 1000ms)
        host: Elasticsearch host
    
    Returns:
        Performance analysis with bottlenecks and optimization suggestions
    """
    try:
        es = get_elasticsearch_client(host)
        time_delta = parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_delta
        
        # Search for performance-related logs
        search_body = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}}
                    ],
                    "should": [
                        {"range": {"response_time": {"gte": response_time_threshold}}},
                        {"range": {"duration": {"gte": response_time_threshold}}},
                        {"wildcard": {"message": "*slow*"}},
                        {"wildcard": {"message": "*timeout*"}},
                        {"wildcard": {"message": "*performance*"}},
                        {"range": {"cpu_usage": {"gte": 80}}},
                        {"range": {"memory_usage": {"gte": 80}}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        response = es.search(index=index_pattern, body=search_body, size=1000)
        
        performance_analysis = analyze_performance_data(response['hits']['hits'])
        
        analysis = {
            "summary": {
                "total_performance_issues": response['hits']['total']['value'],
                "time_range": f"{start_time.isoformat()} to {end_time.isoformat()}",
                "threshold": f"{response_time_threshold}ms"
            },
            "slow_operations": performance_analysis["slow_ops"],
            "resource_bottlenecks": performance_analysis["bottlenecks"],
            "performance_trends": performance_analysis["trends"],
            "optimization_recommendations": generate_performance_recommendations(performance_analysis)
        }
        
        return json.dumps(analysis, indent=2, default=str)
        
    except Exception as e:
        return f"Error analyzing performance: {str(e)}"

@mcp.tool()
def get_cluster_health(host: str = DEFAULT_ES_HOST) -> str:
    """
    Get comprehensive Elasticsearch cluster health information.
    
    Args:
        host: Elasticsearch host
    
    Returns:
        Detailed cluster health analysis with recommendations
    """
    try:
        es = get_elasticsearch_client(host)
        
        # Get cluster health
        health = es.cluster.health()
        
        # Get cluster stats
        stats = es.cluster.stats()
        
        # Get node info
        nodes = es.nodes.info()
        
        # Get indices stats
        indices_stats = es.indices.stats()
        
        health_analysis = {
            "cluster_status": health['status'],
            "cluster_name": health['cluster_name'],
            "nodes": {
                "total": health['number_of_nodes'],
                "data_nodes": health['number_of_data_nodes'],
                "active_shards": health['active_shards'],
                "relocating_shards": health['relocating_shards'],
                "initializing_shards": health['initializing_shards'],
                "unassigned_shards": health['unassigned_shards']
            },
            "storage": {
                "total_size": stats['indices']['store']['size_in_bytes'],
                "total_documents": stats['indices']['docs']['count']
            },
            "performance_metrics": analyze_cluster_performance(health, stats, indices_stats),
            "health_recommendations": generate_cluster_recommendations(health, stats)
        }
        
        return json.dumps(health_analysis, indent=2, default=str)
        
    except Exception as e:
        return f"Error getting cluster health: {str(e)}"

@mcp.tool()
def analyze_index_performance(index_pattern: str = DEFAULT_INDEX_PATTERN,
                             host: str = DEFAULT_ES_HOST) -> str:
    """
    Analyze specific index performance and suggest optimizations.
    
    Args:
        index_pattern: Index pattern to analyze
        host: Elasticsearch host
    
    Returns:
        Index-specific performance analysis and optimization recommendations
    """
    try:
        es = get_elasticsearch_client(host)
        
        # Get index stats
        index_stats = es.indices.stats(index=index_pattern)
        
        # Get index settings
        index_settings = es.indices.get_settings(index=index_pattern)
        
        # Get index mapping
        index_mapping = es.indices.get_mapping(index=index_pattern)
        
        analysis = {}
        
        for index_name, stats in index_stats['indices'].items():
            index_analysis = {
                "index_name": index_name,
                "document_count": stats['primaries']['docs']['count'],
                "size": stats['primaries']['store']['size_in_bytes'],
                "shards": {
                    "primary": stats['primaries'],
                    "total": stats['total']
                },
                "performance_metrics": {
                    "search_queries": stats['total']['search']['query_total'],
                    "search_time": stats['total']['search']['query_time_in_millis'],
                    "indexing_operations": stats['total']['indexing']['index_total'],
                    "indexing_time": stats['total']['indexing']['index_time_in_millis']
                },
                "optimization_suggestions": generate_index_optimization_suggestions(
                    stats, 
                    index_settings.get(index_name, {}), 
                    index_mapping.get(index_name, {})
                )
            }
            analysis[index_name] = index_analysis
        
        return json.dumps(analysis, indent=2, default=str)
        
    except Exception as e:
        return f"Error analyzing index performance: {str(e)}"

def parse_time_range(time_range: str) -> timedelta:
    """Parse time range string like '1h', '2d', '1w' into timedelta."""
    pattern = r'(\d+)([smhd]|min|hour|day|week)'
    match = re.match(pattern, time_range.lower())
    
    if not match:
        return timedelta(hours=1)  # default
    
    value, unit = match.groups()
    value = int(value)
    
    if unit in ['s', 'sec']:
        return timedelta(seconds=value)
    elif unit in ['m', 'min']:
        return timedelta(minutes=value)
    elif unit in ['h', 'hour']:
        return timedelta(hours=value)
    elif unit in ['d', 'day']:
        return timedelta(days=value)
    elif unit in ['w', 'week']:
        return timedelta(weeks=value)
    
    return timedelta(hours=1)

def analyze_log_patterns(hits: List[Dict]) -> Dict:
    """Analyze log patterns to identify common error signatures."""
    patterns = Counter()
    services = Counter()
    timeline = defaultdict(int)
    
    for hit in hits:
        source = hit['_source']
        message = source.get('message', '')
        timestamp = source.get('@timestamp', '')
        service = source.get('service', source.get('logger_name', 'unknown'))
        
        # Extract error patterns
        error_signature = extract_error_signature(message)
        patterns[error_signature] += 1
        services[service] += 1
        
        # Timeline analysis (hourly buckets)
        if timestamp:
            hour = timestamp[:13]  # YYYY-MM-DDTHH
            timeline[hour] += 1
    
    return {
        "patterns": [{"pattern": k, "count": v} for k, v in patterns.most_common()],
        "services": dict(services.most_common()),
        "timeline": dict(timeline)
    }

def extract_error_signature(message: str) -> str:
    """Extract meaningful error signature from log message."""
    # Remove timestamps, IDs, and variable data
    signature = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', message)
    signature = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID', signature)
    signature = re.sub(r'\b\d+\.\d+\.\d+\.\d+\b', 'IP_ADDRESS', signature)
    signature = re.sub(r'\b\d{10,}\b', 'LONG_NUMBER', signature)
    signature = re.sub(r'/\w+/\w+/\w+', '/PATH/PATH/PATH', signature)
    
    # Keep first 200 characters for pattern matching
    return signature[:200]

def generate_root_cause_analysis(error_patterns: Dict) -> List[str]:
    """Generate root cause analysis based on error patterns."""
    analysis = []
    
    top_patterns = error_patterns["patterns"][:5]
    services = error_patterns["services"]
    
    # Analyze top error patterns
    for pattern in top_patterns:
        error_text = pattern["pattern"].lower()
        count = pattern["count"]
        
        if "connection" in error_text and ("refused" in error_text or "timeout" in error_text):
            analysis.append(f"Network connectivity issues detected ({count} occurrences). Check service dependencies and network configuration.")
        elif "memory" in error_text or "heap" in error_text:
            analysis.append(f"Memory-related issues found ({count} occurrences). Consider increasing heap size or optimizing memory usage.")
        elif "database" in error_text or "sql" in error_text:
            analysis.append(f"Database connectivity or query issues detected ({count} occurrences). Check database health and query performance.")
        elif "authentication" in error_text or "unauthorized" in error_text:
            analysis.append(f"Authentication failures found ({count} occurrences). Verify credentials and auth service status.")
        elif "disk" in error_text or "space" in error_text:
            analysis.append(f"Storage issues detected ({count} occurrences). Check disk usage and cleanup old logs/data.")
    
    # Analyze service distribution
    if len(services) > 0:
        top_affected_service = max(services.items(), key=lambda x: x[1])
        analysis.append(f"Most affected service: {top_affected_service[0]} with {top_affected_service[1]} errors.")
    
    return analysis

def generate_recommendations(error_patterns: Dict) -> List[str]:
    """Generate actionable recommendations based on error analysis."""
    recommendations = []
    
    recommendations.extend([
        "Implement comprehensive monitoring and alerting for critical services",
        "Set up proper log aggregation and structured logging",
        "Consider implementing circuit breakers for external service calls",
        "Review and optimize database connection pooling",
        "Implement proper retry mechanisms with exponential backoff",
        "Set up health checks for all critical components",
        "Consider implementing graceful degradation for non-critical features"
    ])
    
    return recommendations

def analyze_performance_data(hits: List[Dict]) -> Dict:
    """Analyze performance data from log entries."""
    slow_ops = []
    bottlenecks = Counter()
    trends = defaultdict(list)
    
    for hit in hits:
        source = hit['_source']
        
        # Extract performance metrics
        response_time = source.get('response_time') or source.get('duration')
        cpu_usage = source.get('cpu_usage')
        memory_usage = source.get('memory_usage')
        operation = source.get('operation') or source.get('endpoint', 'unknown')
        
        if response_time and response_time > 1000:
            slow_ops.append({
                "operation": operation,
                "response_time": response_time,
                "timestamp": source.get('@timestamp')
            })
        
        if cpu_usage and cpu_usage > 80:
            bottlenecks["high_cpu"] += 1
        
        if memory_usage and memory_usage > 80:
            bottlenecks["high_memory"] += 1
    
    return {
        "slow_ops": sorted(slow_ops, key=lambda x: x.get("response_time", 0), reverse=True)[:20],
        "bottlenecks": dict(bottlenecks),
        "trends": dict(trends)
    }

def generate_performance_recommendations(performance_analysis: Dict) -> List[str]:
    """Generate performance optimization recommendations."""
    recommendations = []
    
    if performance_analysis["slow_ops"]:
        recommendations.append("Optimize slow operations identified in the analysis")
        recommendations.append("Consider adding database indexes for slow queries")
        recommendations.append("Implement caching for frequently accessed data")
    
    if "high_cpu" in performance_analysis["bottlenecks"]:
        recommendations.append("Investigate high CPU usage - consider scaling or optimization")
    
    if "high_memory" in performance_analysis["bottlenecks"]:
        recommendations.append("Memory usage is high - check for memory leaks and optimize")
    
    recommendations.extend([
        "Implement proper connection pooling",
        "Consider using asynchronous processing for heavy operations",
        "Review and optimize critical code paths",
        "Consider horizontal scaling if bottlenecks persist"
    ])
    
    return recommendations

def analyze_cluster_performance(health: Dict, stats: Dict, indices_stats: Dict) -> Dict:
    """Analyze cluster-level performance metrics."""
    metrics = {
        "status_health": "healthy" if health['status'] == 'green' else "attention_needed",
        "shard_health": "good" if health['unassigned_shards'] == 0 else "issues_detected",
        "node_distribution": "balanced" if health['active_shards'] > 0 else "unbalanced"
    }
    
    return metrics

def generate_cluster_recommendations(health: Dict, stats: Dict) -> List[str]:
    """Generate cluster-level recommendations."""
    recommendations = []
    
    if health['status'] == 'yellow':
        recommendations.append("Cluster status is yellow - check shard allocation and replica settings")
    elif health['status'] == 'red':
        recommendations.append("CRITICAL: Cluster status is red - immediate attention required")
    
    if health['unassigned_shards'] > 0:
        recommendations.append(f"Found {health['unassigned_shards']} unassigned shards - check node capacity and shard allocation")
    
    recommendations.extend([
        "Monitor heap usage and adjust JVM settings if needed",
        "Ensure proper index lifecycle management (ILM) policies",
        "Regular backup and snapshot strategy implementation",
        "Monitor disk usage across all nodes"
    ])
    
    return recommendations

def generate_index_optimization_suggestions(stats: Dict, settings: Dict, mapping: Dict) -> List[str]:
    """Generate index-specific optimization suggestions."""
    suggestions = []
    
    doc_count = stats['primaries']['docs']['count']
    size = stats['primaries']['store']['size_in_bytes']
    
    if doc_count > 10000000:  # 10M docs
        suggestions.append("Consider implementing index lifecycle management for large indices")
    
    if size > 50 * 1024 * 1024 * 1024:  # 50GB
        suggestions.append("Large index detected - consider splitting or archiving old data")
    
    suggestions.extend([
        "Review mapping for unnecessary fields that could be excluded",
        "Consider using appropriate analyzers for text fields",
        "Optimize refresh interval based on use case",
        "Review shard count - ensure optimal distribution"
    ])
    
    return suggestions

if __name__ == "__main__":
    mcp.run(transport="stdio")