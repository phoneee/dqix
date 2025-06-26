#!/usr/bin/env python3
"""
DQIX Language Comparison Analysis

Analyzes benchmark results to compare programming language paradigms
and their impact on domain quality assessment performance.
"""

import argparse
import json
import os
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import matplotlib.pyplot as plt
import pandas as pd

class LanguageComparator:
    """Analyzes and compares language implementation performance"""
    
    def __init__(self, results_dir: str = "benchmarks/results"):
        self.results_dir = results_dir
        self.results = []
        self.load_results()
    
    def load_results(self):
        """Load all benchmark result files"""
        results_path = Path(self.results_dir)
        if not results_path.exists():
            print(f"Results directory not found: {self.results_dir}")
            return
        
        for file_path in results_path.glob("benchmark_results_*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    data['source_file'] = str(file_path)
                    self.results.append(data)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        
        print(f"Loaded {len(self.results)} benchmark result files")
    
    def extract_performance_metrics(self) -> pd.DataFrame:
        """Extract performance metrics into a pandas DataFrame"""
        rows = []
        
        for result in self.results:
            timestamp = result.get('timestamp', 'unknown')
            system_info = result.get('system_info', {})
            
            for lang, lang_data in result.get('languages', {}).items():
                if not lang_data.get('available', False):
                    continue
                
                # Basic metrics
                row = {
                    'timestamp': timestamp,
                    'language': lang,
                    'platform': system_info.get('platform', 'unknown'),
                    'cpu_count': system_info.get('cpu_count', 0),
                    'memory_gb': system_info.get('memory_gb', 0),
                    'startup_time': lang_data.get('startup_time', 0)
                }
                
                # Single domain metrics
                single_domain_times = []
                single_domain_memory = []
                for domain, domain_data in lang_data.get('single_domain', {}).items():
                    if isinstance(domain_data, dict) and 'execution_time' in domain_data:
                        single_domain_times.append(domain_data['execution_time'])
                        single_domain_memory.append(domain_data.get('memory_peak', 0))
                
                if single_domain_times:
                    row['single_domain_avg_time'] = statistics.mean(single_domain_times)
                    row['single_domain_min_time'] = min(single_domain_times)
                    row['single_domain_max_time'] = max(single_domain_times)
                    row['single_domain_avg_memory'] = statistics.mean(single_domain_memory)
                
                # Bulk assessment metrics
                bulk_throughputs = []
                bulk_times = []
                for bulk_name, bulk_data in lang_data.get('bulk_assessment', {}).items():
                    if isinstance(bulk_data, dict) and 'throughput' in bulk_data:
                        bulk_throughputs.append(bulk_data['throughput'])
                        bulk_times.append(bulk_data['execution_time'])
                
                if bulk_throughputs:
                    row['bulk_max_throughput'] = max(bulk_throughputs)
                    row['bulk_avg_throughput'] = statistics.mean(bulk_throughputs)
                    row['bulk_avg_time'] = statistics.mean(bulk_times)
                
                rows.append(row)
        
        return pd.DataFrame(rows)
    
    def generate_paradigm_analysis(self, df: pd.DataFrame) -> str:
        """Generate analysis of programming paradigm impacts"""
        analysis = []
        analysis.append("# Programming Paradigm Analysis for DQIX")
        analysis.append("")
        analysis.append("## Language Characteristics")
        analysis.append("")
        
        # Language-specific analysis
        paradigms = {
            'python': {
                'type': 'Dynamic, Interpreted, Object-Oriented',
                'strengths': ['Rapid development', 'Rich ecosystem', 'Easy debugging'],
                'weaknesses': ['Runtime performance', 'GIL limitations', 'Memory usage'],
                'dqix_impact': 'Excellent for prototyping probes, slower for bulk assessments'
            },
            'go': {
                'type': 'Static, Compiled, Concurrent',
                'strengths': ['Simple concurrency', 'Fast compilation', 'Good performance'],
                'weaknesses': ['Verbose error handling', 'Limited generics', 'Larger binaries'],
                'dqix_impact': 'Balanced performance and simplicity for network operations'
            },
            'rust': {
                'type': 'Static, Compiled, Systems',
                'strengths': ['Memory safety', 'Zero-cost abstractions', 'Maximum performance'],
                'weaknesses': ['Learning curve', 'Complex type system', 'Longer compile times'],
                'dqix_impact': 'Optimal for high-throughput domain assessments'
            }
        }
        
        for lang, info in paradigms.items():
            if lang in df['language'].values:
                analysis.append(f"### {lang.title()}")
                analysis.append(f"**Paradigm**: {info['type']}")
                analysis.append(f"**Strengths**: {', '.join(info['strengths'])}")
                analysis.append(f"**Weaknesses**: {', '.join(info['weaknesses'])}")
                analysis.append(f"**DQIX Impact**: {info['dqix_impact']}")
                analysis.append("")
        
        # Performance comparison
        if len(df) > 0:
            analysis.append("## Performance Metrics Comparison")
            analysis.append("")
            
            # Startup time comparison
            startup_stats = df.groupby('language')['startup_time'].agg(['mean', 'std']).round(4)
            analysis.append("### Startup Time (Cold Start)")
            analysis.append("| Language | Mean (s) | Std Dev (s) |")
            analysis.append("|----------|----------|-------------|")
            for lang, row in startup_stats.iterrows():
                analysis.append(f"| {lang.title()} | {row['mean']:.4f} | {row['std']:.4f} |")
            analysis.append("")
            
            # Single domain performance
            if 'single_domain_avg_time' in df.columns:
                single_stats = df.groupby('language')['single_domain_avg_time'].agg(['mean', 'std']).round(3)
                analysis.append("### Single Domain Assessment")
                analysis.append("| Language | Mean Time (s) | Std Dev (s) |")
                analysis.append("|----------|---------------|-------------|")
                for lang, row in single_stats.iterrows():
                    analysis.append(f"| {lang.title()} | {row['mean']:.3f} | {row['std']:.3f} |")
                analysis.append("")
            
            # Bulk throughput
            if 'bulk_max_throughput' in df.columns:
                bulk_stats = df.groupby('language')['bulk_max_throughput'].agg(['mean', 'std']).round(2)
                analysis.append("### Bulk Assessment Throughput")
                analysis.append("| Language | Mean (domains/s) | Std Dev |")
                analysis.append("|----------|------------------|---------|")
                for lang, row in bulk_stats.iterrows():
                    analysis.append(f"| {lang.title()} | {row['mean']:.2f} | {row['std']:.2f} |")
                analysis.append("")
        
        # Complexity analysis
        analysis.append("## Code Complexity Analysis")
        analysis.append("")
        analysis.append("Based on implementation patterns observed:")
        analysis.append("")
        analysis.append("### Error Handling Complexity")
        analysis.append("- **Python**: Exception-based, dynamic error discovery")
        analysis.append("- **Go**: Explicit error returns, compile-time checking")
        analysis.append("- **Rust**: Result types, compile-time error handling")
        analysis.append("")
        analysis.append("### Concurrency Model Impact")
        analysis.append("- **Python**: asyncio for I/O concurrency, GIL limitations")
        analysis.append("- **Go**: Goroutines with channels, simple concurrent patterns")
        analysis.append("- **Rust**: Tokio async runtime, ownership-based thread safety")
        analysis.append("")
        analysis.append("### Memory Management")
        analysis.append("- **Python**: Automatic GC, reference counting, higher overhead")
        analysis.append("- **Go**: Automatic GC, optimized for low latency")
        analysis.append("- **Rust**: Manual ownership, zero-cost abstractions")
        
        return '\n'.join(analysis)
    
    def create_performance_charts(self, df: pd.DataFrame, output_dir: str):
        """Create performance comparison charts"""
        if len(df) == 0:
            print("No data available for charts")
            return
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Startup time comparison
        if 'startup_time' in df.columns:
            plt.figure(figsize=(10, 6))
            df.boxplot(column='startup_time', by='language', ax=plt.gca())
            plt.title('Startup Time Comparison by Language')
            plt.ylabel('Time (seconds)')
            plt.xlabel('Language')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/startup_time_comparison.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Single domain performance
        if 'single_domain_avg_time' in df.columns:
            plt.figure(figsize=(10, 6))
            df.boxplot(column='single_domain_avg_time', by='language', ax=plt.gca())
            plt.title('Single Domain Assessment Time by Language')
            plt.ylabel('Time (seconds)')
            plt.xlabel('Language')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/single_domain_performance.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Throughput comparison
        if 'bulk_max_throughput' in df.columns:
            plt.figure(figsize=(10, 6))
            df.boxplot(column='bulk_max_throughput', by='language', ax=plt.gca())
            plt.title('Bulk Assessment Throughput by Language')
            plt.ylabel('Domains per Second')
            plt.xlabel('Language')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/throughput_comparison.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Memory usage comparison
        if 'single_domain_avg_memory' in df.columns:
            plt.figure(figsize=(10, 6))
            df.boxplot(column='single_domain_avg_memory', by='language', ax=plt.gca())
            plt.title('Memory Usage Comparison by Language')
            plt.ylabel('Memory (MB)')
            plt.xlabel('Language')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/memory_usage_comparison.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        print(f"Charts saved to {output_dir}/")
    
    def export_csv_data(self, df: pd.DataFrame, output_file: str):
        """Export performance data to CSV"""
        df.to_csv(output_file, index=False)
        print(f"Data exported to {output_file}")
    
    def run_full_analysis(self, output_dir: str = "benchmarks/reports"):
        """Run complete comparative analysis"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract metrics
        df = self.extract_performance_metrics()
        
        if len(df) == 0:
            print("No benchmark data available for analysis")
            return
        
        print(f"Analyzing {len(df)} benchmark results...")
        
        # Generate analysis report
        analysis = self.generate_paradigm_analysis(df)
        report_file = f"{output_dir}/paradigm_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, 'w') as f:
            f.write(analysis)
        print(f"Paradigm analysis saved to {report_file}")
        
        # Create charts
        charts_dir = f"{output_dir}/charts"
        self.create_performance_charts(df, charts_dir)
        
        # Export raw data
        csv_file = f"{output_dir}/performance_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.export_csv_data(df, csv_file)
        
        # Print summary
        print("\n=== Analysis Summary ===")
        print(f"Languages analyzed: {', '.join(df['language'].unique())}")
        print(f"Total benchmark runs: {len(df)}")
        if 'single_domain_avg_time' in df.columns:
            fastest = df.loc[df['single_domain_avg_time'].idxmin(), 'language']
            print(f"Fastest single domain: {fastest}")
        if 'bulk_max_throughput' in df.columns:
            highest_throughput = df.loc[df['bulk_max_throughput'].idxmax(), 'language']
            print(f"Highest throughput: {highest_throughput}")

def main():
    parser = argparse.ArgumentParser(description="DQIX Language Comparison Analysis")
    parser.add_argument("--input", type=str, default="benchmarks/results",
                       help="Input directory with benchmark results")
    parser.add_argument("--output", type=str, default="benchmarks/reports",
                       help="Output directory for analysis reports")
    parser.add_argument("--format", choices=["full", "charts", "csv", "report"],
                       default="full", help="Analysis format to generate")
    
    args = parser.parse_args()
    
    comparator = LanguageComparator(args.input)
    
    if args.format == "full":
        comparator.run_full_analysis(args.output)
    elif args.format == "charts":
        df = comparator.extract_performance_metrics()
        comparator.create_performance_charts(df, f"{args.output}/charts")
    elif args.format == "csv":
        df = comparator.extract_performance_metrics()
        comparator.export_csv_data(df, f"{args.output}/performance_data.csv")
    elif args.format == "report":
        df = comparator.extract_performance_metrics()
        analysis = comparator.generate_paradigm_analysis(df)
        with open(f"{args.output}/paradigm_analysis.md", 'w') as f:
            f.write(analysis)

if __name__ == "__main__":
    main() 