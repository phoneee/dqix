#!/usr/bin/env python3
"""
Advanced Bulk Domain Assessment - DQIX Enhanced Example

This example demonstrates advanced bulk domain assessment capabilities:
- Loading domains from various file formats
- Comprehensive analysis and visualization
- Detailed reporting and comparison
- Export capabilities

Usage:
    python examples/advanced_bulk_assessment.py
"""

import asyncio
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from dqix.application.use_cases import (
    AssessDomainCommand,
    AssessDomainUseCase,
)
from dqix.domain.entities import AssessmentResult, ProbeConfig
from dqix.domain.services import AssessmentService, DomainValidationService, ScoringService
from dqix.infrastructure.probes import ProbeExecutor
from dqix.infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository


class BulkAssessmentAnalyzer:
    """Advanced bulk assessment analyzer with visualization and reporting."""

    def __init__(self, output_dir: str = "./examples/bulk_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_case = self._create_use_case()

    def _create_use_case(self) -> AssessDomainUseCase:
        """Create assessment use case with dependencies."""
        probe_executor = ProbeExecutor()
        assessment_repo = FileAssessmentRepository(str(self.output_dir / "assessments"))
        cache_repo = InMemoryCacheRepository()

        scoring_service = ScoringService()
        validation_service = DomainValidationService()
        assessment_service = AssessmentService(scoring_service, validation_service)

        return AssessDomainUseCase(
            probe_executor=probe_executor,
            assessment_service=assessment_service,
            validation_service=validation_service,
            assessment_repo=assessment_repo,
            cache_repo=cache_repo
        )

    def load_domains_from_csv(self, csv_file: str) -> list[dict[str, str]]:
        """
        Load domains from CSV file with metadata.

        Expected CSV format:
        domain,category,description,priority
        example.com,tech,Example domain,high
        """
        domains = []
        try:
            with open(csv_file, encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'domain' in row and row['domain'].strip():
                        domains.append({
                            'domain': row['domain'].strip(),
                            'category': row.get('category', 'general'),
                            'description': row.get('description', ''),
                            'priority': row.get('priority', 'medium')
                        })
        except Exception as e:
            print(f"❌ Error loading CSV: {e}")

        return domains

    def load_domains_from_json(self, json_file: str) -> list[dict[str, str]]:
        """Load domains from JSON file."""
        try:
            with open(json_file, encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [
                        {
                            'domain': item if isinstance(item, str) else item.get('domain', ''),
                            'category': item.get('category', 'general') if isinstance(item, dict) else 'general',
                            'description': item.get('description', '') if isinstance(item, dict) else '',
                            'priority': item.get('priority', 'medium') if isinstance(item, dict) else 'medium'
                        }
                        for item in data
                        if (isinstance(item, str) and item.strip()) or
                           (isinstance(item, dict) and item.get('domain', '').strip())
                    ]
                elif isinstance(data, dict) and 'domains' in data:
                    return data['domains']
        except Exception as e:
            print(f"❌ Error loading JSON: {e}")

        return []

    async def assess_domains_with_progress(self, domains: list[dict[str, str]],
                                         timeout: int = 30, max_concurrent: int = 5) -> list[AssessmentResult]:
        """Assess domains with detailed progress tracking."""
        print(f"🔍 Starting assessment of {len(domains)} domains...")

        config = ProbeConfig(
            timeout=timeout,
            cache_enabled=True,
            max_concurrent=max_concurrent
        )

        results = []
        failed_domains = []

        # Process domains in batches for better control
        batch_size = max_concurrent
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            batch_results = await self._assess_batch(batch, config)

            for domain_info, result in zip(batch, batch_results):
                if result:
                    results.append(result)
                    print(f"✅ {domain_info['domain']}: {result.overall_score:.1f}")
                else:
                    failed_domains.append(domain_info['domain'])
                    print(f"❌ {domain_info['domain']}: Failed")

            # Progress update
            completed = min(i + batch_size, len(domains))
            progress = (completed / len(domains)) * 100
            print(f"📊 Progress: {completed}/{len(domains)} ({progress:.1f}%)")

        print("\n🎯 Assessment Complete!")
        print(f"✅ Successful: {len(results)}")
        print(f"❌ Failed: {len(failed_domains)}")

        if failed_domains:
            print(f"Failed domains: {', '.join(failed_domains[:5])}")
            if len(failed_domains) > 5:
                print(f"... and {len(failed_domains) - 5} more")

        return results

    async def _assess_batch(self, batch: list[dict[str, str]], config: ProbeConfig) -> list[AssessmentResult]:
        """Assess a batch of domains concurrently."""
        tasks = []
        for domain_info in batch:
            command = AssessDomainCommand(
                domain_name=domain_info['domain'],
                probe_config=config
            )
            task = self._safe_assess(command)
            tasks.append(task)

        return await asyncio.gather(*tasks)

    async def _safe_assess(self, command: AssessDomainCommand) -> AssessmentResult:
        """Safely assess a domain with error handling."""
        try:
            return await self.use_case.execute(command)
        except Exception as e:
            print(f"⚠️ Error assessing {command.domain_name}: {e}")
            return None

    def analyze_results(self, results: list[AssessmentResult]) -> dict[str, Any]:
        """Perform comprehensive analysis of assessment results."""
        if not results:
            return {}

        analysis = {
            'summary': self._calculate_summary_stats(results),
            'score_distribution': self._analyze_score_distribution(results),
            'probe_analysis': self._analyze_probe_performance(results),
            'compliance_breakdown': self._analyze_compliance_levels(results),
            'top_performers': self._get_top_performers(results),
            'needs_improvement': self._get_domains_needing_improvement(results)
        }

        return analysis

    def _calculate_summary_stats(self, results: list[AssessmentResult]) -> dict[str, Any]:
        """Calculate summary statistics."""
        scores = [r.overall_score for r in results]
        return {
            'total_domains': len(results),
            'average_score': sum(scores) / len(scores),
            'median_score': sorted(scores)[len(scores) // 2],
            'highest_score': max(scores),
            'lowest_score': min(scores),
            'passing_domains': len([s for s in scores if s >= 70]),
            'passing_rate': len([s for s in scores if s >= 70]) / len(scores) * 100
        }

    def _analyze_score_distribution(self, results: list[AssessmentResult]) -> dict[str, int]:
        """Analyze score distribution across ranges."""
        distribution = {
            '90-100 (Excellent)': 0,
            '80-89 (Good)': 0,
            '70-79 (Acceptable)': 0,
            '60-69 (Needs Improvement)': 0,
            'Below 60 (Critical)': 0
        }

        for result in results:
            score = result.overall_score
            if score >= 90:
                distribution['90-100 (Excellent)'] += 1
            elif score >= 80:
                distribution['80-89 (Good)'] += 1
            elif score >= 70:
                distribution['70-79 (Acceptable)'] += 1
            elif score >= 60:
                distribution['60-69 (Needs Improvement)'] += 1
            else:
                distribution['Below 60 (Critical)'] += 1

        return distribution

    def _analyze_probe_performance(self, results: list[AssessmentResult]) -> dict[str, dict[str, float]]:
        """Analyze performance across different probes."""
        probe_stats = defaultdict(list)

        for result in results:
            for probe_result in result.probe_results:
                probe_stats[probe_result.probe_id].append(probe_result.score)

        analysis = {}
        for probe_id, scores in probe_stats.items():
            analysis[probe_id] = {
                'average_score': sum(scores) / len(scores),
                'success_rate': len([s for s in scores if s > 0]) / len(scores) * 100,
                'total_assessments': len(scores)
            }

        return analysis

    def _analyze_compliance_levels(self, results: list[AssessmentResult]) -> dict[str, int]:
        """Analyze compliance level distribution."""
        levels = defaultdict(int)
        for result in results:
            levels[result.compliance_level.value] += 1
        return dict(levels)

    def _get_top_performers(self, results: list[AssessmentResult], count: int = 10) -> list[dict[str, Any]]:
        """Get top performing domains."""
        sorted_results = sorted(results, key=lambda r: r.overall_score, reverse=True)
        return [
            {
                'domain': r.domain.name,
                'score': r.overall_score,
                'compliance_level': r.compliance_level.value
            }
            for r in sorted_results[:count]
        ]

    def _get_domains_needing_improvement(self, results: list[AssessmentResult], count: int = 10) -> list[dict[str, Any]]:
        """Get domains that need the most improvement."""
        sorted_results = sorted(results, key=lambda r: r.overall_score)
        return [
            {
                'domain': r.domain.name,
                'score': r.overall_score,
                'compliance_level': r.compliance_level.value,
                'main_issues': self._identify_main_issues(r)
            }
            for r in sorted_results[:count]
        ]

    def _identify_main_issues(self, result: AssessmentResult) -> list[str]:
        """Identify main issues for a domain."""
        issues = []
        for probe_result in result.probe_results:
            if probe_result.score < 70:
                issues.append(f"{probe_result.probe_id}: {probe_result.score:.1f}")
        return issues[:3]  # Top 3 issues

    def generate_text_report(self, analysis: dict[str, Any], results: list[AssessmentResult]) -> str:
        """Generate comprehensive text report."""
        report = []
        report.append("=" * 80)
        report.append("🔍 DQIX BULK DOMAIN ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        # Summary
        summary = analysis['summary']
        report.append("📊 EXECUTIVE SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Domains Assessed: {summary['total_domains']}")
        report.append(f"Average Score: {summary['average_score']:.2f}/100")
        report.append(f"Passing Rate: {summary['passing_rate']:.1f}% ({summary['passing_domains']}/{summary['total_domains']})")
        report.append(f"Score Range: {summary['lowest_score']:.1f} - {summary['highest_score']:.1f}")
        report.append("")

        # Score Distribution
        report.append("📈 SCORE DISTRIBUTION")
        report.append("-" * 40)
        for range_name, count in analysis['score_distribution'].items():
            percentage = (count / summary['total_domains']) * 100
            report.append(f"{range_name}: {count} domains ({percentage:.1f}%)")
        report.append("")

        # Probe Performance
        report.append("🔬 PROBE PERFORMANCE ANALYSIS")
        report.append("-" * 40)
        for probe_id, stats in analysis['probe_analysis'].items():
            report.append(f"{probe_id}:")
            report.append(f"  Average Score: {stats['average_score']:.2f}")
            report.append(f"  Success Rate: {stats['success_rate']:.1f}%")
        report.append("")

        # Top Performers
        report.append("🏆 TOP PERFORMING DOMAINS")
        report.append("-" * 40)
        for i, domain in enumerate(analysis['top_performers'], 1):
            report.append(f"{i:2d}. {domain['domain']:30} {domain['score']:6.1f} ({domain['compliance_level']})")
        report.append("")

        # Needs Improvement
        report.append("⚠️ DOMAINS NEEDING IMPROVEMENT")
        report.append("-" * 40)
        for i, domain in enumerate(analysis['needs_improvement'], 1):
            report.append(f"{i:2d}. {domain['domain']:30} {domain['score']:6.1f}")
            if domain['main_issues']:
                report.append(f"    Issues: {', '.join(domain['main_issues'])}")
        report.append("")

        report.append("=" * 80)
        report.append("End of Report")
        report.append("=" * 80)

        return "\n".join(report)

    def export_results(self, results: list[AssessmentResult], analysis: dict[str, Any]) -> None:
        """Export results in multiple formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON Export
        json_file = self.output_dir / f"bulk_assessment_{timestamp}.json"
        self._export_json(results, analysis, json_file)

        # CSV Export
        csv_file = self.output_dir / f"bulk_assessment_{timestamp}.csv"
        self._export_csv(results, csv_file)

        # Text Report
        report_file = self.output_dir / f"bulk_report_{timestamp}.txt"
        report_text = self.generate_text_report(analysis, results)
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)

        print("\n📁 Results exported:")
        print(f"  JSON: {json_file}")
        print(f"  CSV:  {csv_file}")
        print(f"  Report: {report_file}")

    def _export_json(self, results: list[AssessmentResult], analysis: dict[str, Any], file_path: Path) -> None:
        """Export results as JSON."""
        export_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_domains': len(results),
                'dqix_version': '1.0.0'
            },
            'analysis': analysis,
            'results': [
                {
                    'domain': r.domain.name,
                    'timestamp': r.timestamp.isoformat() if hasattr(r.timestamp, 'isoformat') else str(r.timestamp),
                    'overall_score': r.overall_score,
                    'compliance_level': r.compliance_level.value,
                    'probe_results': [
                        {
                            'probe_id': pr.probe_id,
                            'score': pr.score,
                            'is_successful': pr.is_successful,
                            'error': pr.error
                        }
                        for pr in r.probe_results
                    ]
                }
                for r in results
            ]
        }

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

    def _export_csv(self, results: list[AssessmentResult], file_path: Path) -> None:
        """Export results as CSV."""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            headers = ['Domain', 'Overall_Score', 'Compliance_Level', 'Timestamp']
            if results:
                probe_headers = [pr.probe_id for pr in results[0].probe_results]
                headers.extend(probe_headers)
            writer.writerow(headers)

            # Data
            for result in results:
                row = [
                    result.domain.name,
                    result.overall_score,
                    result.compliance_level.value,
                    result.timestamp.isoformat() if hasattr(result.timestamp, 'isoformat') else str(result.timestamp)
                ]

                # Add probe scores
                for probe_result in result.probe_results:
                    row.append(probe_result.score)

                writer.writerow(row)

    def print_visual_summary(self, analysis: dict[str, Any]) -> None:
        """Print visual summary of results."""
        print("\n" + "=" * 80)
        print("🎯 VISUAL SUMMARY")
        print("=" * 80)

        # Score distribution chart
        print("\n📊 Score Distribution:")
        for range_name, count in analysis['score_distribution'].items():
            bar_length = min(50, count * 2)  # Scale for readability
            bar = "█" * bar_length
            print(f"{range_name:25} │{bar} {count}")

        # Probe performance
        print("\n🔬 Probe Performance (Average Scores):")
        for probe_id, stats in analysis['probe_analysis'].items():
            score = stats['average_score']
            bar_length = int(score / 2)  # Scale to 50 chars max
            bar = "█" * bar_length + "░" * (50 - bar_length)
            color_indicator = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
            print(f"{probe_id:20} │{bar}│ {score:5.1f} {color_indicator}")

        print("=" * 80)


async def demonstrate_basic_bulk_assessment():
    """Demonstrate basic bulk assessment functionality."""
    print("🚀 Basic Bulk Assessment Demo")
    print("-" * 50)

    analyzer = BulkAssessmentAnalyzer()

    # Sample domains for demonstration
    sample_domains = [
        {'domain': 'example.com', 'category': 'demo', 'priority': 'high'},
        {'domain': 'google.com', 'category': 'tech', 'priority': 'high'},
        {'domain': 'github.com', 'category': 'tech', 'priority': 'medium'},
        {'domain': 'stackoverflow.com', 'category': 'tech', 'priority': 'medium'},
    ]

    # Assess domains
    results = await analyzer.assess_domains_with_progress(sample_domains, timeout=20, max_concurrent=2)

    if results:
        # Analyze results
        analysis = analyzer.analyze_results(results)

        # Display visual summary
        analyzer.print_visual_summary(analysis)

        # Export results
        analyzer.export_results(results, analysis)
    else:
        print("❌ No successful assessments to analyze")


async def demonstrate_csv_bulk_assessment():
    """Demonstrate CSV-based bulk assessment."""
    print("\n🚀 CSV Bulk Assessment Demo")
    print("-" * 50)

    # Create sample CSV file
    csv_file = "examples/sample_domains.csv"
    sample_csv_data = """domain,category,description,priority
example.com,demo,Example domain for testing,high
httpbin.org,api,HTTP testing service,medium
jsonplaceholder.typicode.com,api,Fake JSON API,low
httpstat.us,testing,HTTP status code testing,low"""

    # Write sample CSV
    with open(csv_file, 'w') as f:
        f.write(sample_csv_data)

    analyzer = BulkAssessmentAnalyzer()

    # Load domains from CSV
    domains = analyzer.load_domains_from_csv(csv_file)
    print(f"📋 Loaded {len(domains)} domains from CSV")

    # Assess domains
    results = await analyzer.assess_domains_with_progress(domains, timeout=15, max_concurrent=3)

    if results:
        # Generate and display analysis
        analysis = analyzer.analyze_results(results)

        # Print detailed report
        report_text = analyzer.generate_text_report(analysis, results)
        print("\n" + report_text)

        # Export results
        analyzer.export_results(results, analysis)

    # Cleanup
    Path(csv_file).unlink(missing_ok=True)


async def demonstrate_comparison_analysis():
    """Demonstrate domain comparison analysis."""
    print("\n🚀 Domain Comparison Analysis Demo")
    print("-" * 50)

    analyzer = BulkAssessmentAnalyzer()

    # Compare different types of domains
    comparison_domains = [
        {'domain': 'google.com', 'category': 'tech_giant', 'priority': 'high'},
        {'domain': 'example.com', 'category': 'demo', 'priority': 'medium'},
        {'domain': 'httpbin.org', 'category': 'api_service', 'priority': 'medium'},
    ]

    results = await analyzer.assess_domains_with_progress(comparison_domains, timeout=20)

    if len(results) >= 2:
        print("\n⚖️ DOMAIN COMPARISON ANALYSIS")
        print("=" * 60)

        # Sort by score for comparison
        sorted_results = sorted(results, key=lambda r: r.overall_score, reverse=True)

        for i, result in enumerate(sorted_results, 1):
            print(f"\n{i}. {result.domain.name}")
            print(f"   Overall Score: {result.overall_score:.1f}/100")
            print(f"   Compliance: {result.compliance_level.value}")
            print("   Probe Breakdown:")

            for probe_result in result.probe_results:
                status = "✅" if probe_result.is_successful else "❌"
                print(f"     {status} {probe_result.probe_id}: {probe_result.score:.1f}")

        # Comparative analysis
        best = sorted_results[0]
        worst = sorted_results[-1]

        print(f"\n🏆 Best Performer: {best.domain.name} ({best.overall_score:.1f})")
        print(f"📉 Needs Most Improvement: {worst.domain.name} ({worst.overall_score:.1f})")
        print(f"📊 Score Gap: {best.overall_score - worst.overall_score:.1f} points")


async def main():
    """Main demonstration function."""
    print("🔍 DQIX Advanced Bulk Assessment Examples")
    print("=" * 80)

    # Run different demonstrations
    await demonstrate_basic_bulk_assessment()
    await demonstrate_csv_bulk_assessment()
    await demonstrate_comparison_analysis()

    print("\n✨ All demonstrations completed!")
    print("\nTo use these features:")
    print("1. Create a BulkAssessmentAnalyzer instance")
    print("2. Load domains from CSV/JSON files")
    print("3. Run assess_domains_with_progress()")
    print("4. Analyze results with analyze_results()")
    print("5. Export with export_results()")


if __name__ == "__main__":
    asyncio.run(main())
