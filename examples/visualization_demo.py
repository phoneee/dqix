#!/usr/bin/env python3
"""
Domain Assessment Visualization Demo - DQIX Enhanced Example

This example demonstrates how to create visual representations of domain assessment data:
- ASCII charts and graphs
- Progress bars and indicators
- Comparison visualizations
- Dashboard-style output

Usage:
    python examples/visualization_demo.py
"""

import asyncio
from collections import defaultdict
from datetime import datetime

from dqix.application.use_cases import AssessDomainCommand, AssessDomainUseCase
from dqix.domain.entities import AssessmentResult, ProbeConfig
from dqix.domain.services import AssessmentService, DomainValidationService, ScoringService
from dqix.infrastructure.probes import ProbeExecutor
from dqix.infrastructure.repositories import FileAssessmentRepository, InMemoryCacheRepository


class DomainAssessmentVisualizer:
    """Create visual representations of domain assessment data."""

    def __init__(self):
        self.use_case = self._create_use_case()

    def _create_use_case(self) -> AssessDomainUseCase:
        """Create assessment use case with dependencies."""
        probe_executor = ProbeExecutor()
        assessment_repo = FileAssessmentRepository("./examples/visualizations")
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

    def create_score_bar_chart(self, results: list[AssessmentResult], width: int = 60) -> str:
        """Create horizontal bar chart of domain scores."""
        if not results:
            return "No data to visualize"

        chart_lines = []
        chart_lines.append("📊 DOMAIN SCORES COMPARISON")
        chart_lines.append("=" * (width + 20))

        # Sort by score for better visualization
        sorted_results = sorted(results, key=lambda r: r.overall_score, reverse=True)

        max(r.overall_score for r in sorted_results)
        max_domain_len = max(len(r.domain.name) for r in sorted_results)

        for result in sorted_results:
            # Calculate bar length proportional to score
            bar_length = int((result.overall_score / 100) * width)
            bar = "█" * bar_length + "░" * (width - bar_length)

            # Color coding
            if result.overall_score >= 90:
                color_indicator = "🟢"
            elif result.overall_score >= 80:
                color_indicator = "🟡"
            elif result.overall_score >= 70:
                color_indicator = "🟠"
            else:
                color_indicator = "🔴"

            # Format line
            domain_padded = result.domain.name.ljust(max_domain_len)
            score_str = f"{result.overall_score:5.1f}"

            chart_lines.append(f"{domain_padded} │{bar}│ {score_str} {color_indicator}")

        chart_lines.append("=" * (width + 20))
        chart_lines.append(f"Scale: 0 {'─' * (width//2)} 50 {'─' * (width//2)} 100")

        return "\n".join(chart_lines)

    def create_probe_performance_matrix(self, results: list[AssessmentResult]) -> str:
        """Create a matrix showing probe performance across domains."""
        if not results:
            return "No data to visualize"

        # Collect all probe IDs
        all_probes = set()
        for result in results:
            for probe_result in result.probe_results:
                all_probes.add(probe_result.probe_id)

        probe_list = sorted(all_probes)

        matrix_lines = []
        matrix_lines.append("🔬 PROBE PERFORMANCE MATRIX")
        matrix_lines.append("=" * 80)

        # Header
        header = "Domain".ljust(20)
        for probe in probe_list:
            header += f"{probe[:8]:>10}"
        header += "  Overall"
        matrix_lines.append(header)
        matrix_lines.append("-" * len(header))

        # Data rows
        for result in results:
            row = result.domain.name[:19].ljust(20)

            # Create probe score lookup
            probe_scores = {}
            for probe_result in result.probe_results:
                probe_scores[probe_result.probe_id] = probe_result.score

            # Add probe scores
            for probe in probe_list:
                score = probe_scores.get(probe, 0)
                if score >= 90:
                    indicator = "🟢"
                elif score >= 80:
                    indicator = "🟡"
                elif score >= 70:
                    indicator = "🟠"
                elif score > 0:
                    indicator = "🔴"
                else:
                    indicator = "⚫"

                row += f"{score:4.0f}{indicator:>6}"

            # Overall score
            overall_score = result.overall_score
            if overall_score >= 90:
                overall_indicator = "🟢"
            elif overall_score >= 80:
                overall_indicator = "🟡"
            elif overall_score >= 70:
                overall_indicator = "🟠"
            else:
                overall_indicator = "🔴"

            row += f"  {overall_score:5.1f}{overall_indicator}"
            matrix_lines.append(row)

        matrix_lines.append("-" * len(header))
        matrix_lines.append("Legend: 🟢 90+ 🟡 80-89 🟠 70-79 🔴 <70 ⚫ N/A")

        return "\n".join(matrix_lines)

    def create_score_distribution_histogram(self, results: list[AssessmentResult], bins: int = 10) -> str:
        """Create histogram of score distribution."""
        if not results:
            return "No data to visualize"

        scores = [r.overall_score for r in results]
        min_score = min(scores)
        max_score = max(scores)

        # Create bins
        bin_width = (max_score - min_score) / bins
        bin_counts = [0] * bins
        bin_labels = []

        for i in range(bins):
            bin_start = min_score + i * bin_width
            bin_end = min_score + (i + 1) * bin_width
            bin_labels.append(f"{bin_start:.0f}-{bin_end:.0f}")

            # Count scores in this bin
            for score in scores:
                if bin_start <= score < bin_end or (i == bins - 1 and score == bin_end):
                    bin_counts[i] += 1

        # Create histogram
        hist_lines = []
        hist_lines.append("📈 SCORE DISTRIBUTION HISTOGRAM")
        hist_lines.append("=" * 60)

        max_count = max(bin_counts) if bin_counts else 1
        max_bar_length = 40

        for i, (label, count) in enumerate(zip(bin_labels, bin_counts)):
            bar_length = int((count / max_count) * max_bar_length) if max_count > 0 else 0
            bar = "█" * bar_length

            hist_lines.append(f"{label:>8} │{bar:<40}│ {count:2d}")

        hist_lines.append("=" * 60)
        hist_lines.append(f"Total domains: {len(results)}")
        hist_lines.append(f"Average score: {sum(scores) / len(scores):.1f}")

        return "\n".join(hist_lines)

    def create_compliance_pie_chart(self, results: list[AssessmentResult]) -> str:
        """Create ASCII pie chart of compliance levels."""
        if not results:
            return "No data to visualize"

        # Count compliance levels
        compliance_counts = defaultdict(int)
        for result in results:
            compliance_counts[result.compliance_level.value] += 1

        total = len(results)

        pie_lines = []
        pie_lines.append("🥧 COMPLIANCE LEVEL DISTRIBUTION")
        pie_lines.append("=" * 50)

        # Create simple pie representation
        for level, count in sorted(compliance_counts.items()):
            percentage = (count / total) * 100
            bar_length = int(percentage / 2)  # Scale to 50 chars max
            bar = "█" * bar_length

            pie_lines.append(f"{level:15} │{bar:<25}│ {count:2d} ({percentage:4.1f}%)")

        pie_lines.append("=" * 50)
        pie_lines.append(f"Total: {total} domains")

        return "\n".join(pie_lines)

    def create_probe_radar_chart(self, result: AssessmentResult, size: int = 15) -> str:
        """Create ASCII radar chart for a single domain's probe scores."""
        if not result.probe_results:
            return "No probe data to visualize"

        radar_lines = []
        radar_lines.append(f"🎯 PROBE RADAR CHART - {result.domain.name}")
        radar_lines.append("=" * 60)

        # Simple radar representation using bars
        for probe_result in result.probe_results:
            score = probe_result.score
            bar_length = int((score / 100) * size)
            bar = "█" * bar_length + "░" * (size - bar_length)

            # Status indicator
            status = "✅" if probe_result.is_successful else "❌"

            radar_lines.append(f"{probe_result.probe_id:20} │{bar}│ {score:5.1f} {status}")

        radar_lines.append("=" * 60)
        radar_lines.append(f"Overall Score: {result.overall_score:.1f}/100")

        return "\n".join(radar_lines)

    def create_comparison_dashboard(self, results: list[AssessmentResult]) -> str:
        """Create comprehensive dashboard comparing multiple domains."""
        if not results:
            return "No data to create dashboard"

        dashboard_lines = []
        dashboard_lines.append("🖥️  DOMAIN ASSESSMENT DASHBOARD")
        dashboard_lines.append("=" * 100)
        dashboard_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        dashboard_lines.append(f"Domains Assessed: {len(results)}")
        dashboard_lines.append("")

        # Summary statistics
        scores = [r.overall_score for r in results]
        avg_score = sum(scores) / len(scores)

        dashboard_lines.append("📊 SUMMARY STATISTICS")
        dashboard_lines.append("-" * 50)
        dashboard_lines.append(f"Average Score:    {avg_score:6.2f}")
        dashboard_lines.append(f"Highest Score:    {max(scores):6.2f}")
        dashboard_lines.append(f"Lowest Score:     {min(scores):6.2f}")
        dashboard_lines.append(f"Score Range:      {max(scores) - min(scores):6.2f}")
        dashboard_lines.append("")

        # Top 3 and Bottom 3
        sorted_results = sorted(results, key=lambda r: r.overall_score, reverse=True)

        dashboard_lines.append("🏆 TOP PERFORMERS")
        dashboard_lines.append("-" * 30)
        for i, result in enumerate(sorted_results[:3], 1):
            dashboard_lines.append(f"{i}. {result.domain.name:20} {result.overall_score:6.1f}")

        dashboard_lines.append("")
        dashboard_lines.append("⚠️  NEEDS ATTENTION")
        dashboard_lines.append("-" * 30)
        for i, result in enumerate(sorted_results[-3:], 1):
            dashboard_lines.append(f"{i}. {result.domain.name:20} {result.overall_score:6.1f}")

        dashboard_lines.append("")

        # Mini bar chart
        dashboard_lines.append("📈 QUICK COMPARISON")
        dashboard_lines.append("-" * 40)
        for result in sorted_results:
            bar_length = int((result.overall_score / 100) * 20)
            bar = "█" * bar_length + "░" * (20 - bar_length)

            dashboard_lines.append(f"{result.domain.name[:15]:15} │{bar}│ {result.overall_score:5.1f}")

        dashboard_lines.append("=" * 100)

        return "\n".join(dashboard_lines)

    def create_trend_analysis(self, results: list[AssessmentResult]) -> str:
        """Create trend analysis visualization."""
        if len(results) < 2:
            return "Need at least 2 domains for trend analysis"

        trend_lines = []
        trend_lines.append("📈 TREND ANALYSIS")
        trend_lines.append("=" * 70)

        # Sort by domain name for consistent ordering
        sorted_results = sorted(results, key=lambda r: r.domain.name)

        # Create trend line
        trend_lines.append("Score Trend:")
        trend_line = ""
        prev_score = None

        for _i, result in enumerate(sorted_results):
            score = result.overall_score

            if prev_score is not None:
                if score > prev_score + 5:
                    trend_line += "↗️ "
                elif score < prev_score - 5:
                    trend_line += "↘️ "
                else:
                    trend_line += "→ "

            trend_line += f"{result.domain.name[:10]:10}({score:.0f}) "
            prev_score = score

        trend_lines.append(trend_line)
        trend_lines.append("")

        # Probe trend analysis
        if results:
            probe_trends = defaultdict(list)
            for result in sorted_results:
                for probe_result in result.probe_results:
                    probe_trends[probe_result.probe_id].append(probe_result.score)

            trend_lines.append("Probe Performance Trends:")
            for probe_id, scores in probe_trends.items():
                if len(scores) >= 2:
                    trend_direction = "↗️" if scores[-1] > scores[0] else "↘️" if scores[-1] < scores[0] else "→"
                    avg_score = sum(scores) / len(scores)
                    trend_lines.append(f"{probe_id:20} {trend_direction} Avg: {avg_score:5.1f}")

        trend_lines.append("=" * 70)

        return "\n".join(trend_lines)


async def demonstrate_single_domain_visualization():
    """Demonstrate visualization for a single domain."""
    print("🎯 Single Domain Visualization Demo")
    print("-" * 50)

    visualizer = DomainAssessmentVisualizer()

    # Assess a domain
    config = ProbeConfig(timeout=20, cache_enabled=True)
    command = AssessDomainCommand(domain_name="example.com", probe_config=config)

    try:
        result = await visualizer.use_case.execute(command)

        # Create radar chart
        radar_chart = visualizer.create_probe_radar_chart(result)
        print(radar_chart)

    except Exception as e:
        print(f"❌ Error assessing domain: {e}")


async def demonstrate_multi_domain_visualization():
    """Demonstrate visualization for multiple domains."""
    print("\n📊 Multi-Domain Visualization Demo")
    print("-" * 50)

    visualizer = DomainAssessmentVisualizer()

    # Assess multiple domains
    test_domains = ["example.com", "httpbin.org", "jsonplaceholder.typicode.com"]
    results = []

    config = ProbeConfig(timeout=15, cache_enabled=True)

    for domain in test_domains:
        try:
            command = AssessDomainCommand(domain_name=domain, probe_config=config)
            result = await visualizer.use_case.execute(command)
            results.append(result)
            print(f"✅ Assessed {domain}: {result.overall_score:.1f}")
        except Exception as e:
            print(f"❌ Failed to assess {domain}: {e}")

    if len(results) >= 2:
        print("\n" + "="*80)

        # Bar chart
        bar_chart = visualizer.create_score_bar_chart(results)
        print(bar_chart)

        print("\n")

        # Performance matrix
        matrix = visualizer.create_probe_performance_matrix(results)
        print(matrix)

        print("\n")

        # Score distribution
        histogram = visualizer.create_score_distribution_histogram(results)
        print(histogram)

        print("\n")

        # Compliance pie chart
        pie_chart = visualizer.create_compliance_pie_chart(results)
        print(pie_chart)

        print("\n")

        # Dashboard
        dashboard = visualizer.create_comparison_dashboard(results)
        print(dashboard)

        print("\n")

        # Trend analysis
        trend = visualizer.create_trend_analysis(results)
        print(trend)


async def demonstrate_interactive_visualization():
    """Demonstrate interactive-style visualization."""
    print("\n🖥️  Interactive Dashboard Demo")
    print("-" * 50)

    visualizer = DomainAssessmentVisualizer()

    # Simulate real-time assessment
    domains = ["google.com", "github.com", "stackoverflow.com"]
    results = []

    print("🔍 Real-time Assessment Simulation:")
    print("=" * 40)

    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Assessing {domain}...")

        # Progress bar simulation
        for progress in range(0, 101, 20):
            bar_length = progress // 5
            bar = "█" * bar_length + "░" * (20 - bar_length)
            print(f"\r  Progress: │{bar}│ {progress:3d}%", end="", flush=True)
            await asyncio.sleep(0.1)  # Simulate work

        try:
            config = ProbeConfig(timeout=10, cache_enabled=True)
            command = AssessDomainCommand(domain_name=domain, probe_config=config)
            result = await visualizer.use_case.execute(command)
            results.append(result)

            print(f"\n  ✅ Complete: {result.overall_score:.1f}/100")

            # Show mini dashboard after each assessment
            if len(results) > 1:
                print("\n  📊 Current Standings:")
                sorted_current = sorted(results, key=lambda r: r.overall_score, reverse=True)
                for j, r in enumerate(sorted_current, 1):
                    print(f"    {j}. {r.domain.name:20} {r.overall_score:6.1f}")

        except Exception as e:
            print(f"\n  ❌ Failed: {e}")

    # Final comprehensive dashboard
    if results:
        print("\n" + "="*80)
        print("🎯 FINAL ASSESSMENT DASHBOARD")
        print("="*80)

        dashboard = visualizer.create_comparison_dashboard(results)
        print(dashboard)


async def main():
    """Main demonstration function."""
    print("🎨 DQIX Domain Assessment Visualization Examples")
    print("=" * 80)

    # Run different visualization demonstrations
    await demonstrate_single_domain_visualization()
    await demonstrate_multi_domain_visualization()
    await demonstrate_interactive_visualization()

    print("\n✨ All visualization demonstrations completed!")
    print("\nVisualization Features Demonstrated:")
    print("• 📊 Horizontal bar charts for score comparison")
    print("• 🔬 Performance matrix showing probe results")
    print("• 📈 Score distribution histograms")
    print("• 🥧 Compliance level pie charts")
    print("• 🎯 Radar charts for individual domains")
    print("• 🖥️  Comprehensive dashboards")
    print("• 📈 Trend analysis visualizations")
    print("• 🔄 Real-time progress indicators")


if __name__ == "__main__":
    asyncio.run(main())
