import os
import ast
import sys
import json
import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from statistics import mean, median
from collections import defaultdict
import webbrowser
from datetime import datetime

class CodeComplexityAnalyzer:
    """A class to analyze Python code complexity and development metrics."""
    
    def __init__(self, hourly_rate=50):
        self.hourly_rate = hourly_rate
        self.results = []
    
    def analyze_python_file(self, filepath):
        """Analyze a single Python file for various metrics."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            code = ''.join(lines)
            tree = ast.parse(code)
        except Exception as e:
            return None

        # Basic metrics
        total_lines = len(lines)
        blank_lines = sum(1 for line in lines if not line.strip())
        comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
        code_lines = total_lines - blank_lines - comment_lines
        
        # Function and class definitions
        func_defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        class_defs = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        
        # Calculate function lengths
        func_lengths = []
        for func in func_defs:
            start = func.lineno
            end = max([n.lineno for n in ast.walk(func) if hasattr(n, 'lineno')], default=start)
            func_lengths.append(end - start + 1)

        avg_func_len = mean(func_lengths) if func_lengths else 0
        median_func_len = median(func_lengths) if func_lengths else 0
        comment_percent = comment_lines / total_lines if total_lines else 0
        
        # Complexity metrics
        complexity = self._calculate_cyclomatic_complexity(tree)
        nesting_depth = self._calculate_max_nesting(tree)
        imports = len([node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))])
        
        # Calculate effort score with more factors
        effort_score = min(10, (
            (avg_func_len * 0.2) +
            (complexity * 0.3) +
            (nesting_depth * 0.15) +
            (1.5 if comment_percent < 0.1 else 0) +
            (len(func_defs) * 0.015) +
            (imports * 0.05)
        ))

        # Create result dictionary
        result = {
            'file': filepath,
            'lines': total_lines,
            'blank_lines': blank_lines,
            'code_lines': code_lines,
            'comments': comment_lines,
            'functions': len(func_defs),
            'classes': len(class_defs),
            'avg_func_len': round(avg_func_len, 1),
            'median_func_len': round(median_func_len, 1),
            'comment_percent': round(comment_percent * 100, 2),
            'complexity': round(complexity, 2),
            'max_nesting': nesting_depth,
            'imports': imports,
            'effort_score': round(effort_score, 2)
        }
        
        # Calculate estimated development time and cost
        hours = (effort_score * 0.6 + 0.8) * (total_lines / 100)
        result['estimated_hours'] = round(hours, 2)
        result['estimated_cost'] = round(hours * self.hourly_rate, 2)
        
        return result
    
    def _calculate_cyclomatic_complexity(self, tree):
        """Calculate the cyclomatic complexity of the code."""
        # Start with 1 (for the main program entry point)
        complexity = 1
        
        # Count decision points (if, while, for, and, or, etc.)
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
                complexity += len(node.values) - 1
        
        return complexity
    
    def _calculate_max_nesting(self, tree):
        """Calculate the maximum nesting depth in the code."""
        max_depth = 0
        
        def _get_nesting_depth(node, current_depth=0):
            nonlocal max_depth
            max_depth = max(max_depth, current_depth)
            
            # Recursive traversal for nested structures
            if isinstance(node, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                for child_node in ast.iter_child_nodes(node):
                    _get_nesting_depth(child_node, current_depth + 1)
            else:
                for child_node in ast.iter_child_nodes(node):
                    _get_nesting_depth(child_node, current_depth)
        
        _get_nesting_depth(tree)
        return max_depth
    
    def analyze_directory(self, directory, progress_callback=None):
        """Analyze all Python files in a directory recursively."""
        self.results = []
        total_files = 0
        
        # First count total Python files
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    total_files += 1
        
        current_file = 0
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    result = self.analyze_python_file(filepath)
                    current_file += 1
                    if result:
                        self.results.append(result)
                    if progress_callback:
                        progress_callback(current_file, total_files, filepath)
        
        return self.results
    
    def get_summary_data(self):
        """Generate a summary of the analysis results."""
        if not self.results:
            return None
        
        # Calculate overall project metrics
        total_files = len(self.results)
        total_lines = sum(r['lines'] for r in self.results)
        total_code_lines = sum(r['code_lines'] for r in self.results)
        total_funcs = sum(r['functions'] for r in self.results)
        total_classes = sum(r['classes'] for r in self.results)
        avg_func_len = round(mean(r['avg_func_len'] for r in self.results), 2)
        avg_comment_pct = round(mean(r['comment_percent'] for r in self.results), 2)
        avg_effort_score = round(mean(r['effort_score'] for r in self.results), 2)
        avg_complexity = round(mean(r['complexity'] for r in self.results), 2)
        
        # Calculate highest complexity files
        sorted_by_complexity = sorted(self.results, key=lambda x: x['complexity'], reverse=True)
        most_complex_files = sorted_by_complexity[:3]
        
        # Calculate highest effort files
        sorted_by_effort = sorted(self.results, key=lambda x: x['effort_score'], reverse=True)
        highest_effort_files = sorted_by_effort[:3]
        
        # Calculate development estimates
        total_hours = sum(r['estimated_hours'] for r in self.results)
        total_cost = sum(r['estimated_cost'] for r in self.results)
        
        # Group files by directory
        dir_stats = defaultdict(lambda: {'files': 0, 'lines': 0, 'effort': 0})
        for r in self.results:
            dir_name = os.path.dirname(r['file'])
            dir_stats[dir_name]['files'] += 1
            dir_stats[dir_name]['lines'] += r['lines']
            dir_stats[dir_name]['effort'] += r['effort_score']
        
        # Create final summary data
        summary = {
            'total_files': total_files,
            'total_lines': total_lines,
            'total_code_lines': total_code_lines,
            'total_funcs': total_funcs,
            'total_classes': total_classes,
            'avg_func_len': avg_func_len,
            'avg_comment_pct': avg_comment_pct,
            'avg_complexity': avg_complexity,
            'avg_effort_score': avg_effort_score,
            'most_complex_files': most_complex_files,
            'highest_effort_files': highest_effort_files,
            'dir_stats': dict(dir_stats),
            'total_hours': round(total_hours, 1),
            'total_cost': round(total_cost, 2)
        }
        
        return summary
    
    def export_to_json(self, filepath):
        """Export results to a JSON file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        return filepath
    
    def export_to_csv(self, filepath):
        """Export results to a CSV file."""
        if not self.results:
            return None
            
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            writer.writerows(self.results)
        return filepath
    
    def export_to_html(self, filepath):
        """Export results to an HTML report."""
        if not self.results:
            return None
            
        # Simple HTML template with a basic chart using inline JavaScript
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Python Code Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                h1, h2 { color: #333; }
                .chart-container { width: 800px; height: 400px; margin: 20px 0; }
                .metric-card { 
                    display: inline-block; width: 200px; margin: 10px; padding: 15px; 
                    border-radius: 5px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    text-align: center; background-color: #f8f8f8;
                }
                .metric-card h3 { margin: 0; color: #555; }
                .metric-card p { font-size: 24px; font-weight: bold; margin: 10px 0; }
                .summary-section {
                    margin: 20px 0;
                    padding: 15px;
                    background-color: #f8f8f8;
                    border-radius: 5px;
                }
                .footer {
                    margin-top: 40px;
                    text-align: center;
                    font-size: 12px;
                    color: #777;
                }
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <h1>Python Code Analysis Report</h1>
            <p>Generated on: ${timestamp}</p>
            
            <div class="metrics-container">
                <div class="metric-card">
                    <h3>Files</h3>
                    <p>${total_files}</p>
                </div>
                <div class="metric-card">
                    <h3>Lines</h3>
                    <p>${total_lines}</p>
                </div>
                <div class="metric-card">
                    <h3>Functions</h3>
                    <p>${total_functions}</p>
                </div>
                <div class="metric-card">
                    <h3>Classes</h3>
                    <p>${total_classes}</p>
                </div>
                <div class="metric-card">
                    <h3>Est. Hours</h3>
                    <p>${total_hours}</p>
                </div>
                <div class="metric-card">
                    <h3>Est. Cost</h3>
                    <p>$${total_cost}</p>
                </div>
            </div>
            
            <div class="summary-section">
                <h2>Project Overview</h2>
                <p>Average Function Length: ${avg_func_len} lines</p>
                <p>Average Comment Percentage: ${avg_comment_pct}%</p>
                <p>Average Complexity: ${avg_complexity}</p>
                <p>Average Effort Score: ${avg_effort_score}/10</p>
            </div>
            
            <h2>Effort Score by File</h2>
            <div class="chart-container">
                <canvas id="effortChart"></canvas>
            </div>
            
            <h2>Complexity by File</h2>
            <div class="chart-container">
                <canvas id="complexityChart"></canvas>
            </div>
            
            <h2>Lines of Code by Directory</h2>
            <div class="chart-container">
                <canvas id="directoryChart"></canvas>
            </div>
            
            <h2>Most Complex Files</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Complexity</th>
                    <th>Max Nesting</th>
                    <th>Lines</th>
                    <th>Functions</th>
                </tr>
                ${complex_files_rows}
            </table>
            
            <h2>Files Details</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Lines</th>
                    <th>Code Lines</th>
                    <th>Comments</th>
                    <th>Functions</th>
                    <th>Classes</th>
                    <th>Complexity</th>
                    <th>Effort Score</th>
                    <th>Est. Hours</th>
                    <th>Est. Cost</th>
                </tr>
                ${table_rows}
            </table>
            
            <div class="footer">
                <p>Generated by Python Code Analyzer</p>
            </div>
            
            <script>
                // Effort Score Chart
                const effortCtx = document.getElementById('effortChart').getContext('2d');
                new Chart(effortCtx, {
                    type: 'bar',
                    data: {
                        labels: ${file_labels},
                        datasets: [{
                            label: 'Effort Score (0-10)',
                            data: ${effort_scores},
                            backgroundColor: 'rgba(54, 162, 235, 0.5)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 10
                            }
                        }
                    }
                });
                
                // Complexity Chart
                const complexityCtx = document.getElementById('complexityChart').getContext('2d');
                new Chart(complexityCtx, {
                    type: 'bar',
                    data: {
                        labels: ${file_labels},
                        datasets: [{
                            label: 'Complexity',
                            data: ${complexity_scores},
                            backgroundColor: 'rgba(255, 99, 132, 0.5)',
                            borderColor: 'rgba(255, 99, 132, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
                
                // Directory Chart
                const dirCtx = document.getElementById('directoryChart').getContext('2d');
                new Chart(dirCtx, {
                    type: 'pie',
                    data: {
                        labels: ${dir_labels},
                        datasets: [{
                            label: 'Lines of Code',
                            data: ${dir_lines},
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.5)',
                                'rgba(54, 162, 235, 0.5)',
                                'rgba(255, 206, 86, 0.5)',
                                'rgba(75, 192, 192, 0.5)',
                                'rgba(153, 102, 255, 0.5)',
                                'rgba(255, 159, 64, 0.5)',
                                'rgba(199, 199, 199, 0.5)',
                                'rgba(83, 102, 255, 0.5)',
                                'rgba(40, 159, 64, 0.5)',
                                'rgba(210, 199, 199, 0.5)'
                            ],
                            borderColor: [
                                'rgba(255, 99, 132, 1)',
                                'rgba(54, 162, 235, 1)',
                                'rgba(255, 206, 86, 1)',
                                'rgba(75, 192, 192, 1)',
                                'rgba(153, 102, 255, 1)',
                                'rgba(255, 159, 64, 1)',
                                'rgba(199, 199, 199, 1)',
                                'rgba(83, 102, 255, 1)',
                                'rgba(40, 159, 64, 1)',
                                'rgba(210, 199, 199, 1)'
                            ],
                            borderWidth: 1
                        }]
                    }
                });
            </script>
        </body>
        </html>
        """
        
        # Generate table rows
        table_rows = ""
        for r in sorted(self.results, key=lambda x: x['file']):
            table_rows += f"""
            <tr>
                <td>{r['file']}</td>
                <td>{r['lines']}</td>
                <td>{r['code_lines']}</td>
                <td>{r['comments']}</td>
                <td>{r['functions']}</td>
                <td>{r['classes']}</td>
                <td>{r['complexity']}</td>
                <td>{r['effort_score']}</td>
                <td>{r['estimated_hours']}</td>
                <td>${r['estimated_cost']}</td>
            </tr>"""
        
        # Generate complex files rows
        complex_files_rows = ""
        for r in sorted(self.results, key=lambda x: x['complexity'], reverse=True)[:10]:
            complex_files_rows += f"""
            <tr>
                <td>{r['file']}</td>
                <td>{r['complexity']}</td>
                <td>{r['max_nesting']}</td>
                <td>{r['lines']}</td>
                <td>{r['functions']}</td>
            </tr>"""
        
        # Generate data for charts
        file_labels = json.dumps([os.path.basename(r['file']) for r in self.results[:15]])  # Limit to top 15
        effort_scores = json.dumps([r['effort_score'] for r in self.results[:15]])
        complexity_scores = json.dumps([r['complexity'] for r in self.results[:15]])
        
        # Directory data
        dir_stats = defaultdict(int)
        for r in self.results:
            dir_name = os.path.basename(os.path.dirname(r['file']))
            dir_stats[dir_name] += r['code_lines']
        
        dir_labels = json.dumps(list(dir_stats.keys()))
        dir_lines = json.dumps(list(dir_stats.values()))
        
        # Calculate totals
        total_files = len(self.results)
        total_lines = sum(r['lines'] for r in self.results)
        total_functions = sum(r['functions'] for r in self.results)
        total_classes = sum(r['classes'] for r in self.results)
        total_hours = round(sum(r['estimated_hours'] for r in self.results), 1)
        total_cost = f"{sum(r['estimated_cost'] for r in self.results):,.2f}"
        avg_func_len = round(mean(r['avg_func_len'] for r in self.results), 2)
        avg_comment_pct = round(mean(r['comment_percent'] for r in self.results), 2)
        avg_complexity = round(mean(r['complexity'] for r in self.results), 2)
        avg_effort_score = round(mean(r['effort_score'] for r in self.results), 2)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Replace placeholders
        html_content = html_content.replace("${timestamp}", timestamp)
        html_content = html_content.replace("${total_files}", str(total_files))
        html_content = html_content.replace("${total_lines}", str(total_lines))
        html_content = html_content.replace("${total_functions}", str(total_functions))
        html_content = html_content.replace("${total_classes}", str(total_classes))
        html_content = html_content.replace("${total_hours}", str(total_hours))
        html_content = html_content.replace("${total_cost}", str(total_cost))
        html_content = html_content.replace("${avg_func_len}", str(avg_func_len))
        html_content = html_content.replace("${avg_comment_pct}", str(avg_comment_pct))
        html_content = html_content.replace("${avg_complexity}", str(avg_complexity))
        html_content = html_content.replace("${avg_effort_score}", str(avg_effort_score))
        html_content = html_content.replace("${table_rows}", table_rows)
        html_content = html_content.replace("${complex_files_rows}", complex_files_rows)
        html_content = html_content.replace("${file_labels}", file_labels)
        html_content = html_content.replace("${effort_scores}", effort_scores)
        html_content = html_content.replace("${complexity_scores}", complexity_scores)
        html_content = html_content.replace("${dir_labels}", dir_labels)
        html_content = html_content.replace("${dir_lines}", dir_lines)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath


class CodeAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Code Analyzer")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize analyzer
        self.analyzer = CodeComplexityAnalyzer()
        self.current_path = None
        self.analysis_running = False
        self.results_summary = None
        
        # Setup theme
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use a more modern theme if available
        
        # Configure custom styles
        self.style.configure("TButton", padding=6, relief="flat", background="#3498db")
        self.style.configure("TLabel", padding=5)
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Title.TLabel", font=("Arial", 14, "bold"))
        self.style.configure("Result.TLabel", font=("Arial", 10))
        
        # Create main frame with padding
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create header frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Python Code Analyzer", style="Title.TLabel").pack(side=tk.LEFT)
        
        # Create input frame
        input_frame = ttk.LabelFrame(main_frame, text="Analysis Settings", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Path selection
        path_frame = ttk.Frame(input_frame)
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(path_frame, text="Path:").grid(row=0, column=0, sticky=tk.W)
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, width=50)
        path_entry.grid(row=0, column=1, padx=(5, 5), sticky=tk.EW)
        
        browse_btn = ttk.Button(path_frame, text="Browse File", command=self.browse_file)
        browse_btn.grid(row=0, column=2, padx=(0, 5))
        
        browse_dir_btn = ttk.Button(path_frame, text="Browse Dir", command=self.browse_directory)
        browse_dir_btn.grid(row=0, column=3)
        
        path_frame.columnconfigure(1, weight=1)
        
        # Settings frame
        settings_frame = ttk.Frame(input_frame)
        settings_frame.pack(fill=tk.X)
        
        ttk.Label(settings_frame, text="Hourly Rate ($):").grid(row=0, column=0, sticky=tk.W)
        self.rate_var = tk.StringVar(value="50")
        rate_entry = ttk.Entry(settings_frame, textvariable=self.rate_var, width=10)
        rate_entry.grid(row=0, column=1, padx=(5, 10), sticky=tk.W)
        
        # Export options
        export_frame = ttk.LabelFrame(settings_frame, text="Export Options", padding="5")
        export_frame.grid(row=0, column=2, padx=(10, 0), sticky=tk.EW)
        
        self.export_html_var = tk.BooleanVar(value=True)
        html_check = ttk.Checkbutton(export_frame, text="HTML Report", variable=self.export_html_var)
        html_check.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_csv_var = tk.BooleanVar(value=False)
        csv_check = ttk.Checkbutton(export_frame, text="CSV", variable=self.export_csv_var)
        csv_check.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_json_var = tk.BooleanVar(value=False)
        json_check = ttk.Checkbutton(export_frame, text="JSON", variable=self.export_json_var)
        json_check.pack(side=tk.LEFT)
        
        # Analyze button
        self.analyze_btn = ttk.Button(settings_frame, text="Analyze Code", command=self.start_analysis)
        self.analyze_btn.grid(row=0, column=3, padx=(30, 0), sticky=tk.E)
        
        settings_frame.columnconfigure(2, weight=1)
        
        # Results notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        self.summary_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.summary_frame, text="Summary")
        
        # Create summary sections
        self.create_summary_section()
        
        # Details tab
        self.details_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.details_frame, text="File Details")
        
        # Create a treeview for file details
        self.create_details_treeview()
        
        # Progress frame at the bottom
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, 
                                            variable=self.progress_var,
                                            mode="determinate")
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.progress_frame, textvariable=self.status_var)
        status_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Footer with version info
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(footer_frame, 
                  text="Python Code Analyzer v1.0", 
                  foreground="#777777").pack(side=tk.RIGHT)
    
    def create_summary_section(self):
        """Create summary display widgets."""
        # Create a scrollable frame
        summary_canvas = tk.Canvas(self.summary_frame)
        summary_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.summary_frame, orient=tk.VERTICAL, 
                                 command=summary_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        summary_canvas.configure(yscrollcommand=scrollbar.set)
        summary_canvas.bind('<Configure>', 
                           lambda e: summary_canvas.configure(scrollregion=summary_canvas.bbox("all")))
        
        self.scrollable_frame = ttk.Frame(summary_canvas)
        summary_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Project metrics
        metrics_frame = ttk.LabelFrame(self.scrollable_frame, text="Project Metrics", padding="10")
        metrics_frame.pack(fill=tk.X, pady=(0, 10))
        
        row1 = ttk.Frame(metrics_frame)
        row1.pack(fill=tk.X, pady=(0, 5))

        # Create metric labels for first row (files, lines, functions)
        self.files_label = ttk.Label(row1, text="Total Files: -")
        self.files_label.pack(side=tk.LEFT, padx=(0, 20))

        self.lines_label = ttk.Label(row1, text="Total Lines: -")
        self.lines_label.pack(side=tk.LEFT, padx=(0, 20))

        self.functions_label = ttk.Label(row1, text="Total Functions: -")
        self.functions_label.pack(side=tk.LEFT)

        # Main metrics row 2
        row2 = ttk.Frame(metrics_frame)
        row2.pack(fill=tk.X, pady=(0, 5))

        # Create metric labels for second row (classes, complexity, effort)
        self.classes_label = ttk.Label(row2, text="Total Classes: -")
        self.classes_label.pack(side=tk.LEFT, padx=(0, 20))

        self.complexity_label = ttk.Label(row2, text="Avg Complexity: -")
        self.complexity_label.pack(side=tk.LEFT, padx=(0, 20))

        self.effort_label = ttk.Label(row2, text="Avg Effort Score: -")
        self.effort_label.pack(side=tk.LEFT)

        # Main metrics row 3
        row3 = ttk.Frame(metrics_frame)
        row3.pack(fill=tk.X)

        # Create metric labels for third row (time and cost)
        self.hours_label = ttk.Label(row3, text="Estimated Hours: -")
        self.hours_label.pack(side=tk.LEFT, padx=(0, 20))

        self.cost_label = ttk.Label(row3, text="Estimated Cost: -")
        self.cost_label.pack(side=tk.LEFT)

        # Complex files section
        complex_frame = ttk.LabelFrame(self.scrollable_frame, text="Most Complex Files", padding="10")
        complex_frame.pack(fill=tk.X, pady=(0, 10))

        self.complex_text = ScrolledText(complex_frame, height=6, wrap=tk.WORD)
        self.complex_text.pack(fill=tk.X)
        self.complex_text.insert(tk.END, "Run analysis to see results...")
        self.complex_text.configure(state="disabled")

        # Effort files section
        effort_frame = ttk.LabelFrame(self.scrollable_frame, text="Highest Effort Files", padding="10")
        effort_frame.pack(fill=tk.X, pady=(0, 10))

        self.effort_text = ScrolledText(effort_frame, height=6, wrap=tk.WORD)
        self.effort_text.pack(fill=tk.X)
        self.effort_text.insert(tk.END, "Run analysis to see results...")
        self.effort_text.configure(state="disabled")

        # Directory breakdown
        dir_frame = ttk.LabelFrame(self.scrollable_frame, text="Directory Breakdown", padding="10")
        dir_frame.pack(fill=tk.X)

        self.dir_text = ScrolledText(dir_frame, height=8, wrap=tk.WORD)
        self.dir_text.pack(fill=tk.X)
        self.dir_text.insert(tk.END, "Run analysis to see results...")
        self.dir_text.configure(state="disabled")

    def create_details_treeview(self):
        """Create treeview for file details tab."""
        # Create a frame for the treeview
        tree_frame = ttk.Frame(self.details_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        # Create treeview
        columns = ("file", "lines", "blank", "code", "comments", "functions", 
                "classes", "complexity", "effort", "hours", "cost")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                                yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Configure scrollbars
        vsb.configure(command=self.tree.yview)
        hsb.configure(command=self.tree.xview)
        
        # Set column headings
        self.tree.heading("file", text="File")
        self.tree.heading("lines", text="Lines")
        self.tree.heading("blank", text="Blank")
        self.tree.heading("code", text="Code")
        self.tree.heading("comments", text="Comments")
        self.tree.heading("functions", text="Functions")
        self.tree.heading("classes", text="Classes")
        self.tree.heading("complexity", text="Complexity")
        self.tree.heading("effort", text="Effort Score")
        self.tree.heading("hours", text="Est. Hours")
        self.tree.heading("cost", text="Est. Cost")
        
        # Set column widths
        self.tree.column("file", width=250, minwidth=150)
        self.tree.column("lines", width=60, minwidth=50)
        self.tree.column("blank", width=60, minwidth=50)
        self.tree.column("code", width=60, minwidth=50)
        self.tree.column("comments", width=70, minwidth=60)
        self.tree.column("functions", width=70, minwidth=60)
        self.tree.column("classes", width=60, minwidth=50)
        self.tree.column("complexity", width=80, minwidth=70)
        self.tree.column("effort", width=80, minwidth=70)
        self.tree.column("hours", width=70, minwidth=60)
        self.tree.column("cost", width=70, minwidth=60)
        
        # Pack widgets
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

    def browse_file(self):
        """Open file browser to select a Python file."""
        filetypes = [("Python files", "*.py"), ("All files", "*.*")]
        filename = filedialog.askopenfilename(
            title="Select Python File",
            filetypes=filetypes
        )
        if filename:
            self.path_var.set(filename)
            self.current_path = filename

    def browse_directory(self):
        """Open directory browser to select a project folder."""
        directory = filedialog.askdirectory(
            title="Select Python Project Directory"
        )
        if directory:
            self.path_var.set(directory)
            self.current_path = directory

    def update_progress(self, current, total, filepath):
        """Update progress bar and status."""
        self.progress_var.set((current / total) * 100)
        self.status_var.set(f"Analyzing {current}/{total}: {os.path.basename(filepath)}")
        self.root.update_idletasks()

    def start_analysis(self):
        """Start the analysis process in a separate thread."""
        if self.analysis_running:
            messagebox.showwarning("Analysis Running", 
                                "Analysis is already running. Please wait.")
            return
    
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("No Path", 
                                "Please select a Python file or directory.")
            return
        
        try:
            hourly_rate = float(self.rate_var.get())
        except ValueError:
            messagebox.showwarning("Invalid Rate", 
                                "Please enter a valid hourly rate.")
            return
        
        self.analyzer = CodeComplexityAnalyzer(hourly_rate=hourly_rate)
        self.current_path = path
        self.analysis_running = True
        self.analyze_btn.state(["disabled"])
        self.progress_var.set(0)
        self.status_var.set("Starting analysis...")
        
        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Start analysis in a separate thread
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        """Run the analysis in a background thread."""
        try:
            if os.path.isfile(self.current_path) and self.current_path.endswith(".py"):
                result = self.analyzer.analyze_python_file(self.current_path)
                if result:
                    self.analyzer.results = [result]
                else:
                    self.analyzer.results = []
            elif os.path.isdir(self.current_path):
                self.analyzer.analyze_directory(self.current_path, 
                                            progress_callback=self.update_progress)
            else:
                self.root.after(0, lambda: messagebox.showerror(
                    "Invalid Path", 
                    "Selected path must be a Python file or directory."
                ))
                self.analysis_running = False
                self.analyze_btn.state(["!disabled"])
                return
            
            # Get summary
            self.results_summary = self.analyzer.get_summary_data()
            
            # Update UI with results
            self.root.after(0, self.update_ui_with_results)
            
            # Export if requested
            self.export_results()
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Analysis Error", 
                f"An error occurred during analysis: {str(e)}"
            ))
        finally:
            self.analysis_running = False
            self.root.after(0, lambda: self.analyze_btn.state(["!disabled"]))
            self.root.after(0, lambda: self.status_var.set("Analysis complete"))

    def update_ui_with_results(self):
        """Update UI with analysis results."""
        if not self.results_summary:
            messagebox.showinfo("No Results", "No Python files were analyzed.")
            return
        
        # Update summary labels
        self.files_label.config(text=f"Total Files: {self.results_summary['total_files']}")
        self.lines_label.config(text=f"Total Lines: {self.results_summary['total_lines']}")
        self.functions_label.config(text=f"Total Functions: {self.results_summary['total_funcs']}")
        self.classes_label.config(text=f"Total Classes: {self.results_summary['total_classes']}")
        self.complexity_label.config(text=f"Avg Complexity: {self.results_summary['avg_complexity']}")
        self.effort_label.config(text=f"Avg Effort Score: {self.results_summary['avg_effort_score']}/10")
        self.hours_label.config(text=f"Estimated Hours: {self.results_summary['total_hours']}")
        self.cost_label.config(text=f"Estimated Cost: ${self.results_summary['total_cost']:.2f}")
        
        # Update complex files text
        self.complex_text.configure(state="normal")
        self.complex_text.delete(1.0, tk.END)
        for idx, file in enumerate(self.results_summary['most_complex_files']):
            self.complex_text.insert(tk.END, 
                                    f"{idx+1}. {file['file']}\n"
                                    f"   Complexity: {file['complexity']}, "
                                    f"Nesting: {file['max_nesting']}, "
                                    f"Lines: {file['lines']}\n\n")
        self.complex_text.configure(state="disabled")
        
        # Update effort files text
        self.effort_text.configure(state="normal")
        self.effort_text.delete(1.0, tk.END)
        for idx, file in enumerate(self.results_summary['highest_effort_files']):
            self.effort_text.insert(tk.END, 
                                f"{idx+1}. {file['file']}\n"
                                f"   Effort Score: {file['effort_score']}/10, "
                                f"Est. Hours: {file['estimated_hours']}, "
                                f"Est. Cost: ${file['estimated_cost']:.2f}\n\n")
        self.effort_text.configure(state="disabled")
        
        # Update directory text
        self.dir_text.configure(state="normal")
        self.dir_text.delete(1.0, tk.END)
        for dir_name, stats in self.results_summary['dir_stats'].items():
            avg_effort = stats['effort'] / stats['files'] if stats['files'] > 0 else 0
            self.dir_text.insert(tk.END, 
                                f"{dir_name}\n"
                                f"   Files: {stats['files']}, "
                                f"Lines: {stats['lines']}, "
                                f"Avg Effort: {avg_effort:.2f}/10\n\n")
        self.dir_text.configure(state="disabled")
        
        # Update treeview
        for file in self.analyzer.results:
            self.tree.insert("", "end", values=(
                file['file'],
                file['lines'],
                file['blank_lines'],
                file['code_lines'],
                file['comments'],
                file['functions'],
                file['classes'],
                file['complexity'],
                file['effort_score'],
                file['estimated_hours'],
                file['estimated_cost']
            ))

    def export_results(self):
        """Export analysis results to selected formats."""
        if not self.analyzer.results:
            return
        
        try:
            base_path = os.path.dirname(self.current_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = os.path.basename(self.current_path).split('.')[0] if os.path.isfile(self.current_path) else os.path.basename(self.current_path)
            export_base = os.path.join(base_path, f"{base_name}_analysis_{timestamp}")
            
            # Export HTML
            if self.export_html_var.get():
                html_path = f"{export_base}.html"
                file_path = self.analyzer.export_to_html(html_path)
                if file_path:
                    self.status_var.set(f"Exported HTML to {os.path.basename(file_path)}")
                    webbrowser.open(f"file://{os.path.abspath(file_path)}")
            
            # Export CSV
            if self.export_csv_var.get():
                csv_path = f"{export_base}.csv"
                file_path = self.analyzer.export_to_csv(csv_path)
                if file_path:
                    self.status_var.set(f"Exported CSV to {os.path.basename(file_path)}")
            
            # Export JSON
            if self.export_json_var.get():
                json_path = f"{export_base}.json"
                file_path = self.analyzer.export_to_json(json_path)
                if file_path:
                    self.status_var.set(f"Exported JSON to {os.path.basename(file_path)}")
                    
        except Exception as e:
            messagebox.showwarning("Export Error", f"Error exporting results: {str(e)}")

    # Main function to run the application
def main():
    root = tk.Tk()
    app = CodeAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
