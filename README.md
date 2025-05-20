# python_code_analyzer

# Python Code Analyzer

A powerful tool for analyzing Python codebases to assess complexity, development effort, and cost estimates.

![Python Code Analyzer Screenshot](screenshot.png)

## Features

- **Code Complexity Analysis**: Evaluates cyclomatic complexity, nesting depth, and other code quality metrics.
- **Development Effort Estimation**: Calculates effort scores, development time, and cost estimates.
- **Detailed Reporting**: Generates comprehensive analysis with multiple visualization options.
- **Project Overview**: Provides summaries of total lines, functions, classes, complexity, and effort scores.
- **Export Options**: Export results as HTML reports with interactive charts, CSV, or JSON.

## Metrics Calculated

- **Basic Metrics**: Total lines, blank lines, code lines, comment lines, comment percentage
- **Structure Metrics**: Function count, class count, average function length
- **Complexity Metrics**: Cyclomatic complexity, maximum nesting depth
- **Development Metrics**: Effort score, estimated development hours, estimated cost

## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/python-code-analyzer.git
cd python-code-analyzer
```

2. Install the requirements:
```
pip install -r requirements.txt
```

## Usage

### GUI Mode

Run the application with:

```
python script_analyzer.py
```

1. Browse for a Python file or directory.
2. Set the hourly rate for cost calculations (default: $50).
3. Select export options (HTML, CSV, JSON).
4. Click "Analyze Code" to process files.
5. View results in the Summary and File Details tabs.
6. HTML reports will open automatically in your browser.

### Programmatic Usage

The core analyzer can also be used programmatically:

```python
from script_analyzer import CodeComplexityAnalyzer

# Initialize analyzer with hourly rate
analyzer = CodeComplexityAnalyzer(hourly_rate=50)

# Analyze a single file
result = analyzer.analyze_python_file("path/to/your/file.py")
print(result)

# Analyze a directory
results = analyzer.analyze_directory("path/to/your/project/")

# Generate summary
summary = analyzer.get_summary_data()

# Export results
analyzer.export_to_html("report.html")
analyzer.export_to_csv("data.csv")
analyzer.export_to_json("data.json")
```

## Understanding the Results

### Effort Score (0-10)

The effort score combines several factors:
- Function length (longer functions = higher score)
- Cyclomatic complexity (more branches = higher score)
- Nesting depth (deeper nesting = higher score)
- Comment percentage (fewer comments = higher score)
- Number of functions (more functions = higher score)
- Number of imports (more dependencies = higher score)

### Development Estimates

Time and cost estimates are based on:
- Effort score
- Total lines of code
- Hourly rate specified

## Sample Output

The HTML report includes:
- Key metrics in card format
- Project overview with averages
- Interactive bar charts for effort and complexity
- Pie chart of code distribution by directory
- Tables of most complex files and file details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
