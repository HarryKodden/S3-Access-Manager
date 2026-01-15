# Auto-Generated Demo Analysis

Two analysis documents are automatically generated from the latest demo script executions:

- `output/demo-flow.md` - Gateway API analysis (via S3 Gateway REST endpoints)
- `output/demo-flow-cli.md` - Backend CLI analysis (direct AWS CLI commands to SURF object store)

## Directory Structure

```
analysis/
├── README.md                    # This documentation
├── scripts/                     # Analysis generation scripts
│   ├── generate-demo-analysis.sh    # Gateway API analysis
│   ├── generate-cli-analysis.sh     # CLI backend analysis
│   ├── demo-flow.sh                 # Gateway API demo script
│   └── demo-flow-cli.sh             # Backend CLI demo script
├── templates/                   # Markdown templates
│   ├── demo-flow-template.md        # Gateway API analysis template
│   └── demo-flow-cli-template.md    # CLI analysis template
└── output/                      # Generated analysis documents
    ├── demo-flow.md                 # Gateway API gap analysis
    └── demo-flow-cli.md             # CLI backend gap analysis
```

## How to Regenerate

### Gateway API Analysis
Run the gateway analysis script after any changes to the gateway:

```bash
./analysis/scripts/generate-demo-analysis.sh
```

### CLI Backend Analysis
Run the CLI analysis script to test direct backend operations:

```bash
./analysis/scripts/generate-cli-analysis.sh
```

Both scripts will:
1. Execute the respective demo script and capture all output
2. Extract actual JSON responses from each step
3. Generate an updated analysis document with current results
4. Display a status summary

## Benefits

- **Always Current**: Documents reflect the latest gateway and backend behavior
- **Gap Analysis**: Shows expected vs actual outputs with status badges
- **Issue Tracking**: Automatically counts critical/partial/working steps
- **Dual Perspective**: Compare gateway API vs direct backend operations
- **Timestamped**: Shows when each analysis was last run

## Files

### Scripts (`scripts/`)
- `generate-demo-analysis.sh` - Gateway API analysis generation script
- `generate-cli-analysis.sh` - CLI backend analysis generation script
- `demo-flow.sh` - Gateway API demo script
- `demo-flow-cli.sh` - Backend CLI demo script

### Templates (`templates/`)
- `demo-flow-cli-template.md` - Template for CLI analysis document
- `demo-flow-template.md` - Template for gateway API analysis document

### Output (`output/`)
- `demo-flow.md` - Auto-generated gateway API gap analysis
- `demo-flow-cli.md` - Auto-generated CLI backend gap analysis